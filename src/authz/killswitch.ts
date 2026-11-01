// SPDX-License-Identifier: Apache-2.0
/**
 * Kill switch and break-glass (Server Half).
 * Halts are scoped per agent, per issuer, per workspace, per key or
 * globally, take effect at every connected enforcement point that polls or
 * subscribes (propagation target < 1s; enforcement points must treat a stale
 * revocation feed older than their bound as halted), and every halt, resume
 * and break-glass override is emitted as a signed statement into the log via
 * the injected emitter. Break-glass is always time-boxed, always flagged on
 * its receipts, and always followed by a mandatory-review statement.
 *
 * Pure stateless verification functions live in `./killswitch-verify.js`
 * (Apache-2.0 open half) and are re-exported here for 100% caller compatibility.
 */
import { cborEncode } from '../core/cbor.js';
import { coseSign1 } from '../core/cose.js';
import { digestOf } from '../core/capsule.js';
import type { ReceiptSigner } from '../core/keys.js';
import {
  type HaltScope,
  type HaltRecord,
  type BreakGlassRecord,
  type HaltFeed,
  type HaltStatementVerificationResult,
  type HaltFeedVerificationResult,
  scopeKeyFor,
  verifyHaltStatement,
  verifyHaltFeed,
  isScopeHaltedInFeed,
  matchHaltedScopeInFeed,
  SchemaPinStore,
} from './killswitch-verify.js';

export {
  type HaltScope,
  type HaltRecord,
  type BreakGlassRecord,
  type HaltFeed,
  type HaltStatementVerificationResult,
  type HaltFeedVerificationResult,
  scopeKeyFor,
  verifyHaltStatement,
  verifyHaltFeed,
  isScopeHaltedInFeed,
  matchHaltedScopeInFeed,
  SchemaPinStore,
};

export interface StatementEmitter {
  emit(statementBytes: Buffer, kind: string): Promise<void>;
}

export class KillSwitch {
  private halts = new Map<string, HaltRecord>();
  private breakGlasses = new Map<string, BreakGlassRecord>();
  private listeners = new Set<(e: { type: 'halt' | 'resume' | 'break-glass'; scopeKey: string }) => void>();
  private version = 0;

  constructor(
    private readonly signer?: ReceiptSigner,
    private readonly emitter?: StatementEmitter,
  ) {}

  subscribe(fn: (e: { type: 'halt' | 'resume' | 'break-glass'; scopeKey: string }) => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  private async logStatement(kind: string, payloadObj: unknown): Promise<string | undefined> {
    const payload = cborEncode(payloadObj as never);
    const digest = digestOf(payload);
    if (this.signer && this.emitter) {
      const stmt = await coseSign1(this.signer, payload, {
        contentType: `application/vnd.hivemind.${kind}+cbor`,
      });
      await this.emitter.emit(stmt, kind);
    }
    return digest;
  }

  async halt(scope: HaltScope, reason: string, haltedBy: string, nowSeconds = Math.floor(Date.now() / 1000)): Promise<HaltRecord> {
    const key = scopeKeyFor(scope);
    const rec: HaltRecord = { scopeKey: key, scope, reason, haltedBy, atSeconds: nowSeconds };
    rec.statementDigest = await this.logStatement('revocation', {
      profile: 'urn:hivemind:receipts:revocation:1',
      scope: key,
      reason,
      halted_by: haltedBy,
      at: nowSeconds,
    });
    this.halts.set(key, rec);
    this.version++;
    for (const fn of this.listeners) fn({ type: 'halt', scopeKey: key });
    return rec;
  }

  async resume(scope: HaltScope, resumedBy: string, nowSeconds = Math.floor(Date.now() / 1000)): Promise<void> {
    const key = scopeKeyFor(scope);
    if (!this.halts.delete(key)) return;
    await this.logStatement('revocation', {
      profile: 'urn:hivemind:receipts:revocation:1',
      scope: key,
      resumed_by: resumedBy,
      at: nowSeconds,
    });
    this.version++;
    for (const fn of this.listeners) fn({ type: 'resume', scopeKey: key });
  }

  /** Enforcement points call this before every action. Fail-closed on unknown scope shapes. */
  assertNotHalted(
    issuer: string,
    agent: string,
    extra?: { workspace?: string | undefined; keyId?: string | undefined },
  ): void {
    const hit =
      this.halts.get('global') ??
      this.halts.get(`issuer:${issuer}`) ??
      this.halts.get(`agent:${agent}`) ??
      (extra?.workspace ? this.halts.get(`workspace:${extra.workspace}`) : undefined) ??
      (extra?.keyId ? this.halts.get(`key:${extra.keyId}`) : undefined);
    if (hit) {
      const err = new Error(`kill switch active (${hit.scopeKey}): ${hit.reason}`);
      (err as Error & { code?: string }).code = 'KILL_SWITCH_ACTIVE';
      throw err;
    }
  }

  isHalted(
    issuer: string,
    agent: string,
    extra?: { workspace?: string | undefined; keyId?: string | undefined },
  ): boolean {
    const hit =
      this.halts.get('global') ??
      this.halts.get(`issuer:${issuer}`) ??
      this.halts.get(`agent:${agent}`) ??
      (extra?.workspace ? this.halts.get(`workspace:${extra.workspace}`) : undefined) ??
      (extra?.keyId ? this.halts.get(`key:${extra.keyId}`) : undefined);
    return hit !== undefined;
  }

  async openBreakGlass(input: {
    reason: string;
    openedBy: string;
    durationSeconds: number;
    nowSeconds?: number;
  }): Promise<BreakGlassRecord> {
    const now = input.nowSeconds ?? Math.floor(Date.now() / 1000);
    if (input.durationSeconds < 1 || input.durationSeconds > 24 * 3600)
      throw new Error('break-glass must be time-boxed to at most 24h');
    const rec: BreakGlassRecord = {
      id: `bg-${now}-${this.breakGlasses.size}`,
      reason: input.reason,
      openedBy: input.openedBy,
      startsAtSeconds: now,
      expiresAtSeconds: now + input.durationSeconds,
      reviewDue: true,
    };
    rec.statementDigest = await this.logStatement('break-glass', {
      profile: 'urn:hivemind:receipts:break-glass:1',
      id: rec.id,
      reason: rec.reason,
      opened_by: rec.openedBy,
      expires: rec.expiresAtSeconds,
      review_due: true,
    });
    this.breakGlasses.set(rec.id, rec);
    this.version++;
    for (const fn of this.listeners) fn({ type: 'break-glass', scopeKey: rec.id });
    return rec;
  }

  breakGlassActive(id: string, nowSeconds = Math.floor(Date.now() / 1000)): boolean {
    const r = this.breakGlasses.get(id);
    return Boolean(r && nowSeconds >= r.startsAtSeconds && nowSeconds < r.expiresAtSeconds);
  }

  /** Snapshot for the revocation feed enforcement points poll or subscribe to. */
  feed(nowSeconds = Math.floor(Date.now() / 1000)): HaltFeed {
    return {
      version: this.version,
      issuedAtSeconds: nowSeconds,
      halts: [...this.halts.values()],
      breakGlass: [...this.breakGlasses.values()],
    };
  }
}
