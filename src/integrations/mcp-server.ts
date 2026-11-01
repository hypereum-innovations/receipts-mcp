// SPDX-License-Identifier: Apache-2.0
/**
 * Hivemind Receipts Model Context Protocol (MCP) Server.
 *
 * Compliant with JSON-RPC 2.0 and MCP Streamable HTTP / stdio transports:
 * - Stdio: line-delimited JSON-RPC over any `Readable` / `Writable` stream
 *   (including `process.stdin` / `process.stdout`).
 * - Streamable HTTP: `handleHttpRequest` supporting both `application/json`
 *   and Server-Sent Events (`text/event-stream`).
 *
 * Supported methods:
 * - `initialize`
 * - `notifications/initialized`
 * - `server/discover` (server metadata, capabilities, trust roots, and tool schemas with pinned digest)
 * - `tools/list`
 * - `tools/call`:
 *   - `receipts_authorize`
 *   - `receipts_register`
 *   - `receipts_verify`
 *   - `receipts_checkpoint`
 *   - `receipts_confirm`
 * - `resources/list`
 * - `resources/read`:
 *   - `receipts://checkpoint/latest`
 *   - `receipts://trust-roots`
 */
import type { Readable, Writable } from 'node:stream';
import { cborEncode } from '../core/cbor.js';
import { digestOf, type Digest, type Disclosure, type RiskTier, type VerdictClass } from '../core/capsule.js';
import { verifyReceiptBundle, type TrustRoots } from '../core/verify.js';
import { SchemaPinStore } from '../authz/killswitch.js';
import type { AuthZenResponse } from '../authz/authzen-types.js';
import type { ReceiptSigner } from '../core/keys.js';
import { signConfirmation } from '../confirmations/confirmation.js';
import { toConfirmation, type Observation } from '../confirmations/connectors/index.js';
import type { ActionDescriptor, ReceiptCapture } from './capture.js';
import { classifyRisk, mcpReceiptMeta, MCP_EXTENSION_ID } from './surface-helpers.js';

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

export interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export interface McpToolSchema {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export interface PinnedMcpToolSchema extends McpToolSchema {
  schema_digest: Digest;
  annotations: {
    schema_digest: Digest;
  };
}

export const MCP_TOOL_DEFINITIONS: McpToolSchema[] = [
  {
    name: 'receipts_authorize',
    description: 'Evaluate a pre-action policy decision via Hivemind AuthZEN PDP before executing a tool or action.',
    inputSchema: {
      type: 'object',
      properties: {
        method: { type: 'string', description: 'Action or tool name to authorize' },
        kind: { type: 'string', enum: ['mcp', 'a2a', 'http', 'tool', 'other'] },
        riskTier: { type: 'string', enum: ['read', 'write', 'destructive', 'financial', 'external_communication'] },
        args: { type: 'object', description: 'Tool arguments' },
        subjectId: { type: 'string' },
        resourceId: { type: 'string' },
        approvalDigest: { type: 'string' },
      },
      required: ['method'],
    },
  },
  {
    name: 'receipts_register',
    description: 'Build, sign, and register an Agent Action Capsule in the Hivemind SCITT transparency log.',
    inputSchema: {
      type: 'object',
      properties: {
        method: { type: 'string' },
        kind: { type: 'string', enum: ['mcp', 'a2a', 'http', 'tool', 'other'] },
        riskTier: { type: 'string', enum: ['read', 'write', 'destructive', 'financial', 'external_communication'] },
        args: { type: 'object' },
        verdict: {
          type: 'string',
          enum: ['executed', 'blocked', 'denied', 'errored', 'engine_failure', 'timed_out'],
        },
        observedResponse: {},
        subjectId: { type: 'string' },
      },
      required: ['method'],
    },
  },
  {
    name: 'receipts_verify',
    description: 'Verify a SCITT receipt bundle offline against the pinned trust roots and checkpoint.',
    inputSchema: {
      type: 'object',
      properties: {
        statement_b64: { type: 'string', description: 'Base64url-encoded SCITT transparent statement' },
        checkpoint: { type: 'string', description: 'C2SP cosigned checkpoint text' },
        disclosure: { type: 'object', description: 'Optional salted commitment disclosure object' },
      },
      required: ['statement_b64'],
    },
  },
  {
    name: 'receipts_checkpoint',
    description: 'Retrieve the latest cosigned C2SP checkpoint from the Hivemind transparency log.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'receipts_confirm',
    description: 'Issue and sign a W1-W3 outcome confirmation statement bound to a capsule_id.',
    inputSchema: {
      type: 'object',
      properties: {
        capsule_id: { type: 'string', description: 'Target capsule digest (sha256:...)' },
        witness: { type: 'string', description: 'Witness identifier URI' },
        observation: {
          type: 'object',
          properties: {
            system: { type: 'string' },
            event: { type: 'string' },
            objectId: { type: 'string' },
            state: { type: 'string' },
            at: { type: 'string' },
            evidenceKind: { type: 'string' },
            evidenceDigest: { type: 'string' },
            level: { type: 'string', enum: ['W0', 'W1', 'W2', 'W3'] },
          },
          required: ['system', 'event', 'state', 'at', 'evidenceKind', 'evidenceDigest', 'level'],
        },
      },
      required: ['capsule_id', 'observation'],
    },
  },
];

export interface ReceiptsMcpServerOptions {
  capture: ReceiptCapture;
  trustRoots: TrustRoots;
  getCheckpoint: () => string | Promise<string>;
  connectorSigner?: ReceiptSigner;
  schemaPinStore?: SchemaPinStore;
  serverInfo?: {
    name?: string;
    version?: string;
    protocolVersion?: string;
  };
}

export class ReceiptsMcpServer {
  private readonly schemaPinStore: SchemaPinStore;
  private readonly pinnedTools: PinnedMcpToolSchema[];
  private readonly serverInfo: { name: string; version: string; protocolVersion: string };
  private initialized = false;

  constructor(private readonly opts: ReceiptsMcpServerOptions) {
    this.schemaPinStore = opts.schemaPinStore ?? new SchemaPinStore();
    this.serverInfo = {
      name: opts.serverInfo?.name ?? 'hivemind-receipts-mcp',
      version: opts.serverInfo?.version ?? '1.0.0',
      protocolVersion: opts.serverInfo?.protocolVersion ?? '2025-03-26',
    };
    this.pinnedTools = MCP_TOOL_DEFINITIONS.map((t) => {
      const digest = this.schemaPinStore.assertPinned(t.name, t.inputSchema) as Digest;
      return {
        ...t,
        schema_digest: digest,
        annotations: { schema_digest: digest },
      };
    });
  }

  private serializeTrustRoots(): Record<string, unknown> {
    const issuers = [...this.opts.trustRoots.issuers.values()].map((i) => ({
      kid: i.kid,
      tier: i.tier,
      display: i.display,
      alg: i.alg,
      revoked: Boolean(i.revoked),
    }));
    const logKids = [...this.opts.trustRoots.logKeys.keys()];
    return {
      issuers,
      log_kids: logKids,
      note_verifiers: this.opts.trustRoots.noteVerifiers,
      witness_policy: this.opts.trustRoots.witnessPolicy,
    };
  }

  /** Handle a single JSON-RPC 2.0 request/notification. Returns null for notifications without an id. */
  async handleJsonRpc(msg: JsonRpcRequest): Promise<JsonRpcResponse | null> {
    if (!msg || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') {
      return {
        jsonrpc: '2.0',
        id: msg?.id ?? null,
        error: { code: -32600, message: 'Invalid Request' },
      };
    }

    const id = msg.id;
    const params = msg.params ?? {};

    if (msg.method === 'notifications/initialized') {
      this.initialized = true;
      if (id === undefined) return null;
      return { jsonrpc: '2.0', id, result: { acknowledged: true } };
    }

    if (id === undefined) {
      // Any other notification
      return null;
    }

    try {
      switch (msg.method) {
        case 'initialize': {
          this.initialized = true;
          return {
            jsonrpc: '2.0',
            id,
            result: {
              protocolVersion:
                typeof params['protocolVersion'] === 'string'
                  ? params['protocolVersion']
                  : this.serverInfo.protocolVersion,
              serverInfo: {
                name: this.serverInfo.name,
                version: this.serverInfo.version,
              },
              capabilities: {
                tools: { listChanged: false },
                resources: { subscribe: false, listChanged: false },
                extensions: [MCP_EXTENSION_ID],
              },
            },
          };
        }

        case 'server/discover': {
          return {
            jsonrpc: '2.0',
            id,
            result: {
              serverInfo: this.serverInfo,
              initialized: this.initialized,
              capabilities: {
                tools: { listChanged: false, schemaPinning: true },
                resources: { subscribe: false, listChanged: false },
                extensions: [MCP_EXTENSION_ID],
                transports: ['stdio', 'streamable-http', 'sse'],
              },
              trustRoots: this.serializeTrustRoots(),
              tools: this.pinnedTools,
            },
          };
        }

        case 'tools/list': {
          return {
            jsonrpc: '2.0',
            id,
            result: {
              tools: this.pinnedTools,
            },
          };
        }

        case 'tools/call': {
          const toolName = String(params['name'] ?? '');
          const args = (params['arguments'] as Record<string, unknown> | undefined) ?? {};
          const out = await this.callTool(toolName, args);
          return {
            jsonrpc: '2.0',
            id,
            result: out,
          };
        }

        case 'resources/list': {
          return {
            jsonrpc: '2.0',
            id,
            result: {
              resources: [
                {
                  uri: 'receipts://checkpoint/latest',
                  name: 'Latest Cosigned Checkpoint',
                  description: 'Current C2SP signed-note checkpoint with witness cosignatures',
                  mimeType: 'text/plain',
                },
                {
                  uri: 'receipts://trust-roots',
                  name: 'Pinned Trust Roots',
                  description: 'Issuers, log keys, and witness quorum policy',
                  mimeType: 'application/json',
                },
              ],
            },
          };
        }

        case 'resources/read': {
          const uri = String(params['uri'] ?? '');
          if (uri === 'receipts://checkpoint/latest') {
            const text = await this.opts.getCheckpoint();
            return {
              jsonrpc: '2.0',
              id,
              result: {
                contents: [
                  {
                    uri,
                    mimeType: 'text/plain',
                    text,
                  },
                ],
              },
            };
          }
          if (uri === 'receipts://trust-roots') {
            return {
              jsonrpc: '2.0',
              id,
              result: {
                contents: [
                  {
                    uri,
                    mimeType: 'application/json',
                    text: JSON.stringify(this.serializeTrustRoots()),
                  },
                ],
              },
            };
          }
          return {
            jsonrpc: '2.0',
            id,
            error: { code: -32602, message: `Unknown resource URI: ${uri}` },
          };
        }

        default:
          return {
            jsonrpc: '2.0',
            id,
            error: { code: -32601, message: `Method not found: ${msg.method}` },
          };
      }
    } catch (err) {
      return {
        jsonrpc: '2.0',
        id,
        error: {
          code: -32603,
          message: err instanceof Error ? err.message : String(err),
        },
      };
    }
  }

  private async callTool(
    rawName: string,
    args: Record<string, unknown>,
  ): Promise<{
    content: Array<{ type: 'text'; text: string }>;
    structuredContent: Record<string, unknown>;
    isError?: boolean;
    _meta?: Record<string, unknown>;
  }> {
    const normalizedName =
      rawName === 'hivemind.authorize'
        ? 'receipts_authorize'
        : rawName === 'hivemind.record'
          ? 'receipts_register'
          : rawName === 'hivemind.verify'
            ? 'receipts_verify'
            : rawName;

    const toolDef = this.pinnedTools.find((t) => t.name === normalizedName);
    if (!toolDef) {
      throw new Error(`Unknown MCP tool: ${rawName}`);
    }

    // Verify tool schema pin has not drifted
    const schemaDigest = this.schemaPinStore.assertPinned(
      toolDef.name,
      toolDef.inputSchema,
    ) as `sha256:${string}`;

    switch (normalizedName) {
      case 'receipts_authorize': {
        const method = String(args['method'] ?? '');
        if (!method) throw new Error('method is required for receipts_authorize');
        const action: ActionDescriptor = {
          method,
          kind: (args['kind'] as ActionDescriptor['kind']) ?? 'mcp',
          riskTier: (args['riskTier'] as RiskTier | undefined) ?? classifyRisk(method),
          args: args['args'] ?? {},
          toolSchemaDigest: schemaDigest,
          ...(typeof args['subjectId'] === 'string' ? { subjectId: args['subjectId'] } : {}),
          ...(typeof args['resourceId'] === 'string' ? { resourceId: args['resourceId'] } : {}),
        };
        const decision = await this.opts.capture.authorize(
          action,
          typeof args['approvalDigest'] === 'string' ? args['approvalDigest'] : '',
        );
        return {
          content: [{ type: 'text', text: JSON.stringify(decision) }],
          structuredContent: {
            decision: decision.decision,
            hivemind: decision.hivemind,
            schema_digest: schemaDigest,
          },
          isError: !decision.decision,
        };
      }

      case 'receipts_register': {
        const method = String(args['method'] ?? '');
        if (!method) throw new Error('method is required for receipts_register');
        const action: ActionDescriptor = {
          method,
          kind: (args['kind'] as ActionDescriptor['kind']) ?? 'mcp',
          riskTier: (args['riskTier'] as RiskTier | undefined) ?? classifyRisk(method),
          args: args['args'] ?? {},
          toolSchemaDigest: schemaDigest,
          ...(typeof args['subjectId'] === 'string' ? { subjectId: args['subjectId'] } : {}),
        };
        const decision: AuthZenResponse =
          (args['decision'] as AuthZenResponse | undefined) ?? (await this.opts.capture.authorize(action));
        const verdict: VerdictClass =
          (args['verdict'] as VerdictClass | undefined) ??
          (decision.decision ? 'executed' : decision.hivemind.requires_approval ? 'blocked' : 'denied');
        const observed =
          args['observedResponse'] !== undefined
            ? args['observedResponse']
            : verdict === 'executed'
              ? { ok: true }
              : undefined;
        const receipt = await this.opts.capture.record(action, verdict, decision, observed);
        const statementToExport = receipt.transparentStatement ?? receipt.statement;
        const payload = {
          capsule_id: receipt.capsule.capsule_id,
          action_id: receipt.capsule.action_id,
          verdict_class: receipt.capsule.verdict_class,
          leaf_index: receipt.leafIndex,
          statement_b64: statementToExport.toString('base64url'),
          disclosure: receipt.disclosure,
          schema_digest: schemaDigest,
        };
        return {
          content: [{ type: 'text', text: JSON.stringify(payload) }],
          structuredContent: payload,
          _meta: mcpReceiptMeta(receipt),
        };
      }

      case 'receipts_verify': {
        const stmtB64 = String(args['statement_b64'] ?? '');
        if (!stmtB64) throw new Error('statement_b64 is required for receipts_verify');
        const checkpoint =
          typeof args['checkpoint'] === 'string' ? args['checkpoint'] : await this.opts.getCheckpoint();
        const disclosure = args['disclosure'] as Disclosure | undefined;
        const report = verifyReceiptBundle(
          {
            statement: Buffer.from(stmtB64, 'base64url'),
            checkpoint,
            ...(disclosure ? { disclosure } : {}),
          },
          this.opts.trustRoots,
        );
        const structured = {
          verdict: report.verdict,
          issuerTier: report.issuerTier,
          capsule_id: report.capsule?.capsule_id ?? null,
          checks: report.checks,
          assertedOnly: report.assertedOnly,
          log: report.log,
        };
        return {
          content: [{ type: 'text', text: JSON.stringify(structured) }],
          structuredContent: structured,
          isError: report.verdict !== 'VERIFIED',
        };
      }

      case 'receipts_checkpoint': {
        const checkpoint = await this.opts.getCheckpoint();
        const structured = { checkpoint };
        return {
          content: [{ type: 'text', text: checkpoint }],
          structuredContent: structured,
        };
      }

      case 'receipts_confirm': {
        if (!this.opts.connectorSigner) {
          throw new Error('connectorSigner is not configured on this MCP server');
        }
        const capsuleId = String(args['capsule_id'] ?? '') as Digest;
        const witness = String(args['witness'] ?? 'urn:hivemind:witness:mcp');
        const obs = args['observation'] as Observation | undefined;
        if (!capsuleId || !obs) {
          throw new Error('capsule_id and observation are required for receipts_confirm');
        }
        const confPayload = toConfirmation(obs, capsuleId, witness);
        const signed = await signConfirmation(this.opts.connectorSigner, confPayload);
        const confDigest = digestOf(cborEncode(confPayload as never));
        const structured = {
          capsule_id: capsuleId,
          witness,
          level: confPayload.level,
          confirmation_digest: confDigest,
          confirmation_b64: signed.toString('base64url'),
        };
        return {
          content: [{ type: 'text', text: JSON.stringify(structured) }],
          structuredContent: structured,
        };
      }

      default:
        throw new Error(`Unhandled tool: ${normalizedName}`);
    }
  }

  /**
   * Attach line-delimited JSON-RPC 2.0 over stdio (`Readable` / `Writable` streams
   * or `process.stdin` / `process.stdout`).
   */
  attachStdio(
    input: Readable = process.stdin,
    output: Writable = process.stdout,
  ): { close: () => void } {
    let buffer = '';
    const onData = (chunk: Buffer | string) => {
      buffer += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
      let newlineIdx = buffer.indexOf('\n');
      while (newlineIdx !== -1) {
        const line = buffer.slice(0, newlineIdx).trim();
        buffer = buffer.slice(newlineIdx + 1);
        newlineIdx = buffer.indexOf('\n');
        if (!line) continue;
        void (async () => {
          try {
            const parsed = JSON.parse(line) as JsonRpcRequest | JsonRpcRequest[];
            if (Array.isArray(parsed)) {
              const responses = (
                await Promise.all(parsed.map((item) => this.handleJsonRpc(item)))
              ).filter((r): r is JsonRpcResponse => r !== null);
              if (responses.length > 0) {
                output.write(JSON.stringify(responses) + '\n');
              }
            } else {
              const res = await this.handleJsonRpc(parsed);
              if (res !== null) {
                output.write(JSON.stringify(res) + '\n');
              }
            }
          } catch {
            const errRes: JsonRpcResponse = {
              jsonrpc: '2.0',
              id: null,
              error: { code: -32700, message: 'Parse error' },
            };
            output.write(JSON.stringify(errRes) + '\n');
          }
        })();
      }
    };

    input.on('data', onData);
    return {
      close: () => {
        input.off('data', onData);
      },
    };
  }

  /**
   * Streamable HTTP handler for MCP (`POST` or `GET`), supporting both
   * `application/json` and Server-Sent Events (`text/event-stream`).
   */
  async handleHttpRequest(req: {
    method: string;
    headers?: Record<string, string | undefined>;
    body?: unknown;
  }): Promise<{
    status: number;
    headers: Record<string, string>;
    body: string;
  }> {
    const accept = (req.headers?.['accept'] ?? req.headers?.['Accept'] ?? '').toLowerCase();
    const wantsSse =
      accept.includes('text/event-stream') &&
      (!accept.includes('application/json') ||
        accept.indexOf('text/event-stream') < accept.indexOf('application/json') ||
        req.headers?.['x-mcp-stream'] === 'sse');

    if (req.method.toUpperCase() === 'GET') {
      if (accept.includes('text/event-stream')) {
        const discover = await this.handleJsonRpc({
          jsonrpc: '2.0',
          id: 'sse-init',
          method: 'server/discover',
        });
        return {
          status: 200,
          headers: {
            'content-type': 'text/event-stream; charset=utf-8',
            'cache-control': 'no-cache',
            connection: 'keep-alive',
          },
          body: `event: endpoint\ndata: /mcp\n\nevent: message\ndata: ${JSON.stringify(discover)}\n\n`,
        };
      }
      return {
        status: 405,
        headers: { 'content-type': 'application/json; charset=utf-8' },
        body: JSON.stringify({ error: 'Method Not Allowed; use POST or GET with Accept: text/event-stream' }),
      };
    }

    if (req.method.toUpperCase() !== 'POST') {
      return {
        status: 405,
        headers: { 'content-type': 'application/json; charset=utf-8' },
        body: JSON.stringify({ error: 'Method Not Allowed' }),
      };
    }

    let parsedBody: JsonRpcRequest | JsonRpcRequest[];
    try {
      if (typeof req.body === 'string') {
        parsedBody = JSON.parse(req.body) as JsonRpcRequest | JsonRpcRequest[];
      } else if (Buffer.isBuffer(req.body)) {
        parsedBody = JSON.parse(req.body.toString('utf8')) as JsonRpcRequest | JsonRpcRequest[];
      } else {
        parsedBody = req.body as JsonRpcRequest | JsonRpcRequest[];
      }
    } catch {
      const parseErr: JsonRpcResponse = {
        jsonrpc: '2.0',
        id: null,
        error: { code: -32700, message: 'Parse error' },
      };
      return {
        status: 400,
        headers: { 'content-type': 'application/json; charset=utf-8' },
        body: JSON.stringify(parseErr),
      };
    }

    if (Array.isArray(parsedBody)) {
      const responses = (await Promise.all(parsedBody.map((m) => this.handleJsonRpc(m)))).filter(
        (r): r is JsonRpcResponse => r !== null,
      );
      if (responses.length === 0) {
        return { status: 202, headers: {}, body: '' };
      }
      if (wantsSse) {
        const sseEvents = responses.map((r) => `event: message\ndata: ${JSON.stringify(r)}\n\n`).join('');
        return {
          status: 200,
          headers: {
            'content-type': 'text/event-stream; charset=utf-8',
            'cache-control': 'no-cache',
          },
          body: sseEvents,
        };
      }
      return {
        status: 200,
        headers: { 'content-type': 'application/json; charset=utf-8' },
        body: JSON.stringify(responses),
      };
    }

    const res = await this.handleJsonRpc(parsedBody);
    if (res === null) {
      return { status: 202, headers: {}, body: '' };
    }

    if (wantsSse) {
      return {
        status: 200,
        headers: {
          'content-type': 'text/event-stream; charset=utf-8',
          'cache-control': 'no-cache',
        },
        body: `event: message\ndata: ${JSON.stringify(res)}\n\n`,
      };
    }

    return {
      status: 200,
      headers: { 'content-type': 'application/json; charset=utf-8' },
      body: JSON.stringify(res),
    };
  }
}
