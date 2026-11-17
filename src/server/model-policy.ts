import { readFileSync, statSync } from 'node:fs';
import type { ModelEffort, ModelSelection } from '../shared/models.ts';

export const policyLanes = [
  'chat',
  'schedule',
  'background',
  'portal',
  'hold',
  'fallback',
] as const;
export type PolicyLane = (typeof policyLanes)[number];
export type ModelPolicy = Partial<Record<PolicyLane, string[]>>;

interface PolicyRow {
  id: string;
  status: string;
  models: Array<{ choice: { id: string; efforts: ModelEffort[]; audio?: unknown } }>;
  retry?: Record<string, number>;
}

const efforts: readonly ModelEffort[] = ['off', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max'];
const entry = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,79}(@(off|minimal|low|medium|high|xhigh|max))?$/;

export function parseModelPolicy(text: string): ModelPolicy {
  const data: unknown = JSON.parse(text);
  if (!data || typeof data !== 'object' || Array.isArray(data))
    throw new Error('The model policy must be a JSON object of lanes.');
  const policy: ModelPolicy = {};
  for (const [lane, list] of Object.entries(data)) {
    if (!(policyLanes as readonly string[]).includes(lane))
      throw new Error(`The model policy names an unknown lane: ${lane}.`);
    if (
      !Array.isArray(list) ||
      list.length > 8 ||
      !list.every((item) => typeof item === 'string' && entry.test(item))
    )
      throw new Error(
        `The model policy lane ${lane} must be a list of up to 8 "model@effort" entries.`,
      );
    policy[lane as PolicyLane] = list;
  }
  return policy;
}

export function policyChoice(
  policy: ModelPolicy,
  lane: PolicyLane,
  rows: readonly PolicyRow[],
  now = Date.now(),
): ModelSelection | undefined {
  const list =
    lane === 'fallback'
      ? (policy.fallback ?? [])
      : [...(policy[lane] ?? []), ...(policy.fallback ?? [])];
  for (const item of list) {
    const [modelId, wanted] = item.split('@') as [string, ModelEffort | undefined];
    for (const row of rows) {
      if (row.status !== 'connected') continue;
      const model = row.models.find((candidate) => candidate.choice.id === modelId);
      if (!model || model.choice.audio || (row.retry?.[modelId] ?? 0) > now) continue;
      const effort =
        wanted && model.choice.efforts.includes(wanted)
          ? wanted
          : (['medium', 'low', 'high', 'off'] as ModelEffort[]).find((value) =>
              model.choice.efforts.includes(value),
            );
      if (effort && efforts.includes(effort)) return { connectionId: row.id, modelId, effort };
    }
  }
  return undefined;
}

let cached: { path: string; mtime: number; policy: ModelPolicy | undefined } | undefined;

export function loadModelPolicy(path = process.env.NOD_MODEL_POLICY): ModelPolicy | undefined {
  if (!path) return undefined;
  let mtime: number;
  try {
    mtime = statSync(path).mtimeMs;
  } catch {
    return undefined;
  }
  if (cached?.path === path && cached.mtime === mtime) return cached.policy;
  let policy: ModelPolicy | undefined;
  try {
    policy = parseModelPolicy(readFileSync(path, 'utf8'));
  } catch (error) {
    console.error(`Nod ignored the model policy at ${path}: ${(error as Error).message}`);
    policy = undefined;
  }
  cached = { path, mtime, policy };
  return policy;
}
