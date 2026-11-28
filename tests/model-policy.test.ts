import assert from 'node:assert/strict';
import test from 'node:test';
import { parseModelPolicy, policyChoice } from '../src/server/model-policy.ts';

const model = (id: string, efforts = ['off', 'low', 'medium', 'high']) => ({
  choice: { id, efforts: efforts as never },
});
const openai = {
  id: 'openai',
  status: 'connected',
  models: [
    model('gpt-6-astra', ['low', 'medium', 'high']),
    model('gpt-6.1-sol'),
    model('gpt-6.1-terra'),
  ],
  retry: {} as Record<string, number>,
};
const local = { id: 'local', status: 'connected', models: [model('ornith-1.5-35b-a3b', ['off'])] };
const policy = parseModelPolicy(
  JSON.stringify({
    chat: ['gpt-6-astra@medium'],
    portal: ['gpt-6.1-terra@medium'],
    fallback: ['gpt-6.1-sol@high', 'ornith-1.5-35b-a3b'],
  }),
);

test('each lane gets its own model, with the effort it names', () => {
  assert.deepEqual(policyChoice(policy, 'chat', [openai, local], 1), {
    connectionId: 'openai',
    modelId: 'gpt-6-astra',
    effort: 'medium',
  });
  assert.equal(policyChoice(policy, 'portal', [openai, local], 1)?.modelId, 'gpt-6.1-terra');
  assert.equal(policyChoice(policy, 'schedule', [openai, local], 1)?.modelId, 'gpt-6.1-sol');
});

test('a paused model or a lost connection moves to the next model, ending at the local one', () => {
  const paused = { ...openai, retry: { 'gpt-6-astra': 10, 'gpt-6.1-sol': 10 } };
  assert.equal(policyChoice(policy, 'chat', [paused, local], 5)?.modelId, 'ornith-1.5-35b-a3b');
  assert.equal(policyChoice(policy, 'chat', [paused, local], 5)?.effort, 'off');
  assert.equal(policyChoice(policy, 'chat', [paused, local], 20)?.modelId, 'gpt-6-astra');
  const down = { ...openai, status: 'reconnect' };
  assert.equal(policyChoice(policy, 'portal', [down, local], 1)?.connectionId, 'local');
  assert.equal(policyChoice(policy, 'portal', [down], 1), undefined);
});

test('a usage limit on one model skips every model of that connection, until its pause ends', () => {
  const fallback = parseModelPolicy(
    JSON.stringify({
      portal: ['gpt-6.1-terra@medium'],
      fallback: ['gpt-6.1-sol@high', 'gpt-6.1-terra@medium', 'ornith-1.5-35b-a3b'],
    }),
  );
  const limited = {
    ...openai,
    retry: { 'gpt-6.1-terra': 10 },
    issues: {
      'gpt-6.1-terra': {
        reason:
          'The ChatGPT user has reached their Subscription Sharing usage limit. Ask the user to try again after their usage limit resets or use an API key instead. (HTTP 200)',
      },
    },
  };
  assert.equal(
    policyChoice(fallback, 'portal', [limited, local], 5)?.modelId,
    'ornith-1.5-35b-a3b',
  );
  assert.equal(policyChoice(fallback, 'fallback', [limited, local], 5)?.connectionId, 'local');
  assert.equal(policyChoice(fallback, 'portal', [limited, local], 20)?.modelId, 'gpt-6.1-terra');
  const timeout = {
    ...limited,
    issues: { 'gpt-6.1-terra': { reason: 'The request timed out. (HTTP 504)' } },
  };
  assert.equal(policyChoice(fallback, 'portal', [timeout, local], 5)?.modelId, 'gpt-6.1-sol');
});

test('a malformed policy is refused, never half-read', () => {
  for (const bad of ['[]', '{"chat":"gpt"}', '{"chats":["gpt"]}', '{"chat":["gpt; rm -rf"]}'])
    assert.throws(() => parseModelPolicy(bad));
});
