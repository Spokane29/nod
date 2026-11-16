import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import type { Pool, PoolClient } from 'pg';
import { z } from 'zod';
import { waitingTurnSql } from './turn-chain.ts';
import type { SubmitUserMessageResult } from './thread.ts';

export const signinSourcePrefix = 'inbox:';
const segment = /^[A-Za-z0-9._~-]{1,40}$/;
const label = /^[a-z0-9-]{1,30}$/;

function plainWords(value: string) {
  return (value.match(/-/g) ?? []).length <= 2;
}

export function signinUrl(value: unknown) {
  if (typeof value !== 'string' || value.length > 100 || /[?#@\s\\]/.test(value)) return undefined;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return undefined;
  }
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.port ||
    url.search ||
    url.hash ||
    url.href !== value
  )
    return undefined;
  const labels = url.hostname.split('.');
  if (labels.length < 2 || !labels.every((part) => label.test(part) && plainWords(part)))
    return undefined;
  const parts = url.pathname.split('/').slice(1);
  if (parts.at(-1) === '') parts.pop();
  if (parts.length > 4 || !parts.every((part) => segment.test(part) && plainWords(part)))
    return undefined;
  return value;
}

export function signinMessage(url: string) {
  return `Open ${url} in the browser. If the page shows a sign-in form, sign in with the saved Vault login for this site. Leave the tab open. Do not do anything else on the site: no search, no booking, no hold, no payment, no settings, no agreement. If the site asks for a code, a CAPTCHA or new terms, stop and report it.`;
}

export async function ownerBusy(db: Pick<Pool, 'query'>, ownerId: string, exceptTurnId?: string) {
  const { rows } = await db.query<{ busy: boolean }>(
    `SELECT EXISTS (SELECT 1 FROM turns u WHERE u.owner_id=$1 AND ($2::uuid IS NULL OR u.id<>$2::uuid) AND (
       (u.status IN ('queued','running') AND (u.source IN ('user','task','resume') OR to_jsonb(u)->>'task_id' IS NOT NULL))
       OR (${waitingTurnSql('u')}))) AS busy`,
    [ownerId, exceptTurnId ?? null],
  );
  return rows[0]!.busy;
}

const busyError = () =>
  Object.assign(new Error('Nod is busy or waiting for you.'), { signinBusy: true });

export function registerSigninRequests(
  app: FastifyInstance,
  options: {
    pool: Pool;
    ownerId: string;
    ready: () => boolean;
    submit: (
      text: string,
      attachments: [],
      input: {
        channel: string;
        sourceId: string;
        clientMessageId: string;
        persistSubmission: (client: PoolClient, result: SubmitUserMessageResult) => Promise<void>;
      },
    ) => Promise<SubmitUserMessageResult>;
  },
) {
  const { pool, ownerId } = options;
  app.post('/api/desktop/signin', async (request, reply) => {
    const { url } = z
      .object({ url: z.string().max(100) })
      .strict()
      .parse(request.body);
    const checked = signinUrl(url);
    if (!checked)
      throw Object.assign(new Error('This sign-in address is not accepted.'), { statusCode: 400 });
    if (!options.ready())
      throw Object.assign(
        new Error('Configure an agent provider before starting a conversation.'),
        {
          statusCode: 503,
        },
      );
    const busy = () =>
      reply.code(409).send({ code: 'signin_busy', error: 'Nod is busy or waiting for you.' });
    if (await ownerBusy(pool, ownerId)) return busy();
    try {
      return await options.submit(signinMessage(checked), [], {
        channel: 'web',
        sourceId: `${signinSourcePrefix}${randomUUID()}`,
        clientMessageId: randomUUID(),
        persistSubmission: async (client, result) => {
          if (await ownerBusy(client, ownerId, result.turnId)) throw busyError();
        },
      });
    } catch (error) {
      if ((error as { signinBusy?: boolean }).signinBusy) return busy();
      throw error;
    }
  });
  app.get<{ Params: { id: string } }>('/api/desktop/signin/:id', async (request, reply) => {
    const id = z.uuid().parse(request.params.id);
    const turn = await pool.query<{ status: string }>(
      'SELECT status FROM turns WHERE id=$1 AND owner_id=$2 AND starts_with(source_id,$3)',
      [id, ownerId, signinSourcePrefix],
    );
    if (!turn.rows[0]) return reply.code(404).send({ error: 'Not found.' });
    const uses = await pool.query<{ status: string }>(
      `SELECT status FROM vault_uses WHERE owner_id=$1 AND root_turn_id=$2
         AND kind IN ('identifier','password','method')`,
      [ownerId, id],
    );
    const statuses = uses.rows.map((row) => row.status);
    return {
      turn: turn.rows[0].status,
      signin: !statuses.length
        ? 'none'
        : statuses.every((status) => status === 'submitted')
          ? 'submitted'
          : 'uncertain',
    };
  });
}
