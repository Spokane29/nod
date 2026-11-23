import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { execFile } from 'node:child_process';
import { constants, watch } from 'node:fs';
import { link, lstat, mkdir, open, readdir, realpath, rename, rm, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { isAbsolute, join, resolve, sep } from 'node:path';

export const requestBytes = 2048;
export const siteIntervalMs = 10 * 60_000;
export const hourlyLimit = 20;
export const siteDailyLimit = 16;
export const totalDailyLimit = 60;
export const deferralMs = 15 * 60_000;
export const unconfirmedLimit = 2;
export const autoholdDailyLimit = 5;
export const holdKeyFile = 'autohold-key';
export const dialogTitle = 'Allow sign-in requests?';
export const allowFile = 'signin-allow.json';
export const approvedFile = 'signin-allow.approved';
export const stateFile = 'signin-state.json';
export const checksFile = 'signin-checks.json';
export const healthFile = 'health.json';
export const retryDelayMs = 60_000;
export const signinCauses = [
  'vault_missing',
  'wrong_password',
  'code_asked',
  'captcha',
  'form_blank',
  'browser_error',
  'not_finished',
  'other',
];
const retryCauses = new Set(['form_blank', 'browser_error']);
const noStrikeCauses = new Set(['form_blank', 'browser_error']);
const allowBytes = 65_536;
const stateBytes = 65_536;
const logBytes = 1_000_000;
const rejectedLimit = 400;
const acceptedLimit = 400;
const passLimit = 200;
const outcomeWaitMs = 30 * 60_000;
const holdWaitMs = 12 * 3_600_000;
const hour = 3_600_000;
const day = 24 * hour;
const siteKey = /^[a-z0-9]{2,20}$/;
const requestName = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.json$/;
export const recordsFolder = 'signin-records';
const resumeName = /^([a-z0-9]{2,20})\.signin-resume$/;
const segment = /^[a-z0-9]{1,24}$|^[a-z0-9]{1,15}-[a-z0-9]{1,15}$/;
const label = /^[a-z0-9]{1,30}$|^[a-z0-9]{1,15}-[a-z0-9]{1,15}$/;
const suffix = /^[a-z]{2,24}$/;
const localSuffix = new Set(['localhost', 'local', 'internal', 'lan', 'home', 'arpa', 'test']);

export function signinInboxPath(environment, fileText, home = homedir()) {
  const value = (environment ?? '').trim() || (fileText ?? '').trim();
  if (!value || value.includes('\0')) return '';
  const expanded =
    value === '~' ? home : value.startsWith('~/') ? join(home, value.slice(2)) : value;
  return isAbsolute(expanded) ? resolve(expanded) : '';
}

export function signinUrl(value) {
  if (typeof value !== 'string' || value.length > 100 || /[?#@\s\\]/.test(value)) return undefined;
  let url;
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
  if (
    labels.length < 2 ||
    labels.length > 4 ||
    !suffix.test(labels.at(-1)) ||
    localSuffix.has(labels.at(-1)) ||
    !labels.every((part) => label.test(part) && !part.startsWith('xn--'))
  )
    return undefined;
  const parts = url.pathname.split('/').slice(1);
  if (parts.at(-1) === '') parts.pop();
  if (parts.length > 2 || !parts.every((part) => segment.test(part))) return undefined;
  return value;
}

export function parseAllowList(text) {
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) return undefined;
  if (!data.sites || typeof data.sites !== 'object' || Array.isArray(data.sites)) return undefined;
  const sites = new Map();
  const autohold = new Set();
  const origins = new Map();
  const skipped = [];
  for (const [key, entry] of Object.entries(data.sites)) {
    const url =
      siteKey.test(key) && entry && typeof entry === 'object' ? signinUrl(entry.url) : undefined;
    const extra = url ? loginOrigins(entry.loginOrigins) : undefined;
    if (url && extra) {
      sites.set(key, url);
      if (entry.autohold === true) autohold.add(key);
      if (extra.length) origins.set(key, extra);
    } else skipped.push(key.slice(0, 20));
  }
  return { sites, skipped, autohold, origins };
}

export function loginOrigins(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 4) return undefined;
  const list = [];
  for (const item of value) {
    if (typeof item !== 'string' || !signinUrl(`${item}/`) || new URL(`${item}/`).origin !== item)
      return undefined;
    list.push(item);
  }
  return [...new Set(list)];
}

export function baseDomain(host) {
  return String(host ?? '')
    .toLowerCase()
    .split('.')
    .slice(-2)
    .join('.');
}

export function siteHosts(url, origins = []) {
  return [...new Set([url, ...origins].map((value) => baseDomain(new URL(value).hostname)))];
}

export const portalJobs = ['signin', 'status', 'invoice', 'hold', 'autohold', 'release'];
const bookingRef = /^[A-Za-z0-9][A-Za-z0-9-]{2,23}$/;
const signedJobs = new Set(['autohold', 'release']);
const holdText = /^[A-Za-z0-9][A-Za-z0-9 .'&/-]{0,59}$/;
const holdFields = ['ship', 'sailDate', 'category', 'guests', 'maxTotal', 'currency', 'yesId'];

const tidy = (value) => (typeof value === 'string' ? value.trim().replace(/\s+/g, ' ') : value);
const numeric = (value, shape) =>
  typeof value === 'string' && shape.test(value.trim()) ? Number(value.trim()) : value;

export function holdDetails(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const keys = Object.keys(value).filter((key) => key !== 'ages');
  if (keys.length !== holdFields.length || !holdFields.every((key) => keys.includes(key)))
    return undefined;
  const ship = tidy(value.ship);
  const sailDate = tidy(value.sailDate);
  const category = tidy(value.category);
  const yesId = tidy(value.yesId);
  const currency =
    typeof value.currency === 'string' ? tidy(value.currency).toUpperCase() : value.currency;
  const guests = numeric(value.guests, /^\d{1,2}$/);
  const maxTotal = numeric(value.maxTotal, /^\d{1,7}(\.\d{1,2})?$/);
  const ages = Array.isArray(value.ages)
    ? value.ages.map((age) => numeric(age, /^\d{1,3}$/))
    : value.ages;
  if (
    ages !== undefined &&
    (!Array.isArray(ages) ||
      ages.length !== guests ||
      !ages.every((age) => Number.isInteger(age) && age >= 0 && age <= 120))
  )
    return undefined;
  const date = typeof sailDate === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(sailDate);
  if (
    typeof ship !== 'string' ||
    !holdText.test(ship) ||
    typeof category !== 'string' ||
    !holdText.test(category) ||
    !date ||
    Number.isNaN(Date.parse(`${sailDate}T00:00:00Z`)) ||
    !Number.isInteger(guests) ||
    guests < 1 ||
    guests > 9 ||
    typeof maxTotal !== 'number' ||
    !(maxTotal > 0) ||
    maxTotal > 1_000_000 ||
    !/^\d+(\.\d{1,2})?$/.test(String(maxTotal)) ||
    typeof currency !== 'string' ||
    !/^[A-Z]{3}$/.test(currency) ||
    typeof yesId !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9-]{2,39}$/.test(yesId)
  )
    return undefined;
  return { ship, sailDate, category, guests, maxTotal, currency, yesId, ...(ages ? { ages } : {}) };
}

export function holdSignature(key, site, job, ref, hold) {
  const lines = [
    site,
    job,
    ref,
    ...(hold ? holdFields.map((field) => String(hold[field])) : ['']),
    ...(Array.isArray(hold?.ages) ? [hold.ages.join(',')] : []),
  ];
  return createHmac('sha256', key).update(lines.join('\n')).digest('hex');
}

function holdTexts(raw, hold) {
  const amount = hold.maxTotal;
  const choices = holdFields.map((field) => [
    ...new Set([
      String(raw[field]),
      String(hold[field]),
      ...(field === 'maxTotal' ? [amount.toFixed(2), amount.toFixed(1)] : []),
    ]),
  ]);
  if (hold.ages) choices.push([...new Set([raw.ages.map(String).join(','), hold.ages.join(',')])]);
  return choices.reduce(
    (texts, options) => texts.flatMap((text) => options.map((option) => [...text, option])),
    [[]],
  );
}

function signed(key, data, hold) {
  if (typeof key !== 'string' || key.length < 32 || typeof data.sig !== 'string') return false;
  const given = Buffer.from(data.sig.trim().toLowerCase());
  const head = [data.site, data.job, data.ref];
  const texts = hold ? holdTexts(data.hold, hold) : [['']];
  let match = false;
  for (const text of texts) {
    const expected = Buffer.from(
      createHmac('sha256', key)
        .update([...head, ...text].join('\n'))
        .digest('hex'),
    );
    if (given.length === expected.length && timingSafeEqual(given, expected)) match = true;
  }
  return match;
}

export function validateRequest(text, sites, holds = {}) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > requestBytes)
    return { ok: false, reason: 'request too large' };
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    return { ok: false, reason: 'not valid JSON' };
  }
  if (!data || typeof data !== 'object' || Array.isArray(data))
    return { ok: false, reason: 'not a JSON object' };
  if (typeof data.site !== 'string' || !siteKey.test(data.site))
    return { ok: false, reason: 'bad site key' };
  const job = data.job ?? 'signin';
  if (!portalJobs.includes(job)) return { ok: false, site: data.site, reason: 'unknown job' };
  const fields = signedJobs.has(job)
    ? ['site', 'job', 'ref', 'sig', ...(job === 'autohold' ? ['hold'] : [])]
    : ['site', 'job', 'ref'];
  if (Object.keys(data).some((key) => !fields.includes(key)))
    return {
      ok: false,
      site: data.site,
      reason: `unknown field; only ${fields.join(', ')} are allowed`,
    };
  let hold;
  if (signedJobs.has(job)) {
    if (!holds.sites?.has(data.site))
      return { ok: false, site: data.site, reason: 'this site may not hold without asking' };
    if (typeof data.ref !== 'string' || !bookingRef.test(data.ref))
      return { ok: false, site: data.site, reason: `bad ref for ${job}` };
    if (job === 'autohold') {
      hold = holdDetails(data.hold);
      if (!hold) return { ok: false, site: data.site, reason: 'bad hold details' };
    }
    if (!signed(holds.key, data, hold))
      return { ok: false, site: data.site, reason: 'the request signature is missing or wrong' };
  }
  let ref;
  if (job === 'signin') {
    if (data.ref !== undefined)
      return { ok: false, site: data.site, reason: 'a sign-in takes no ref' };
  } else {
    const refs = typeof data.ref === 'string' ? data.ref.split(',') : [];
    if (
      !refs.length ||
      refs.length > (job === 'status' ? 10 : 1) ||
      !refs.every((value) => bookingRef.test(value))
    )
      return { ok: false, site: data.site, reason: `bad ref for ${job}` };
    ref = refs.join(',');
  }
  const url = sites.get(data.site);
  if (!url) return { ok: false, site: data.site, reason: 'site not in allow-list' };
  return {
    ok: true,
    site: data.site,
    url,
    job,
    ...(ref ? { ref } : {}),
    ...(hold ? { hold } : {}),
    key: job === 'signin' ? data.site : `${data.site}.${job}`,
  };
}

export function pacificStamp(date) {
  const parts = Object.fromEntries(
    new Intl.DateTimeFormat('en-CA', {
      timeZone: 'America/Los_Angeles',
      hourCycle: 'h23',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
      .formatToParts(date)
      .map((part) => [part.type, part.value]),
  );
  return {
    text: `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second}`,
    file: `${parts.year}${parts.month}${parts.day}-${parts.hour}${parts.minute}${parts.second}`,
  };
}

async function readSmall(path, limit) {
  const handle = await open(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  ).catch(() => undefined);
  if (!handle) return undefined;
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.size > limit) return undefined;
    const buffer = Buffer.alloc(info.size);
    const { bytesRead } = await handle.read(buffer, 0, info.size, 0);
    return buffer.subarray(0, bytesRead).toString('utf8');
  } finally {
    await handle.close().catch(() => {});
  }
}

async function writeNew(path, text) {
  const handle = await open(
    path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    await handle.writeFile(text);
  } finally {
    await handle.close();
  }
}

async function writeAtomic(path, text) {
  const draft = `${path}.${randomBytes(6).toString('hex')}`;
  try {
    await writeNew(draft, text);
    await rename(draft, path);
  } catch (error) {
    await rm(draft, { force: true }).catch(() => {});
    throw error;
  }
}

const within = (path, base) =>
  path === base || path.startsWith(base.endsWith(sep) ? base : base + sep);

export async function inboxLocationProblem(inbox, home = homedir(), fs = {}) {
  const lstatOf = fs.lstat ?? lstat;
  const realOf = fs.realpath ?? realpath;
  const info = await lstatOf(inbox).catch(() => undefined);
  if (info?.isSymbolicLink()) return 'the inbox folder is a symlink';
  if (info && !info.isDirectory()) return 'the inbox path is not a folder';
  const real = info ? await realOf(inbox).catch(() => inbox) : inbox;
  const cloud = join(home, 'Library', 'Mobile Documents');
  const banned = [join(home, 'Downloads'), join(home, 'Desktop'), cloud];
  const checked = [];
  for (const path of banned) checked.push(path, await realOf(path).catch(() => path));
  if ([inbox, real].some((path) => checked.some((base) => within(path, base))))
    return 'the inbox folder is under Downloads, Desktop or iCloud Drive';
  const documents = join(home, 'Documents');
  const realDocuments = await realOf(documents).catch(() => documents);
  const realCloud = await realOf(cloud).catch(() => cloud);
  const driveDocuments = await lstatOf(join(cloud, 'com~apple~CloudDocs', 'Documents')).catch(
    () => undefined,
  );
  if (
    [inbox, real].some((path) => within(path, documents) || within(path, realDocuments)) &&
    (within(realDocuments, realCloud) || driveDocuments?.isDirectory())
  )
    return 'the Documents folder is synced by iCloud';
}

export function hasQuarantine(path) {
  if (process.platform !== 'darwin') return Promise.resolve(false);
  return new Promise((accept) =>
    execFile('/usr/bin/xattr', ['-s', '-p', 'com.apple.quarantine', path], (error) =>
      accept(!error),
    ),
  );
}

export function allowListDialog(sites, autohold, origins) {
  return {
    title: dialogTitle,
    detail: `Other programs on this computer will be able to ask Nod to open these pages and sign in with the saved Vault login, with no one in the chat:\n\n${[
      ...sites,
    ]
      .map(
        ([key, url]) =>
          `${key}   ${url}${origins?.get(key)?.length ? `   (its login may also be saved for ${origins.get(key).join(', ')})` : ''}`,
      )
      .join('\n')}\n\n${
      autohold?.size
        ? `HOLDS WITHOUT ASKING: on ${[...autohold].join(', ')}, a signed request can make Nod place a courtesy hold or release one it placed, without asking you first (at most ${autoholdDailyLimit} holds a day, never a payment).\n\n`
        : ''
    }Nothing else can be requested this way.`,
    buttons: ['Allow', 'Keep off'],
    defaultId: 1,
    cancelId: 1,
  };
}

export async function loadAllowList(options) {
  const { dataDir, showDialog, seal, unseal } = options;
  if (typeof seal !== 'function' || typeof unseal !== 'function')
    return { reason: 'this computer cannot protect the approval' };
  const text = await readSmall(join(dataDir, allowFile), allowBytes);
  if (text === undefined) return { reason: 'the allow-list is missing or unreadable' };
  const parsed = parseAllowList(text);
  if (!parsed) return { reason: 'the allow-list is not valid' };
  if (!parsed.sites.size) return { reason: 'the allow-list has no valid sites' };
  const hash = createHash('sha256').update(text).digest('hex');
  const approved = ((await readSmall(join(dataDir, approvedFile), 4096)) ?? '').trim();
  let opened;
  try {
    opened = approved ? await unseal(approved) : undefined;
  } catch {
    opened = undefined;
  }
  const loaded = {
    sites: parsed.sites,
    skipped: parsed.skipped,
    autohold: parsed.autohold,
    origins: parsed.origins,
  };
  if (opened === hash) return loaded;
  const answer = await showDialog(allowListDialog(parsed.sites, parsed.autohold, parsed.origins));
  if (answer !== 0) return { reason: 'the allow-list was not approved' };
  await writeAtomic(join(dataDir, approvedFile), `${await seal(hash)}\n`);
  return loaded;
}

export const statusFile = 'status.json';

export async function writeSigninStatus(dataDir, fields, clock = Date.now) {
  try {
    const records = join(dataDir, recordsFolder);
    await mkdir(records, { recursive: true, mode: 0o700 });
    const info = await lstat(records);
    if (!info.isDirectory() || info.isSymbolicLink()) return;
    const path = join(records, statusFile);
    const previous = JSON.parse((await readSmall(path, 16_384)) ?? '{}');
    const next = { ...previous, ...fields, updatedAt: pacificStamp(new Date(clock())).text };
    await writeAtomic(path, `${JSON.stringify(next, null, 2)}\n`);
  } catch {}
}

export async function prepareSigninInbox(options) {
  const { environment, setting, dataDir, home, showDialog, seal, unseal } = options;
  const diagnostic = options.diagnostic ?? (() => {});
  const status = options.status ?? (() => {});
  const off = async (reason) => {
    diagnostic(`Sign-in inbox is off: ${reason}.`);
    await status({ state: 'off', reason, lastPass: null });
    return undefined;
  };
  const inbox = signinInboxPath(environment, setting, home);
  if (!inbox)
    return off(
      'no inbox folder is set (NOD_SIGNIN_INBOX or the signin-inbox file in the data folder)',
    );
  if ((options.platform ?? process.platform) !== 'darwin')
    return off('it is available on macOS only');
  const problem = await inboxLocationProblem(inbox, home, options.fs);
  if (problem) return off(problem);
  const ask = async (dialog) => {
    await status({ state: 'off', reason: 'waiting for the owner to approve the site list in Nod' });
    return showDialog(dialog);
  };
  const loaded = await loadAllowList({ dataDir, showDialog: ask, seal, unseal });
  if (!loaded.sites) return off(loaded.reason);
  if (loaded.skipped.length) diagnostic('Sign-in inbox ignored invalid allow-list entries.');
  await status({ state: 'on', reason: null, inbox, sites: [...loaded.sites.keys()] });
  return {
    inbox,
    sites: loaded.sites,
    autohold: loaded.autohold,
    origins: loaded.origins,
    dataDir,
  };
}

export function createGate(options) {
  const { file } = options;
  const clock = options.now ?? Date.now;
  const siteMs = options.siteMs ?? siteIntervalMs;
  let state = { accepted: [], strikes: {}, blocked: {}, pending: {}, held: {}, placed: {} };
  let holdUntil = 0;
  let unsaved = false;
  return {
    get state() {
      return state;
    },
    async load() {
      const text = await readSmall(file, stateBytes);
      let data;
      try {
        data = text === undefined ? undefined : JSON.parse(text);
      } catch {
        data = undefined;
      }
      if (data && typeof data === 'object' && Array.isArray(data.accepted)) {
        state = {
          accepted: data.accepted.filter(
            (item) =>
              Array.isArray(item) && typeof item[0] === 'string' && Number.isFinite(item[1]),
          ),
          strikes: data.strikes && typeof data.strikes === 'object' ? data.strikes : {},
          blocked: data.blocked && typeof data.blocked === 'object' ? data.blocked : {},
          pending: data.pending && typeof data.pending === 'object' ? data.pending : {},
          held: data.held && typeof data.held === 'object' ? data.held : {},
          placed: data.placed && typeof data.placed === 'object' ? data.placed : {},
        };
      } else {
        holdUntil = clock() + siteMs;
        unsaved = true;
      }
    },
    async settled() {
      if (unsaved && clock() >= holdUntil) {
        unsaved = false;
        await this.save();
      }
    },
    async save() {
      unsaved = false;
      const now = clock();
      state.accepted = state.accepted.filter(([, at]) => now - at < day);
      await writeAtomic(file, JSON.stringify(state));
    },
    check(site, now, ref) {
      if (now < holdUntil) return { state: 'wait' };
      if (site.endsWith('.autohold')) {
        if (state.held[ref]) return { state: 'reject', reason: 'this quote was already held once' };
        const today = state.accepted.filter(
          ([name, at]) => name.endsWith('.autohold') && now - at < day,
        );
        if (today.length >= autoholdDailyLimit)
          return {
            state: 'reject',
            reason: `rate limit: ${autoholdDailyLimit} holds without asking per day`,
          };
      }
      if (site.endsWith('.release') && state.placed[ref] !== site.split('.')[0])
        return { state: 'reject', reason: 'nod did not place this booking' };
      if (state.blocked[site])
        return {
          state: 'reject',
          reason: `site paused after ${unconfirmedLimit} sign-ins that were not confirmed; put an empty ${site}.signin-resume file in Nod's data folder to resume`,
        };
      const recent = state.accepted.filter(([, at]) => now - at < day);
      const last = recent.filter(([name]) => name === site).map(([, at]) => at);
      if (last.some((at) => now - at < siteMs))
        return { state: 'reject', reason: 'rate limit: one request per site every 10 minutes' };
      if (recent.filter(([, at]) => now - at < hour).length >= hourlyLimit)
        return { state: 'reject', reason: `rate limit: ${hourlyLimit} requests per hour` };
      if (last.length >= siteDailyLimit)
        return {
          state: 'reject',
          reason: `rate limit: ${siteDailyLimit} requests per site per day`,
        };
      if (recent.length >= totalDailyLimit)
        return { state: 'reject', reason: `rate limit: ${totalDailyLimit} requests per day` };
      return { state: 'ok' };
    },
    record(site, now) {
      state.accepted.push([site, now]);
    },
    track(site, turnId, now, ref) {
      state.pending[site] = { turnId, at: now, ...(ref ? { ref } : {}) };
      if (site.endsWith('.autohold') && ref) state.held[ref] = now;
    },
    placed(site, booking) {
      if (booking) state.placed[booking] = site;
      else delete state.placed[site];
    },
    settle(site, confirmed, typed = true) {
      delete state.pending[site];
      if (site.includes('.')) return;
      if (confirmed) {
        delete state.strikes[site];
        return;
      }
      if (!typed) return;
      state.strikes[site] = (state.strikes[site] ?? 0) + 1;
      if (state.strikes[site] >= unconfirmedLimit) state.blocked[site] = true;
    },
    retryLater(site, entry) {
      state.pending[site] = entry;
    },
    reset(site) {
      delete state.strikes[site];
      delete state.blocked[site];
    },
  };
}

export function heldBooking(reply) {
  return /^BOOKING ([A-Za-z0-9][A-Za-z0-9-]{2,23}) EXPIRES \S/m.exec(
    typeof reply === 'string' ? reply : '',
  )?.[1];
}

export function outcomeConfirmed(outcome, key = '', ref = '') {
  if (
    outcome?.turn !== 'succeeded' ||
    !(outcome.signin === 'submitted' || outcome.signin === 'none')
  )
    return false;
  const lines = String(outcome.reply ?? '')
    .split('\n')
    .map((line) => line.trim());
  if (key && !key.includes('.'))
    return lines.includes('SIGNED-IN') && !lines.some((line) => line.startsWith('NOT-SIGNED-IN'));
  if (key.endsWith('.autohold')) return Boolean(heldBooking(outcome.reply));
  if (key.endsWith('.release'))
    return String(outcome.reply ?? '')
      .split('\n')
      .some((line) => line.trim() === `RELEASED ${ref}`);
  return true;
}

const loginLabels = new Set([
  'login',
  'logon',
  'signin',
  'identity',
  'sso',
  'auth',
  'accounts',
  'idp',
]);
const checkText = /^[^\n\r]{2,60}$/;
const hostShape = /^[a-z0-9.-]{3,100}$/;

export function parseSigninChecks(text) {
  const checks = new Map();
  let data;
  try {
    data = JSON.parse(text ?? '');
  } catch {
    return checks;
  }
  if (!data?.sites || typeof data.sites !== 'object' || Array.isArray(data.sites)) return checks;
  for (const [key, entry] of Object.entries(data.sites)) {
    if (!siteKey.test(key) || !entry || typeof entry !== 'object') continue;
    const list = (value, shape) =>
      Array.isArray(value)
        ? value.filter((item) => typeof item === 'string' && shape.test(item)).slice(0, 8)
        : [];
    checks.set(key, {
      signedIn: list(entry.signedIn, checkText),
      browserFilled: entry.browserFilled === true,
      loginHosts: list(
        Array.isArray(entry.loginHosts)
          ? entry.loginHosts.map((host) => (typeof host === 'string' ? host.toLowerCase() : host))
          : [],
        hostShape,
      ),
    });
  }
  return checks;
}

export function loginHost(host, extra = []) {
  const name = String(host ?? '').toLowerCase();
  return extra.includes(name) || loginLabels.has(name.split('.')[0]);
}

export function pageVerdict(look, check = {}) {
  if (!look || typeof look !== 'object') return { ok: false, cause: 'browser_error' };
  if (look.passwords > 0 || loginHost(look.host, check.loginHosts))
    return { ok: false, cause: 'not_finished' };
  if (!(look.textLength >= 40)) return { ok: false, cause: 'form_blank' };
  if (!look.signOut && !(look.markers > 0)) return { ok: false, cause: 'not_finished' };
  return { ok: true, cause: null };
}

export function replyCause(reply) {
  const t = String(reply ?? '').toLowerCase();
  if (/captcha|are you a robot|verify you are human/.test(t)) return 'captcha';
  if (
    /verification code|one-time|two-factor|2fa|asked for a code|asks for a code|enter the code|code (?:was )?sent|sent (?:a|the) code/.test(
      t,
    )
  )
    return 'code_asked';
  if (
    /incorrect|not accepted|rejected the saved|invalid (?:email|password|credentials)|wrong password/.test(
      t,
    )
  )
    return 'wrong_password';
  if (
    /no (?:matching )?saved (?:vault )?login|no saved login|couldn.t find a matching|matching saved (?:vault )?login was found|saved login is for a different|saved login is for \S+, not/.test(
      t,
    )
  )
    return 'vault_missing';
  if (
    /stayed blank|did not load|didn.t load|not load|neither a sign-in form|no sign-in form|blank page|spinner/.test(
      t,
    )
  )
    return 'form_blank';
  if (/connection error|couldn.t read|could not read|couldn.t verify|could not verify/.test(t))
    return 'browser_error';
  if (/didn.t finish|did not finish/.test(t)) return 'not_finished';
  return 'other';
}

export function shortReason(reply) {
  const lines = String(reply ?? '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
  const line =
    lines.find((item) => item.startsWith('NOT-SIGNED-IN')) ??
    lines.find((item) => item === 'SIGNED-IN') ??
    '';
  return line
    .replace(/\d{4,}/g, '#')
    .replace(/\S+@\S+/g, '[email]')
    .slice(0, 160);
}

export function signinVerdict(outcome, look, check = {}) {
  const reason = shortReason(outcome?.reply);
  if (!outcome || !finished.has(outcome.turn))
    return { confirmed: false, cause: 'not_finished', reason };
  if (outcome.turn !== 'succeeded') {
    const cause = replyCause(outcome.reply);
    return { confirmed: false, cause: cause === 'other' ? 'not_finished' : cause, reason };
  }
  if (!outcomeConfirmed(outcome, 'site')) {
    const cause = replyCause(outcome.reply);
    return {
      confirmed: false,
      cause: cause === 'other' && outcome.signin === 'uncertain' ? 'not_finished' : cause,
      reason,
    };
  }
  const page = pageVerdict(look, check);
  return page.ok
    ? { confirmed: true, cause: null, reason }
    : { confirmed: false, cause: page.cause, reason };
}

export function pageProbe(markers = []) {
  return `(() => {
  const markers = ${JSON.stringify(markers.map((item) => item.toLowerCase()))};
  const shown = (element) => element.getClientRects().length > 0;
  const passwords = [...document.querySelectorAll('input[type=password]')].filter(shown).length;
  const controls = [...document.querySelectorAll('a,button,[role=button],[role=menuitem],input[type=submit],input[type=button]')]
    .map((element) => [element.textContent, element.getAttribute('aria-label'), element.getAttribute('title'), element.getAttribute('href'), element.type === 'submit' || element.type === 'button' ? element.value : ''].join(' '))
    .join('\\n');
  const signOut = /\\b(sign|log)[ -]?(out|off)\\b|logout|signout|logoff/i.test(controls);
  const text = document.body ? document.body.innerText.slice(0, 50000) : '';
  const lower = text.toLowerCase();
  const frames = [...document.querySelectorAll('iframe')].map((frame) => frame.getAttribute('src') || '').join(' ');
  return {
    host: location.hostname,
    title: document.title.slice(0, 80),
    passwords,
    signOut,
    markers: markers.filter((marker) => lower.includes(marker)).length,
    textLength: text.trim().length,
    captcha: /captcha|are you a robot|verify you are human/.test(lower) || /recaptcha|hcaptcha|turnstile/i.test(frames),
    codeAsked: /verification code|one-time|security code|enter the code|code (?:was )?sent|two-factor|2fa/.test(lower),
    loginError: /incorrect|invalid (?:user ?name|email|password|credentials)|login failed|authentication failed|not recogni[sz]ed|try again/.test(lower),
  };
})()`;
}

export const filledProbe = `(() => {
  const shown = (element) => element.getClientRects().length > 0;
  const filled = (element) => {
    let auto = false;
    try {
      auto = element.matches(':autofill');
    } catch {}
    try {
      auto = auto || element.matches(':-webkit-autofill');
    } catch {}
    return auto || element.value.length > 0;
  };
  const passwords = [...document.querySelectorAll('input[type=password]')].filter(shown);
  if (passwords.length !== 1) return { ok: false, reason: 'no single visible password field' };
  const form = passwords[0].form;
  if (!form) return { ok: false, reason: 'the password field has no form' };
  const users = [...form.querySelectorAll('input')].filter(
    (element) => shown(element) && ['text', 'email', 'tel', ''].includes(element.getAttribute('type') || ''),
  );
  if (users.length !== 1) return { ok: false, reason: 'no single visible username field' };
  if (!filled(passwords[0]) || !filled(users[0])) return { ok: false, reason: 'the form is not filled' };
  const buttons = [...form.querySelectorAll('button,input[type=submit]')].filter(
    (element) => shown(element) && !element.disabled && (element.tagName !== 'BUTTON' || (element.getAttribute('type') || 'submit') === 'submit'),
  );
  if (buttons.length !== 1) return { ok: false, reason: 'no single sign-in button' };
  buttons[0].scrollIntoView({ block: 'center' });
  const box = buttons[0].getBoundingClientRect();
  if (!(box.width > 0 && box.height > 0)) return { ok: false, reason: 'the sign-in button has no size' };
  return { ok: true, x: box.left + box.width / 2, y: box.top + box.height / 2 };
})()`;

export function pickTarget(targets, hosts, prefer) {
  const pages = (Array.isArray(targets) ? targets : []).filter((target) => {
    if (target?.type !== 'page' || typeof target.webSocketDebuggerUrl !== 'string') return false;
    try {
      const url = new URL(target.url);
      return url.protocol === 'https:' && hosts.includes(baseDomain(url.hostname));
    } catch {
      return false;
    }
  });
  if (prefer)
    for (const target of pages) if (new URL(target.url).hostname === prefer) return target;
  return pages[0];
}

function cdpSend(address, commands, timeoutMs) {
  return new Promise((accept, refuse) => {
    const socket = new WebSocket(address);
    const results = [];
    const timer = setTimeout(() => {
      socket.close();
      refuse(new Error('the page did not answer in time'));
    }, timeoutMs);
    const next = () => {
      if (results.length === commands.length) {
        clearTimeout(timer);
        socket.close();
        accept(results);
        return;
      }
      const [method, params] = commands[results.length];
      socket.send(JSON.stringify({ id: results.length + 1, method, params }));
    };
    socket.addEventListener('open', next);
    socket.addEventListener('message', (event) => {
      let data;
      try {
        data = JSON.parse(String(event.data));
      } catch {
        return;
      }
      if (data.id !== results.length + 1) return;
      if (data.error) {
        clearTimeout(timer);
        socket.close();
        refuse(new Error('the browser refused a step'));
        return;
      }
      results.push(data.result);
      next();
    });
    socket.addEventListener('error', () => {
      clearTimeout(timer);
      refuse(new Error('the browser connection failed'));
    });
  });
}

async function cdpEvaluate(address, expression, timeoutMs) {
  const [result] = await cdpSend(
    address,
    [['Runtime.evaluate', { expression, returnByValue: true, timeout: timeoutMs }]],
    timeoutMs,
  );
  if (!result?.result?.value || result.exceptionDetails)
    throw new Error('the page could not be read');
  return result.result.value;
}

async function siteTarget(port, hosts, prefer, timeoutMs) {
  if (!/^\d{2,5}$/.test(String(port))) return undefined;
  const response = await fetch(`http://127.0.0.1:${port}/json/list`, {
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) return undefined;
  const target = pickTarget(await response.json(), hosts, prefer);
  if (!target) return undefined;
  const address = new URL(target.webSocketDebuggerUrl);
  return address.hostname === '127.0.0.1' || address.hostname === 'localhost' ? target : undefined;
}

export async function pressFilledForm({ port, hosts, prefer, timeoutMs = 5000, send = cdpSend }) {
  const target = await siteTarget(port, hosts, prefer, timeoutMs);
  if (!target) return { pressed: false, reason: 'no tab on the site' };
  const host = new URL(target.url).hostname;
  const [probe] = await send(
    target.webSocketDebuggerUrl,
    [['Runtime.evaluate', { expression: filledProbe, returnByValue: true, timeout: timeoutMs }]],
    timeoutMs,
  );
  const found = probe?.result?.value;
  if (!found?.ok)
    return { pressed: false, host, reason: String(found?.reason ?? 'the form could not be read') };
  const at = { x: Number(found.x), y: Number(found.y), button: 'left', clickCount: 1 };
  await send(
    target.webSocketDebuggerUrl,
    [
      ['Page.bringToFront', {}],
      ['Input.dispatchMouseEvent', { type: 'mouseMoved', x: at.x, y: at.y }],
      ['Input.dispatchMouseEvent', { type: 'mousePressed', ...at }],
      ['Input.dispatchMouseEvent', { type: 'mouseReleased', ...at }],
    ],
    timeoutMs,
  );
  return { pressed: true, host };
}

export function cdpPressFilled(dataDir) {
  return async ({ hosts, prefer }) => {
    const port = ((await readSmall(join(dataDir, 'browser-cdp'), 64)) ?? '').trim();
    return pressFilledForm({ port, hosts, prefer }).catch(() => ({
      pressed: false,
      reason: 'the browser could not be reached',
    }));
  };
}

export function filledVerdict(look, check = {}) {
  const reason = 'the browser had filled the sign-in form; Nod pressed its sign-in button once';
  if (!look || typeof look !== 'object')
    return { confirmed: false, cause: 'browser_error', reason };
  if (look.captcha) return { confirmed: false, cause: 'captcha', reason };
  if (look.codeAsked) return { confirmed: false, cause: 'code_asked', reason };
  if (look.passwords > 0 && look.loginError)
    return { confirmed: false, cause: 'wrong_password', reason };
  const page = pageVerdict(look, check);
  return { confirmed: page.ok, cause: page.cause, reason };
}

export async function readSitePage({ port, hosts, markers, prefer, timeoutMs = 5000 }) {
  const target = await siteTarget(port, hosts, prefer, timeoutMs);
  if (!target) return undefined;
  const look = await cdpEvaluate(target.webSocketDebuggerUrl, pageProbe(markers), timeoutMs);
  return {
    host: String(look.host ?? ''),
    title: String(look.title ?? ''),
    passwords: Number(look.passwords) || 0,
    signOut: look.signOut === true,
    markers: Number(look.markers) || 0,
    textLength: Number(look.textLength) || 0,
    captcha: look.captcha === true,
    codeAsked: look.codeAsked === true,
    loginError: look.loginError === true,
  };
}

export function cdpPageCheck(dataDir) {
  return async ({ hosts, markers, prefer }) => {
    const port = ((await readSmall(join(dataDir, 'browser-cdp'), 64)) ?? '').trim();
    return readSitePage({ port, hosts, markers, prefer }).catch(() => undefined);
  };
}

export function replyHost(reply) {
  const match = /\]\((https:\/\/[^)\s]+)\)/.exec(String(reply ?? ''));
  try {
    return match ? new URL(match[1]).hostname : undefined;
  } catch {
    return undefined;
  }
}

export const healthHourMs = hour;
const healthLine =
  /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (\S+) (confirmed|unconfirmed|rejected|waiting|resumed)\b/;

export function pacificIso(ms) {
  const parts = Object.fromEntries(
    new Intl.DateTimeFormat('en-US', {
      timeZone: 'America/Los_Angeles',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hourCycle: 'h23',
      timeZoneName: 'longOffset',
    })
      .formatToParts(new Date(ms))
      .map((part) => [part.type, part.value]),
  );
  const offset = /GMT([+-])(\d{1,2})(?::?(\d{2}))?/.exec(parts.timeZoneName ?? '');
  return `${parts.year}-${parts.month}-${parts.day}T${parts.hour}:${parts.minute}:${parts.second}${offset ? `${offset[1]}${offset[2].padStart(2, '0')}:${offset[3] ?? '00'}` : '-08:00'}`;
}

export function pacificMs(date, time) {
  for (const offset of ['-08:00', '-07:00']) {
    const ms = Date.parse(`${date}T${time}${offset}`);
    if (Number.isFinite(ms) && pacificIso(ms).startsWith(`${date}T${time}`)) return ms;
  }
  return null;
}

export function signinHealth(logText, { now, sites = [], causes = {} }) {
  const lines = [];
  for (const line of String(logText ?? '').split('\n')) {
    const match = healthLine.exec(line);
    if (!match || match[3].includes('.')) continue;
    const at = pacificMs(match[1], match[2]);
    if (at !== null) lines.push({ at, site: match[3], outcome: match[4] });
  }
  lines.sort((a, b) => a.at - b.at);
  const names = [...new Set([...sites, ...lines.map((line) => line.site)])].sort();
  return {
    updatedAt: pacificIso(now),
    sites: names.map((site) => {
      const mine = lines.filter(
        (line) => line.site === site && line.outcome !== 'resumed' && line.at <= now,
      );
      const window = mine.filter((line) => now - line.at < 48 * hour);
      const recent = window.filter((line) => now - line.at < day);
      const count = (list, outcome) => list.filter((line) => line.outcome === outcome).length;
      const lastConfirmed = mine.filter((line) => line.outcome === 'confirmed').at(-1)?.at ?? null;
      const newestVerdict = window
        .filter((line) => line.outcome === 'confirmed' || line.outcome === 'unconfirmed')
        .at(-1);
      const counts48h = {
        confirmed: count(window, 'confirmed'),
        unconfirmed: count(window, 'unconfirmed'),
        rejected: count(window, 'rejected'),
      };
      const confirmed24h = count(recent, 'confirmed');
      const state = !recent.length
        ? 'unknown'
        : !confirmed24h
          ? 'down'
          : newestVerdict?.outcome === 'unconfirmed' || counts48h.unconfirmed >= 2
            ? 'flaky'
            : 'ok';
      const newest = mine.at(-1);
      return {
        site,
        state,
        lastConfirmedAt: lastConfirmed === null ? null : pacificIso(lastConfirmed),
        lastResult: newest ? { outcome: newest.outcome, at: pacificIso(newest.at) } : null,
        requests24h: recent.length,
        confirmed24h,
        counts48h,
        lastCause: signinCauses.includes(causes[site]) ? causes[site] : null,
      };
    }),
  };
}

const finished = new Set(['succeeded', 'failed', 'cancelled', 'waiting']);
const signedRequest = /"job"\s*:\s*"(autohold|release)"/;

export function startSigninInbox(options) {
  const { inbox, sites, request, isIdle } = options;
  const clock = options.now ?? Date.now;
  const quarantined = options.hasQuarantine ?? hasQuarantine;
  const gate = createGate({
    file: join(options.dataDir, stateFile),
    now: clock,
    siteMs: options.limits?.siteMs,
  });
  const intervals = { missing: 60_000, idle: 60_000, pending: 15_000, ...options.intervals };
  const debounceMs = options.debounceMs ?? 500;
  const retryMs = options.limits?.retryMs ?? retryDelayMs;
  const origins = options.origins ?? new Map();
  const pageCheck = options.pageCheck;
  const pressFilled = options.pressFilled;
  const filledWaitMs = options.limits?.filledWaitMs ?? 20_000;
  const records = join(options.dataDir, recordsFolder);
  const logPath = join(records, 'log.txt');
  const acceptedLogPath = join(records, 'accepted-log.txt');
  const acceptedDirectory = join(records, 'accepted');
  const rejectedDirectory = join(records, 'rejected');
  const repliesDirectory = join(records, 'replies');
  const firstSeen = new Map();
  const stuck = new Set();
  const noted = new Set();
  let watcher;
  let timer;
  let debounce;
  let stopped = false;
  let loaded = false;
  let running = Promise.resolve();

  async function appendLog(path, line) {
    const handle = await open(
      path,
      constants.O_WRONLY |
        constants.O_APPEND |
        constants.O_CREAT |
        constants.O_NOFOLLOW |
        constants.O_NONBLOCK,
      0o600,
    ).catch(() => undefined);
    if (!handle) return;
    try {
      if (!(await handle.stat()).isFile()) return;
      await handle.appendFile(line);
    } catch {
    } finally {
      await handle.close().catch(() => {});
    }
  }

  async function log(site, decision, reason) {
    const stamp = pacificStamp(new Date(clock()));
    const line = `${stamp.text} ${site || '-'} ${decision} ${reason}\n`;
    if (decision === 'accepted') return appendLog(acceptedLogPath, line);
    const info = await lstat(logPath).catch(() => undefined);
    if (info?.isFile() && info.size > logBytes)
      await rename(logPath, join(records, 'log.1.txt')).catch(() => {});
    await appendLog(logPath, line);
  }

  async function ensure(directory) {
    await mkdir(directory, { mode: 0o700 }).catch((error) => {
      if (error?.code !== 'EEXIST') throw error;
    });
    const info = await lstat(directory);
    if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('not a directory');
  }

  async function prune(directory, limit) {
    const names = await readdir(directory).catch(() => []);
    if (names.length <= limit) return;
    const dated = await Promise.all(
      names.map(async (name) => [
        name,
        (await stat(join(directory, name)).catch(() => undefined))?.mtimeMs ?? 0,
      ]),
    );
    dated.sort((a, b) => a[1] - b[1]);
    for (const [name] of dated.slice(0, names.length - limit))
      await rm(join(directory, name), { force: true }).catch(() => {});
  }

  async function reject(name, site, reason, identity) {
    const stem = name.replace(/\.json$/, '');
    const target = join(
      rejectedDirectory,
      `${stem}-${pacificStamp(new Date(clock())).file}-${randomBytes(2).toString('hex')}`,
    );
    try {
      await ensure(rejectedDirectory);
      await prune(rejectedDirectory, rejectedLimit);
      await rename(join(inbox, name), `${target}.json`);
      await writeNew(`${target}.reason.txt`, `${reason}\n`).catch(() => {});
    } catch {
      const removed = await rm(join(inbox, name), { force: true }).then(
        () => true,
        () => false,
      );
      if (!removed || (await lstat(join(inbox, name)).catch(() => undefined))) stuck.add(identity);
    }
    firstSeen.delete(identity);
    await log(site, 'rejected', reason);
  }

  async function restore(claimed, path) {
    const back = await link(claimed, path).then(
      () => true,
      () => false,
    );
    await rm(claimed, { force: true }).catch(() => {});
    return back;
  }

  async function handle(name) {
    const path = join(inbox, name);
    const info = await lstat(path).catch(() => undefined);
    if (!info) return 'done';
    const identity = `${name}:${info.dev}:${info.ino}:${info.mtimeMs}`;
    if (stuck.has(identity)) return 'skipped';
    const now = clock();
    const seen = firstSeen.get(identity) ?? now;
    firstSeen.set(identity, seen);
    if (firstSeen.size > 1000) firstSeen.clear();
    if (info.isSymbolicLink() || !info.isFile()) {
      if (info.isDirectory()) stuck.add(identity);
      else await rm(path, { force: true }).catch(() => stuck.add(identity));
      firstSeen.delete(identity);
      await log('', 'rejected', 'not a regular file');
      return 'done';
    }
    if (info.size > requestBytes) {
      await reject(name, '', 'file too large', identity);
      return 'done';
    }
    const handleFile = await open(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    ).catch(() => undefined);
    if (!handleFile) {
      await reject(name, '', 'not a regular file', identity);
      return 'done';
    }
    let opened;
    let text;
    try {
      opened = await handleFile.stat();
      if (opened.isFile() && opened.size <= requestBytes && opened.nlink === 1) {
        const buffer = Buffer.alloc(opened.size);
        const { bytesRead } = await handleFile.read(buffer, 0, opened.size, 0);
        text = buffer.subarray(0, bytesRead).toString('utf8');
      }
    } finally {
      await handleFile.close().catch(() => {});
    }
    if (text === undefined) {
      await reject(
        name,
        '',
        opened?.nlink > 1 ? 'file has more than one link' : 'file changed while being read',
        identity,
      );
      return 'done';
    }
    if (await quarantined(path)) {
      await reject(name, '', 'file is quarantined', identity);
      return 'done';
    }
    const result = validateRequest(text, sites, {
      sites: options.autohold,
      key: signedRequest.test(text) ? await options.holdKey?.().catch(() => undefined) : undefined,
    });
    if (!result.ok) {
      await reject(
        name,
        result.site && siteKey.test(result.site) ? result.site : '',
        result.reason,
        identity,
      );
      return 'done';
    }
    const decision = gate.check(result.key, now, result.ref);
    if (decision.state === 'reject') {
      await reject(name, result.key, decision.reason, identity);
      return 'done';
    }
    const waiting = async (reason) => {
      if (now - seen > deferralMs) {
        noted.delete(identity);
        await reject(name, result.key, reason, identity);
        return 'done';
      }
      if (!noted.has(identity)) {
        if (noted.size > 1000) noted.clear();
        noted.add(identity);
        await log(result.key, 'waiting', reason.replace(' for 15 minutes', ''));
      }
      return 'deferred';
    };
    if (decision.state === 'wait') return waiting('limits were unavailable for 15 minutes');
    if (
      Object.keys(gate.state.pending).some(
        (key) => key === result.site || key.startsWith(`${result.site}.`),
      )
    )
      return waiting('another job for this site was still running for 15 minutes');
    const idle = await Promise.resolve()
      .then(() => isIdle(result.job))
      .catch(() => false);
    if (!idle) return waiting('nod was busy or waiting for you for 15 minutes');
    const stamp = pacificStamp(new Date(now));
    const base = `${result.key}-${stamp.file}`;
    const claimed = join(acceptedDirectory, `${base}.json`);
    try {
      await ensure(acceptedDirectory);
      await prune(acceptedDirectory, acceptedLimit);
      await rename(path, claimed);
    } catch {
      stuck.add(identity);
      await log(result.site, 'rejected', 'could not claim the request file');
      return 'done';
    }
    firstSeen.delete(identity);
    const moved = await lstat(claimed).catch(() => undefined);
    if (
      !moved?.isFile() ||
      moved.isSymbolicLink() ||
      moved.dev !== opened.dev ||
      moved.ino !== opened.ino ||
      moved.nlink !== 1
    ) {
      await rm(claimed, { force: true }).catch(() => {});
      await log(result.site, 'rejected', 'file changed while being claimed');
      return 'done';
    }
    const ready = await Promise.resolve()
      .then(() => isIdle(result.job))
      .catch(() => false);
    let posted;
    let failure = '';
    let busy = !ready;
    if (ready)
      try {
        const response = await post(result);
        if (response.status === 409) busy = true;
        else if (!response.ok) failure = `nod refused the request (status ${response.status})`;
        else {
          const body = await response.json();
          if (typeof body?.messageId === 'string' && typeof body?.threadId === 'string')
            posted = body;
          else failure = 'nod returned no message id';
        }
      } catch {
        failure = 'could not reach nod';
      }
    if (busy) {
      if (await restore(claimed, path)) firstSeen.set(identity, seen);
      else await log(result.site, 'rejected', 'superseded while waiting');
      return 'deferred';
    }
    gate.record(result.key, now);
    if (!posted) {
      try {
        await ensure(rejectedDirectory);
        const target = join(rejectedDirectory, `${base}`);
        await rename(claimed, `${target}.json`);
        await writeNew(`${target}.reason.txt`, `${failure}\n`);
      } catch {}
      await gate.save().catch(() => {});
      await log(result.key, 'rejected', failure);
      return 'done';
    }
    if (typeof posted.turnId === 'string') gate.track(result.key, posted.turnId, now, result.ref);
    await gate.save().catch(() => {});
    await writeNew(
      join(acceptedDirectory, `${base}.result.json`),
      `${JSON.stringify(
        {
          site: result.site,
          job: result.job,
          ...(result.ref ? { ref: result.ref } : {}),
          url: result.url,
          acceptedAt: stamp.text,
          threadId: posted.threadId,
          messageId: posted.messageId,
          ...(typeof posted.turnId === 'string' ? { turnId: posted.turnId } : {}),
        },
        null,
        2,
      )}\n`,
    ).catch(() => {});
    await log(result.key, 'accepted', 'posted');
    return 'done';
  }

  function post(result, retry = false) {
    const extra = origins.get(result.site) ?? [];
    return request('/api/desktop/signin', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        url: result.url,
        job: result.job,
        ...(result.ref ? { ref: result.ref } : {}),
        ...(result.hold ? { hold: result.hold } : {}),
        ...(extra.length ? { loginOrigins: extra } : {}),
        ...(retry ? { retry: true } : {}),
      }),
      signal: AbortSignal.timeout(30_000),
    });
  }

  async function resumeSites() {
    const names = await readdir(options.dataDir).catch(() => []);
    for (const name of names) {
      const site = resumeName.exec(name)?.[1];
      if (!site) continue;
      const path = join(options.dataDir, name);
      const info = await lstat(path).catch(() => undefined);
      if (info?.isFile() && !info.isSymbolicLink() && sites.has(site)) {
        gate.reset(site);
        await gate.save().catch(() => {});
        await log(site, 'resumed', 'site resumed from the data folder');
      }
      await rm(path, { force: true }).catch(() => {});
    }
  }

  async function checksFor(site) {
    const text = await readSmall(join(options.dataDir, checksFile), allowBytes);
    return parseSigninChecks(text).get(site) ?? { signedIn: [], loginHosts: [] };
  }

  async function judge(key, outcome, done) {
    const check = await checksFor(key);
    let look;
    if (done && outcomeConfirmed(outcome, key)) {
      const url = sites.get(key);
      look = url
        ? await Promise.resolve()
            .then(() =>
              pageCheck?.({
                site: key,
                hosts: siteHosts(url, origins.get(key) ?? []),
                markers: check.signedIn,
                prefer: replyHost(outcome.reply),
              }),
            )
            .catch(() => undefined)
        : undefined;
    }
    return { ...signinVerdict(done ? outcome : undefined, look, check), look };
  }

  async function finish(key, entry, verdict, outcome, typed) {
    gate.settle(key, verdict.confirmed, typed && !noStrikeCauses.has(verdict.cause));
    await gate.save().catch(() => {});
    await saveReply(key, entry.turnId, outcome, verdict);
    await keep(key, entry, verdict.confirmed ? 'confirmed' : 'unconfirmed', verdict, outcome);
    await log(
      key,
      verdict.confirmed ? 'confirmed' : 'unconfirmed',
      `${key.includes('.') ? 'job' : 'sign-in'} outcome read${
        !key.includes('.') && verdict.cause ? ` (${verdict.cause})` : ''
      }${entry.retried ? ' after one more try' : ''}${entry.filled ? ' after the browser-filled sign-in' : ''}`,
    );
    verdictWritten = true;
  }

  async function retry(key, entry) {
    if (clock() < entry.retryAt) return true;
    const url = sites.get(key);
    const idle =
      url &&
      (await Promise.resolve()
        .then(() => isIdle('signin'))
        .catch(() => false));
    let response;
    if (idle)
      try {
        response = await post({ site: key, url, job: 'signin' }, true);
      } catch {
        response = undefined;
      }
    if (url && (!idle || response?.status === 409)) {
      if (clock() - entry.retryAt < deferralMs) return true;
      await finish(
        key,
        entry,
        { confirmed: false, cause: entry.cause, reason: entry.reason },
        undefined,
        false,
      );
      return false;
    }
    let posted;
    if (response?.ok) posted = await response.json().catch(() => undefined);
    if (typeof posted?.turnId !== 'string') {
      await finish(
        key,
        entry,
        { confirmed: false, cause: entry.cause, reason: entry.reason },
        undefined,
        false,
      );
      return false;
    }
    gate.track(key, posted.turnId, clock(), entry.ref);
    gate.state.pending[key].retried = true;
    await gate.save().catch(() => {});
    await log(key, 'accepted', 'posted one more try');
    return true;
  }

  async function settle() {
    if (!options.outcome) return false;
    let waiting = false;
    for (const [key, entry] of Object.entries(gate.state.pending)) {
      if (entry.retryAt) {
        if (await retry(key, entry)) waiting = true;
        continue;
      }
      if (entry.checkAt) {
        if (clock() < entry.checkAt) {
          waiting = true;
          continue;
        }
        const check = await checksFor(key);
        const url = sites.get(key);
        const look = url
          ? await Promise.resolve()
              .then(() =>
                pageCheck?.({
                  site: key,
                  hosts: siteHosts(url, origins.get(key) ?? []),
                  markers: check.signedIn,
                  prefer: entry.host,
                }),
              )
              .catch(() => undefined)
          : undefined;
        await finish(
          key,
          entry,
          { ...filledVerdict(look, check), look },
          { turn: 'succeeded', signin: 'browser_filled', reply: '' },
          true,
        );
        continue;
      }
      const { turnId, at, ref } = entry;
      const hold = key.endsWith('.hold');
      let outcome;
      try {
        outcome = await options.outcome(turnId);
      } catch {
        outcome = undefined;
      }
      const done = outcome && finished.has(outcome.turn) && !(hold && outcome.turn === 'waiting');
      if (!done && clock() - at < (hold ? holdWaitMs : outcomeWaitMs)) {
        waiting = true;
        continue;
      }
      const verdict = key.includes('.')
        ? {
            confirmed: Boolean(done) && outcomeConfirmed(outcome, key, ref),
            cause: null,
            reason: '',
          }
        : await judge(key, outcome, done);
      if (verdict.confirmed && key.endsWith('.autohold'))
        gate.placed(key.split('.')[0], heldBooking(outcome.reply));
      if (verdict.confirmed && key.endsWith('.release')) gate.placed(ref);
      if (
        !key.includes('.') &&
        !verdict.confirmed &&
        verdict.cause === 'vault_missing' &&
        pressFilled &&
        sites.has(key) &&
        (await checksFor(key)).browserFilled
      ) {
        const pressed = await Promise.resolve()
          .then(() =>
            pressFilled({
              site: key,
              hosts: siteHosts(sites.get(key), origins.get(key) ?? []),
              prefer: replyHost(outcome?.reply),
            }),
          )
          .catch(() => undefined);
        if (pressed?.pressed) {
          gate.retryLater(key, {
            at: entry.at,
            checkAt: clock() + filledWaitMs,
            filled: true,
            host: pressed.host,
            turnId,
            ...(entry.retried ? { retried: true } : {}),
          });
          await gate.save().catch(() => {});
          await saveReply(key, turnId, outcome, verdict);
          await keep(key, entry, 'pressing', verdict, outcome);
          await log(
            key,
            'pressing',
            'the browser had filled the sign-in form; pressed its button once',
          );
          waiting = true;
          continue;
        }
        verdict.reason = `${verdict.reason} (browser form: ${String(pressed?.reason ?? 'not pressed').slice(0, 60)})`;
      }
      if (
        !key.includes('.') &&
        !verdict.confirmed &&
        !entry.retried &&
        retryCauses.has(verdict.cause)
      ) {
        gate.retryLater(key, {
          at: entry.at,
          retryAt: clock() + retryMs,
          cause: verdict.cause,
          reason: verdict.reason,
          turnId,
          ...(ref ? { ref } : {}),
        });
        await gate.save().catch(() => {});
        await saveReply(key, turnId, outcome, verdict);
        await keep(key, entry, 'retrying', verdict, outcome);
        await log(
          key,
          'retrying',
          `sign-in outcome read (${verdict.cause}); one more try in a minute`,
        );
        waiting = true;
        continue;
      }
      await finish(
        key,
        entry,
        verdict,
        outcome,
        !(outcome?.turn === 'succeeded' && outcome.signin === 'none'),
      );
    }
    return waiting;
  }

  async function saveReply(key, turnId, outcome, verdict) {
    try {
      await ensure(repliesDirectory);
      await writeAtomic(
        join(repliesDirectory, `${key}.json`),
        `${JSON.stringify(
          {
            key,
            turnId,
            confirmed: verdict.confirmed,
            ...(key.includes('.') ? {} : { cause: verdict.cause }),
            turn: outcome?.turn ?? null,
            signin: outcome?.signin ?? null,
            readAt: pacificStamp(new Date(clock())).text,
            reply: typeof outcome?.reply === 'string' ? outcome.reply : '',
          },
          null,
          2,
        )}\n`,
      );
    } catch {}
  }

  async function keep(key, entry, verdict, judged, outcome) {
    const [site, job = 'signin'] = key.split('.');
    const look = judged.look;
    const line = {
      at: pacificIso(clock()),
      key,
      job,
      verdict,
      cause: judged.cause ?? null,
      reason: judged.reason ?? '',
      turn: outcome?.turn ?? null,
      signin: outcome?.signin ?? null,
      ...(entry.turnId ? { turnId: entry.turnId } : {}),
      ...(entry.retried ? { secondTry: true } : {}),
      ...(look
        ? {
            page: {
              host: look.host,
              title: look.title,
              passwords: look.passwords,
              signOut: look.signOut,
              markers: look.markers,
            },
          }
        : {}),
    };
    try {
      await ensure(repliesDirectory);
      const path = join(repliesDirectory, `${site}.log.jsonl`);
      const info = await lstat(path).catch(() => undefined);
      if (info?.isFile() && info.size > logBytes)
        await rename(path, join(repliesDirectory, `${site}.log.1.jsonl`)).catch(() => {});
      await appendLog(path, `${JSON.stringify(line)}\n`);
    } catch {}
  }

  let healthAt = 0;
  let verdictWritten = false;
  async function writeHealth() {
    if (!verdictWritten && clock() - healthAt < 60_000) return;
    verdictWritten = false;
    healthAt = clock();
    try {
      const logText = (await readSmall(logPath, 2 * logBytes)) ?? '';
      const causes = {};
      for (const site of sites.keys()) {
        try {
          const saved = JSON.parse(
            (await readSmall(join(repliesDirectory, `${site}.json`), 65_536)) ?? '',
          );
          if (saved?.confirmed === false)
            causes[site] = signinCauses.includes(saved.cause)
              ? saved.cause
              : replyCause(saved.reply);
        } catch {}
      }
      const report = signinHealth(logText, { now: clock(), sites: [...sites.keys()], causes });
      await writeAtomic(join(records, healthFile), `${JSON.stringify(report, null, 2)}\n`);
    } catch {}
  }

  let beatAt = 0;
  async function beat(fields) {
    if (clock() - beatAt < 60_000 && !fields.reason) return;
    beatAt = clock();
    await writeSigninStatus(options.dataDir, fields, clock);
  }

  async function pass() {
    if (stopped) return 0;
    await beat({ state: 'on', reason: null, lastPass: pacificStamp(new Date(clock())).text });
    const info = await lstat(inbox).catch(() => undefined);
    if (!info?.isDirectory() || info.isSymbolicLink()) {
      watcher?.close();
      watcher = undefined;
      return intervals.missing;
    }
    if (!loaded) {
      loaded = true;
      await gate.load();
    }
    if (!watcher)
      try {
        watcher = options.watch
          ? options.watch(inbox, () => kick())
          : watch(inbox, { persistent: false }, () => kick());
        watcher.on?.('error', () => {
          watcher?.close();
          watcher = undefined;
        });
      } catch {
        watcher = undefined;
      }
    await ensure(records).catch(() => {});
    await gate.settled().catch(() => {});
    await resumeSites();
    const names = await readdir(inbox).catch(() => []);
    let deferred = false;
    let attempts = 0;
    for (const name of names.sort()) {
      if (stopped) return 0;
      if (!requestName.test(name)) continue;
      if (attempts >= passLimit) {
        deferred = true;
        break;
      }
      const outcome = await handle(name);
      if (outcome !== 'skipped') attempts++;
      if (outcome === 'deferred') deferred = true;
    }
    const waiting = await settle();
    await writeHealth();
    return deferred || waiting ? intervals.pending : intervals.idle;
  }

  function schedule(delay) {
    if (stopped || !delay) return;
    clearTimeout(timer);
    timer = setTimeout(() => void scan(), delay);
    timer.unref?.();
  }

  function scan() {
    running = running
      .then(pass)
      .catch(() => intervals.idle)
      .then(schedule);
    return running;
  }

  function kick() {
    if (stopped) return;
    clearTimeout(debounce);
    debounce = setTimeout(() => void scan(), debounceMs);
    debounce.unref?.();
  }

  void scan();
  return {
    scan,
    stop() {
      stopped = true;
      clearTimeout(timer);
      clearTimeout(debounce);
      watcher?.close();
      watcher = undefined;
    },
  };
}
