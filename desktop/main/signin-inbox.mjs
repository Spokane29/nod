import { createHash, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { constants, watch } from 'node:fs';
import { link, lstat, mkdir, open, readdir, realpath, rename, rm, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { isAbsolute, join, resolve, sep } from 'node:path';

export const requestBytes = 2048;
export const siteIntervalMs = 10 * 60_000;
export const hourlyLimit = 12;
export const siteDailyLimit = 6;
export const totalDailyLimit = 24;
export const deferralMs = 15 * 60_000;
export const unconfirmedLimit = 2;
export const dialogTitle = 'Allow sign-in requests?';
export const allowFile = 'signin-allow.json';
export const approvedFile = 'signin-allow.approved';
export const stateFile = 'signin-state.json';
const allowBytes = 65_536;
const stateBytes = 65_536;
const logBytes = 1_000_000;
const rejectedLimit = 400;
const acceptedLimit = 400;
const passLimit = 200;
const outcomeWaitMs = 30 * 60_000;
const hour = 3_600_000;
const day = 24 * hour;
const siteKey = /^[a-z0-9]{2,20}$/;
const requestName = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.json$/;
const resetName = /^([a-z0-9]{2,20})\.reset$/;
const segment = /^[A-Za-z0-9._~-]{1,40}$/;
const label = /^[a-z0-9-]{1,30}$/;

export function signinInboxPath(environment, fileText, home = homedir()) {
  const value = (environment ?? '').trim() || (fileText ?? '').trim();
  if (!value || value.includes('\0')) return '';
  const expanded =
    value === '~' ? home : value.startsWith('~/') ? join(home, value.slice(2)) : value;
  return isAbsolute(expanded) ? resolve(expanded) : '';
}

const plainWords = (value) => (value.match(/-/g) ?? []).length <= 2;

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
  if (labels.length < 2 || !labels.every((part) => label.test(part) && plainWords(part)))
    return undefined;
  const parts = url.pathname.split('/').slice(1);
  if (parts.at(-1) === '') parts.pop();
  if (parts.length > 4 || !parts.every((part) => segment.test(part) && plainWords(part)))
    return undefined;
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
  const skipped = [];
  for (const [key, entry] of Object.entries(data.sites)) {
    const url =
      siteKey.test(key) && entry && typeof entry === 'object' ? signinUrl(entry.url) : undefined;
    if (url) sites.set(key, url);
    else skipped.push(key.slice(0, 20));
  }
  return { sites, skipped };
}

export function validateRequest(text, sites) {
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
  const url = sites.get(data.site);
  if (!url) return { ok: false, site: data.site, reason: 'site not in allow-list' };
  return { ok: true, site: data.site, url };
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
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW).catch(() => undefined);
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

export function allowListDialog(sites) {
  return {
    title: dialogTitle,
    detail: `Other programs on this computer will be able to ask Nod to open these pages and sign in with the saved Vault login, with no one in the chat:\n\n${[
      ...sites,
    ]
      .map(([key, url]) => `${key}   ${url}`)
      .join('\n')}\n\nNothing else can be requested this way.`,
    buttons: ['Allow', 'Keep off'],
    defaultId: 1,
    cancelId: 1,
  };
}

export async function loadAllowList(options) {
  const { dataDir, showDialog } = options;
  const text = await readSmall(join(dataDir, allowFile), allowBytes);
  if (text === undefined) return { reason: 'the allow-list is missing or unreadable' };
  const parsed = parseAllowList(text);
  if (!parsed) return { reason: 'the allow-list is not valid' };
  if (!parsed.sites.size) return { reason: 'the allow-list has no valid sites' };
  const hash = createHash('sha256').update(text).digest('hex');
  const approved = ((await readSmall(join(dataDir, approvedFile), 200)) ?? '').trim();
  if (approved === hash) return { sites: parsed.sites, skipped: parsed.skipped };
  const answer = await showDialog(allowListDialog(parsed.sites));
  if (answer !== 0) return { reason: 'the allow-list was not approved' };
  await writeAtomic(join(dataDir, approvedFile), `${hash}\n`);
  return { sites: parsed.sites, skipped: parsed.skipped };
}

export async function prepareSigninInbox(options) {
  const { environment, setting, dataDir, home, showDialog, diagnostic = () => {} } = options;
  const inbox = signinInboxPath(environment, setting, home);
  if (!inbox) return undefined;
  const problem = await inboxLocationProblem(inbox, home, options.fs);
  if (problem) {
    diagnostic(`Sign-in inbox is off: ${problem}.`);
    return undefined;
  }
  const loaded = await loadAllowList({ dataDir, showDialog });
  if (!loaded.sites) {
    diagnostic(`Sign-in inbox is off: ${loaded.reason}.`);
    return undefined;
  }
  if (loaded.skipped.length) diagnostic('Sign-in inbox ignored invalid allow-list entries.');
  return { inbox, sites: loaded.sites, dataDir };
}

export function createGate(options) {
  const { file } = options;
  const clock = options.now ?? Date.now;
  const siteMs = options.siteMs ?? siteIntervalMs;
  let state = { accepted: [], strikes: {}, blocked: {}, pending: {} };
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
    check(site, now) {
      if (now < holdUntil) return { state: 'wait' };
      if (state.blocked[site])
        return {
          state: 'reject',
          reason: `site paused after ${unconfirmedLimit} sign-ins that were not confirmed; drop ${site}.reset to resume`,
        };
      const recent = state.accepted.filter(([, at]) => now - at < day);
      const last = recent.filter(([name]) => name === site).map(([, at]) => at);
      if (last.some((at) => now - at < siteMs))
        return { state: 'reject', reason: 'rate limit: one request per site every 10 minutes' };
      if (recent.filter(([, at]) => now - at < hour).length >= hourlyLimit)
        return { state: 'reject', reason: 'rate limit: 12 requests per hour' };
      if (last.length >= siteDailyLimit)
        return { state: 'reject', reason: 'rate limit: 6 requests per site per day' };
      if (recent.length >= totalDailyLimit)
        return { state: 'reject', reason: 'rate limit: 24 requests per day' };
      return { state: 'ok' };
    },
    record(site, now) {
      state.accepted.push([site, now]);
    },
    track(site, turnId, now) {
      state.pending[site] = { turnId, at: now };
    },
    settle(site, confirmed) {
      delete state.pending[site];
      if (confirmed) {
        delete state.strikes[site];
        return;
      }
      state.strikes[site] = (state.strikes[site] ?? 0) + 1;
      if (state.strikes[site] >= unconfirmedLimit) state.blocked[site] = true;
    },
    reset(site) {
      delete state.strikes[site];
      delete state.blocked[site];
    },
  };
}

export function outcomeConfirmed(outcome) {
  return (
    outcome?.turn === 'succeeded' && (outcome.signin === 'submitted' || outcome.signin === 'none')
  );
}

const finished = new Set(['succeeded', 'failed', 'cancelled', 'waiting']);

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
  const logPath = join(inbox, 'log.txt');
  const acceptedLogPath = join(inbox, 'accepted-log.txt');
  const acceptedDirectory = join(inbox, 'accepted');
  const rejectedDirectory = join(inbox, 'rejected');
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
      constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW,
      0o600,
    ).catch(() => undefined);
    if (!handle) return;
    try {
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
      await rename(logPath, join(inbox, 'log.1.txt')).catch(() => {});
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
      await rm(join(directory, name), { force: true, recursive: true }).catch(() => {});
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
      const removed = await rm(join(inbox, name), { force: true, recursive: true }).then(
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
      await reject(name, '', 'not a regular file', identity);
      return 'done';
    }
    if (info.size > requestBytes) {
      await reject(name, '', 'file too large', identity);
      return 'done';
    }
    const handleFile = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW).catch(
      () => undefined,
    );
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
    const result = validateRequest(text, sites);
    if (!result.ok) {
      await reject(
        name,
        result.site && siteKey.test(result.site) ? result.site : '',
        result.reason,
        identity,
      );
      return 'done';
    }
    const decision = gate.check(result.site, now);
    if (decision.state === 'reject') {
      await reject(name, result.site, decision.reason, identity);
      return 'done';
    }
    const waiting = async (reason) => {
      if (now - seen > deferralMs) {
        await reject(name, result.site, reason, identity);
        return 'done';
      }
      return 'deferred';
    };
    if (decision.state === 'wait') return waiting('limits were unavailable for 15 minutes');
    const idle = await Promise.resolve()
      .then(isIdle)
      .catch(() => false);
    if (!idle) return waiting('nod was busy or waiting for you for 15 minutes');
    const stamp = pacificStamp(new Date(now));
    const base = `${result.site}-${stamp.file}`;
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
      .then(isIdle)
      .catch(() => false);
    let posted;
    let failure = '';
    let busy = !ready;
    if (ready)
      try {
        const response = await request('/api/desktop/signin', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ url: result.url }),
          signal: AbortSignal.timeout(30_000),
        });
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
      if (!(await restore(claimed, path)))
        await log(result.site, 'rejected', 'superseded while waiting');
      return 'deferred';
    }
    gate.record(result.site, now);
    if (!posted) {
      try {
        await ensure(rejectedDirectory);
        const target = join(rejectedDirectory, `${base}`);
        await rename(claimed, `${target}.json`);
        await writeNew(`${target}.reason.txt`, `${failure}\n`);
      } catch {}
      await gate.save().catch(() => {});
      await log(result.site, 'rejected', failure);
      return 'done';
    }
    if (typeof posted.turnId === 'string') gate.track(result.site, posted.turnId, now);
    await gate.save().catch(() => {});
    await writeNew(
      join(acceptedDirectory, `${base}.result.json`),
      `${JSON.stringify(
        {
          site: result.site,
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
    await log(result.site, 'accepted', 'posted');
    return 'done';
  }

  async function handleReset(name, site) {
    const path = join(inbox, name);
    const info = await lstat(path).catch(() => undefined);
    if (!info) return;
    const known = sites.has(site) && info.isFile() && !info.isSymbolicLink();
    if (known && !(await quarantined(path))) {
      gate.reset(site);
      await gate.save().catch(() => {});
      await log(site, 'reset', 'site resumed by the owner');
    } else await log('', 'ignored', 'reset file not accepted');
    await rm(path, { force: true }).catch(() => {});
  }

  async function settle() {
    if (!options.outcome) return false;
    let waiting = false;
    for (const [site, { turnId, at }] of Object.entries(gate.state.pending)) {
      let outcome;
      try {
        outcome = await options.outcome(turnId);
      } catch {
        outcome = undefined;
      }
      const done = outcome && finished.has(outcome.turn);
      if (!done && clock() - at < outcomeWaitMs) {
        waiting = true;
        continue;
      }
      const confirmed = Boolean(done) && outcomeConfirmed(outcome);
      gate.settle(site, confirmed);
      await gate.save().catch(() => {});
      await log(site, confirmed ? 'confirmed' : 'unconfirmed', 'sign-in outcome read');
    }
    return waiting;
  }

  async function pass() {
    if (stopped) return 0;
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
    await gate.settled().catch(() => {});
    const names = await readdir(inbox).catch(() => []);
    let deferred = false;
    let attempts = 0;
    for (const name of names.sort()) {
      if (stopped) return 0;
      const reset = resetName.exec(name);
      if (reset) {
        await handleReset(name, reset[1]);
        continue;
      }
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
