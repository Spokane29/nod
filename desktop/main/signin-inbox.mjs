import { randomUUID } from 'node:crypto';
import { constants, watch } from 'node:fs';
import { appendFile, lstat, mkdir, open, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';

export const requestBytes = 2048;
export const siteIntervalMs = 10 * 60_000;
export const hourlyLimit = 12;
export const deferralMs = 15 * 60_000;
const allowBytes = 65_536;
const logBytes = 1_000_000;
const rejectedLimit = 400;
const scanLimit = 50;
const siteKey = /^[a-z0-9-]{2,32}$/;
const requestName = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.json$/;
const urlPath = /^\/[A-Za-z0-9._~/-]{0,119}$/;

export function signinInboxPath(environment, fileText, home = homedir()) {
  const value = (environment ?? '').trim() || (fileText ?? '').trim();
  if (!value || value.includes('\0')) return '';
  const expanded =
    value === '~' ? home : value.startsWith('~/') ? join(home, value.slice(2)) : value;
  return isAbsolute(expanded) ? resolve(expanded) : '';
}

export function allowListPath(inbox) {
  return join(dirname(inbox), 'nod-signin-allow.json');
}

function listedOrigin(value) {
  if (typeof value !== 'string') return undefined;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' &&
      !url.username &&
      !url.password &&
      url.origin === value.replace(/\/$/, '')
      ? url.origin
      : undefined;
  } catch {
    return undefined;
  }
}

function startUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password
      ? `${url.origin}${url.pathname}${url.search}`
      : undefined;
  } catch {
    return undefined;
  }
}

export function parseAllowList(text) {
  const sites = new Map();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) return undefined;
  if (!data.sites || typeof data.sites !== 'object' || Array.isArray(data.sites)) return undefined;
  for (const [key, entry] of Object.entries(data.sites)) {
    if (!siteKey.test(key) || !entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const origins = new Set(
      (Array.isArray(entry.origins) ? entry.origins : []).map(listedOrigin).filter(Boolean),
    );
    if (!origins.size) continue;
    const pinned = new Set(
      (Array.isArray(entry.startUrls) ? entry.startUrls : [])
        .map(startUrl)
        .filter((value) => value && origins.has(new URL(value).origin)),
    );
    sites.set(key, { origins, pinned, pinnedOnly: entry.pinnedOnly === true });
  }
  return sites;
}

export function validateRequest(text, allow) {
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
  const entry = allow?.get(data.site);
  if (!entry) return { ok: false, site: data.site, reason: 'site not in allow-list' };
  if (typeof data.url !== 'string' || data.url.length > 2048)
    return { ok: false, site: data.site, reason: 'bad url' };
  let url;
  try {
    url = new URL(data.url);
  } catch {
    return { ok: false, site: data.site, reason: 'bad url' };
  }
  if (url.protocol !== 'https:') return { ok: false, site: data.site, reason: 'url is not https' };
  if (url.username || url.password)
    return { ok: false, site: data.site, reason: 'url has credentials' };
  if (!entry.origins.has(url.origin))
    return { ok: false, site: data.site, reason: 'origin not listed for site' };
  const exact = `${url.origin}${url.pathname}${url.search}`;
  if (entry.pinned.has(exact)) return { ok: true, site: data.site, url: exact };
  if (entry.pinnedOnly) return { ok: false, site: data.site, reason: 'url not pinned for site' };
  if (!urlPath.test(url.pathname))
    return { ok: false, site: data.site, reason: 'url path not accepted' };
  return { ok: true, site: data.site, url: `${url.origin}${url.pathname}` };
}

export function signinMessage(site, url) {
  return `Open ${url} in the browser. If the page shows a sign-in form, sign in with the saved Vault login for this site (${site}). Leave the tab open. Do not do anything else on the site: no search, no booking, no hold, no payment, no settings, no agreement. If the site asks for a code, a CAPTCHA or new terms, stop and report it.`;
}

export function createLimiter(options = {}) {
  const siteMs = options.siteMs ?? siteIntervalMs;
  const hourMax = options.hourMax ?? hourlyLimit;
  const lastBySite = new Map();
  let accepted = [];
  return {
    check(site, now) {
      accepted = accepted.filter((time) => now - time < 3_600_000);
      const last = lastBySite.get(site);
      if (last !== undefined && now - last < siteMs)
        return 'rate limit: one request per site every 10 minutes';
      if (accepted.length >= hourMax) return 'rate limit: 12 requests per hour';
    },
    record(site, now) {
      lastBySite.set(site, now);
      accepted.push(now);
    },
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

async function realDirectory(path) {
  const info = await lstat(path).catch(() => undefined);
  return Boolean(info?.isDirectory() && !info.isSymbolicLink());
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

export function startSigninInbox(options) {
  const { inbox, request, isIdle } = options;
  const allowPath = options.allowPath ?? allowListPath(inbox);
  const clock = options.now ?? Date.now;
  const limiter = createLimiter(options.limits);
  const intervals = { missing: 60_000, idle: 60_000, pending: 15_000, ...options.intervals };
  const debounceMs = options.debounceMs ?? 500;
  const logPath = join(inbox, 'log.txt');
  const acceptedDirectory = join(inbox, 'accepted');
  const rejectedDirectory = join(inbox, 'rejected');
  const noted = new Set();
  let watcher;
  let timer;
  let debounce;
  let stopped = false;
  let running = Promise.resolve();
  let allowState = '';

  async function log(site, decision, reason) {
    const stamp = pacificStamp(new Date(clock()));
    const info = await lstat(logPath).catch(() => undefined);
    if (info && (!info.isFile() || info.size > logBytes))
      await rm(logPath, { force: true }).catch(() => {});
    await appendFile(logPath, `${stamp.text} ${site || '-'} ${decision} ${reason}\n`, {
      mode: 0o600,
      flag: 'a',
    }).catch(() => {});
  }

  async function ensure(directory) {
    await mkdir(directory, { mode: 0o700 }).catch((error) => {
      if (error?.code !== 'EEXIST') throw error;
    });
    if (!(await realDirectory(directory))) throw new Error('not a directory');
  }

  async function reject(name, site, reason) {
    const stem = name.slice(0, -'.json'.length);
    const stamp = pacificStamp(new Date(clock())).file;
    try {
      await ensure(rejectedDirectory);
      if ((await readdir(rejectedDirectory)).length >= rejectedLimit) throw new Error('full');
      const target = join(rejectedDirectory, `${stem}-${stamp}`);
      await rename(join(inbox, name), `${target}.json`);
      await writeFile(`${target}.reason.txt`, `${reason}\n`, { mode: 0o600 });
    } catch {
      await rm(join(inbox, name), { force: true }).catch(() => {});
    }
    await log(site, 'rejected', reason);
  }

  async function handle(name, allow) {
    const path = join(inbox, name);
    const info = await lstat(path).catch(() => undefined);
    if (!info) return 'done';
    const identity = `${name}:${info.ino}:${info.mtimeMs}`;
    if (!info.isFile() || info.isSymbolicLink() || info.size > requestBytes) {
      if (!noted.has(identity)) {
        noted.add(identity);
        if (noted.size > 500) noted.clear();
        await log(
          '',
          'ignored',
          info.size > requestBytes ? 'file too large' : 'not a regular file',
        );
      }
      return 'done';
    }
    const text = await readSmall(path, requestBytes);
    if (text === undefined) return 'done';
    const result = validateRequest(text, allow);
    if (!result.ok) {
      await reject(
        name,
        result.site && siteKey.test(result.site) ? result.site : '',
        result.reason,
      );
      return 'done';
    }
    const now = clock();
    const limited = limiter.check(result.site, now);
    if (limited) {
      await reject(name, result.site, limited);
      return 'done';
    }
    const idle = await Promise.resolve()
      .then(isIdle)
      .catch(() => false);
    if (!idle) {
      if (now - info.mtimeMs > deferralMs) {
        await reject(name, result.site, 'nod was not available for 15 minutes');
        return 'done';
      }
      return 'deferred';
    }
    const stamp = pacificStamp(new Date(now));
    const claimed = join(acceptedDirectory, `${result.site}-${stamp.file}.json`);
    try {
      await ensure(acceptedDirectory);
      await rename(path, claimed);
    } catch {
      if (!noted.has(identity)) {
        noted.add(identity);
        await log(result.site, 'rejected', 'could not claim the request file');
      }
      return 'done';
    }
    limiter.record(result.site, now);
    let posted;
    let failure = '';
    try {
      const response = await request('/api/messages', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          text: signinMessage(result.site, result.url),
          clientMessageId: randomUUID(),
        }),
        signal: AbortSignal.timeout(30_000),
      });
      if (!response.ok) failure = `nod refused the message (status ${response.status})`;
      else {
        const body = await response.json();
        if (typeof body?.messageId === 'string' && typeof body?.threadId === 'string')
          posted = body;
        else failure = 'nod returned no message id';
      }
    } catch {
      failure = 'could not reach nod';
    }
    if (!posted) {
      try {
        await ensure(rejectedDirectory);
        const target = join(rejectedDirectory, `${result.site}-${stamp.file}`);
        await rename(claimed, `${target}.json`);
        await writeFile(`${target}.reason.txt`, `${failure}\n`, { mode: 0o600 });
      } catch {}
      await log(result.site, 'rejected', failure);
      return 'done';
    }
    await writeFile(
      claimed,
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
      { mode: 0o600 },
    ).catch(() => {});
    await log(result.site, 'accepted', 'posted');
    return 'done';
  }

  async function pass() {
    if (stopped) return 0;
    if (!(await realDirectory(inbox))) {
      watcher?.close();
      watcher = undefined;
      return intervals.missing;
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
    const text = await readSmall(allowPath, allowBytes);
    const allow = text === undefined ? undefined : parseAllowList(text);
    if (!allow) {
      if (allowState !== 'off') {
        allowState = 'off';
        await log('', 'ignored', 'allow-list missing or unreadable; inbox is off');
      }
      return intervals.idle;
    }
    allowState = 'on';
    const names = (await readdir(inbox).catch(() => []))
      .filter((name) => requestName.test(name))
      .sort();
    let deferred = false;
    for (const name of names.slice(0, scanLimit)) {
      if (stopped) return 0;
      if ((await handle(name, allow)) === 'deferred') deferred = true;
    }
    return deferred || names.length > scanLimit ? intervals.pending : intervals.idle;
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
