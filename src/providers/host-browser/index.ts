import { accessSync, constants } from 'node:fs';
import { createRequire } from 'node:module';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import type { Computer } from '../../ports/computer.ts';
import { loopbackHost } from '../../shared/loopback.ts';
import { createAgentBrowserComputer } from '../agent-browser/index.ts';
import { publicUrl } from '../agent-browser/network.ts';

export function hostBrowserDriver(
  platform: NodeJS.Platform = process.platform,
  architecture: NodeJS.Architecture = process.arch,
) {
  if (
    !['darwin', 'linux', 'win32'].includes(platform) ||
    !['arm64', 'x64'].includes(architecture) ||
    (platform === 'win32' && architecture !== 'x64')
  )
    throw new Error(`The host browser is unsupported on ${platform} ${architecture}.`);
  return join(
    dirname(createRequire(import.meta.url).resolve('agent-browser/package.json')),
    'bin',
    `agent-browser-${platform}-${architecture}${platform === 'win32' ? '.exe' : ''}`,
  );
}

export function hostBrowserName(browserExecutable: string) {
  return basename(browserExecutable.trim()).replace(/\.exe$/i, '');
}

export function hostBrowserAddress(value: string) {
  const trimmed = value.trim();
  const url = URL.canParse(trimmed) ? new URL(trimmed) : new URL(`http://127.0.0.1:${trimmed}`);
  if (
    !['http:', 'ws:'].includes(url.protocol) ||
    !loopbackHost(url.hostname) ||
    !/^\d{2,5}$/.test(url.port) ||
    url.username ||
    url.password
  )
    throw new Error(
      'NOD_BROWSER_CDP must be a debugging port or address on this computer, such as 9223 or http://127.0.0.1:9223.',
    );
  return url.port;
}

export function createHostBrowserComputer(options: {
  dataRoot: string;
  browserExecutable?: string;
  attach?: string;
  foreground?: boolean;
  driver?: string;
  maxLiveSessions?: number;
}): Computer {
  const dataRoot = resolve(options.dataRoot, 'host-browser');
  const executable = options.driver ?? hostBrowserDriver();
  if (options.attach) {
    const computer = createAgentBrowserComputer({
      dataRoot,
      executable,
      attach: hostBrowserAddress(options.attach),
      foreground: options.foreground,
      maxLiveSessions: options.maxLiveSessions,
    });
    return {
      ...computer,
      act: async (threadId, input, signal) => {
        if (input.action === 'open' && input.url) await publicUrl(input.url);
        return computer.act(threadId, input, signal);
      },
    };
  }
  const browserExecutable = options.browserExecutable?.trim() ?? '';
  if (!isAbsolute(browserExecutable))
    throw new Error('NOD_BROWSER_EXECUTABLE must be the full path to a Chromium-based browser.');
  try {
    accessSync(browserExecutable, constants.X_OK);
  } catch (error) {
    throw new Error(
      `NOD_BROWSER_EXECUTABLE cannot be run: ${browserExecutable} (${(error as NodeJS.ErrnoException).code ?? 'unknown error'}).`,
    );
  }
  return createAgentBrowserComputer({
    dataRoot,
    executable,
    browserExecutable,
    visible: true,
    maxLiveSessions: options.maxLiveSessions,
  });
}
