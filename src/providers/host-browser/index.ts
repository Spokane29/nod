import { accessSync, constants } from 'node:fs';
import { createRequire } from 'node:module';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import type { Computer } from '../../ports/computer.ts';
import { createAgentBrowserComputer } from '../agent-browser/index.ts';

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

export function createHostBrowserComputer(options: {
  dataRoot: string;
  browserExecutable: string;
  driver?: string;
  maxLiveSessions?: number;
}): Computer {
  const browserExecutable = options.browserExecutable.trim();
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
    dataRoot: resolve(options.dataRoot, 'host-browser'),
    executable: options.driver ?? hostBrowserDriver(),
    browserExecutable,
    maxLiveSessions: options.maxLiveSessions,
  });
}
