/**
 * Guards the build/start contract.
 *
 * REGRESSION: `start` pointed at dist/server.js while tsc, with rootDir ".",
 * emitted dist/src/server.js. Everything typechecked and every test passed —
 * the failure only appeared when someone actually ran the built artifact.
 * These assertions fail in CI instead.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const readJson = (f: string) =>
  // tsconfig files are JSONC; strip line comments before parsing.
  JSON.parse(readFileSync(path.join(root, f), 'utf8').replace(/^\s*\/\/.*$/gm, ''));

describe('build configuration', () => {
  const pkg = readJson('package.json') as { scripts: Record<string, string> };
  const buildCfg = readJson('tsconfig.build.json') as {
    compilerOptions?: { outDir?: string; rootDir?: string };
    include: string[];
    exclude: string[];
  };
  const baseCfg = readJson('tsconfig.json') as {
    compilerOptions: { outDir: string; rootDir: string };
  };

  const outDir = buildCfg.compilerOptions?.outDir ?? baseCfg.compilerOptions.outDir;
  const rootDir = buildCfg.compilerOptions?.rootDir ?? baseCfg.compilerOptions.rootDir;

  test('start script points at the path tsc actually emits', () => {
    // tsc mirrors the tree under rootDir into outDir, so rootDir "." means
    // src/server.ts -> dist/src/server.js.
    const emitted = path.posix.join(
      outDir,
      path.posix.relative(rootDir === '.' ? '.' : rootDir, 'src/server.js'),
    );
    assert.equal(
      pkg.scripts.start,
      `node ${emitted}`,
      `start script must match the emit path implied by rootDir "${rootDir}"`,
    );
  });

  test('build uses the production tsconfig, not the typecheck one', () => {
    assert.match(pkg.scripts.build!, /tsconfig\.build\.json/);
  });

  test('tests are excluded from the shipped artifact', () => {
    assert.ok(
      buildCfg.exclude.some((p) => p.startsWith('test')),
      'tsconfig.build.json must exclude test/',
    );
    assert.ok(!buildCfg.include.some((p) => p.startsWith('test')));
  });
});
