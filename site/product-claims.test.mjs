import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const homepage = await readFile(new URL('./src/pages/index.astro', import.meta.url), 'utf8');

test('homepage describes live policy reload behavior accurately', () => {
  assert.match(homepage, /watches policy and schema files/i);
  assert.match(homepage, /atomically reloads valid snapshots/i);
  assert.match(homepage, /last known-good snapshot/i);
  assert.doesNotMatch(homepage, /Restart the server after policy changes/i);
});
