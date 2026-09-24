import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const homepage = await readFile(new URL('./src/pages/index.astro', import.meta.url), 'utf8');
const concepts = await readFile(new URL('../docs/concepts.md', import.meta.url), 'utf8');
const security = await readFile(new URL('../docs/security.md', import.meta.url), 'utf8');
const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8');
const footer = await readFile(new URL('./src/components/footer.astro', import.meta.url), 'utf8');
const releaseWorkflow = await readFile(new URL('../.github/workflows/release.yml', import.meta.url), 'utf8');

test('homepage describes live policy reload behavior accurately', () => {
  assert.match(homepage, /watches policy and schema files/i);
  assert.match(homepage, /atomically reloads valid snapshots/i);
  assert.match(homepage, /last known-good snapshot/i);
  assert.doesNotMatch(homepage, /Restart the server after policy changes/i);
});

test('canonical concepts guide documents the implemented fallible cache configuration API', () => {
  assert.match(concepts, /DecisionCache::try_config_from_env/);
  assert.match(concepts, /AGENTGUARD_CACHE_CAPACITY/);
  assert.match(concepts, /Invalid\s+values fail startup/);
  assert.match(concepts, /Authorizer::try_with_cache/);
  assert.doesNotMatch(concepts, /CacheConfig::from_env/);
});

test('security guide defines the operator-local audit verification boundary', () => {
  assert.match(security, /verifies the native HMAC chain with its chain secret/i);
  assert.match(security, /anyone given the secret can create valid/i);
  assert.match(security, /exported records do not carry the native\s+chain's cryptographic metadata/i);
  assert.match(security, /no public-key-signed\s+export or handoff format/i);
});

test('public install and release claims match the GHCR-only binary release workflow', () => {
  assert.match(readme, /cargo install --path crates\/agentguard-cli/);
  assert.match(readme, /Rust workspace\s+crates remain source-distributed and are not published to crates\.io/i);
  assert.match(readme, /versioned GHCR images/i);
  assert.doesNotMatch(readme, /crates\.io\/crates\/agentguard-core|img\.shields\.io\/crates\/v\/agentguard-core/i);
  assert.doesNotMatch(readme, /CI publishes Rust crates|publishes .*TypeScript package/i);
  assert.match(footer, /\$\{site\.repo\}\/releases/);
  assert.doesNotMatch(footer, /crates\.io\/crates\/agentguard-core/i);
  assert.doesNotMatch(releaseWorkflow, /cargo publish|npm publish/);
  assert.match(releaseWorkflow, /packages: write/);
  assert.match(releaseWorkflow, /ghcr\.io/);
});
