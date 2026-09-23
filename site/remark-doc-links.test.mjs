import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import test from 'node:test';
import { remarkDocLinks } from './remark-doc-links.mjs';

test('repository guide links point to canonical site routes or repository sources', () => {
  const tree = {
    type: 'root',
    children: [
      { type: 'link', url: 'console.md#configuration', children: [] },
      { type: 'link', url: '../README.md#configuration', children: [] },
      { type: 'link', url: '../site/public/brand/concept-boundary.svg', children: [] },
      { type: 'link', url: 'adr/', children: [] },
      { type: 'link', url: '#safe-authoring', children: [] },
      { type: 'link', url: 'https://docs.cedarpolicy.com/', children: [] },
    ],
  };

  remarkDocLinks()(tree, {
    path: resolve('..', 'docs', 'policy-authoring.md'),
  });

  assert.deepEqual(
    tree.children.map(({ url }) => url),
    [
      '/agent-guard/docs/console/#configuration',
      'https://github.com/sachncs/agent-guard/blob/master/README.md#configuration',
      '/agent-guard/brand/concept-boundary.svg',
      'https://github.com/sachncs/agent-guard/tree/master/docs/adr',
      '#safe-authoring',
      'https://docs.cedarpolicy.com/',
    ],
  );
});
