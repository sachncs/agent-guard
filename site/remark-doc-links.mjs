import { existsSync, statSync } from 'node:fs';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const siteRoot = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(siteRoot, '..');
const docsRoot = resolve(repositoryRoot, 'docs');
const publicRoot = resolve(siteRoot, 'public');
const docsRoutes = new Map([
  ['README.md', ''],
  ['architecture.md', 'deploy'],
  ['backups.md', 'backups'],
  ['branding.md', 'branding'],
  ['compatibility.md', 'compatibility'],
  ['console.md', 'console'],
  ['getting-started.md', 'getting-started'],
  ['identity.md', 'identity'],
  ['incident-response.md', 'incident-response'],
  ['kubernetes.md', 'kubernetes'],
  ['local-development.md', 'local-development'],
  ['operations/runbook.md', 'operations'],
  ['oss-governance.md', 'oss-governance'],
  ['policy-authoring.md', 'policy-authoring'],
  ['production.md', 'production'],
  ['reference.md', 'reference'],
  ['troubleshooting.md', 'troubleshooting'],
  ['upgrades.md', 'upgrades'],
]);

/** Keep links in imported repository guides useful on the published docs site. */
export function remarkDocLinks() {
  return (tree, file) => {
    const visit = (node) => {
      if (
        node.type === 'link' &&
        typeof node.url === 'string' &&
        node.url.length > 0 &&
        !node.url.startsWith('#') &&
        !node.url.startsWith('/') &&
        !/^[a-z][a-z\d+.-]*:/i.test(node.url)
      ) {
        const [pathname, ...fragmentParts] = node.url.split('#');
        const target = resolve(dirname(file.path), pathname);
        const fragment = fragmentParts.length ? `#${fragmentParts.join('#')}` : '';
        const relativePath = relative(repositoryRoot, target).split(sep).join('/');
        const docsPath = relative(docsRoot, target).split(sep).join('/');
        const route = docsRoutes.get(docsPath);
        const publicPath = relative(publicRoot, target).split(sep).join('/');

        if (route !== undefined && existsSync(target)) {
          node.url = `/agent-guard/docs/${route ? `${route}/` : ''}${fragment}`;
        } else if (!publicPath.startsWith('..') && !publicPath.startsWith('/') && existsSync(target)) {
          node.url = `/agent-guard/${publicPath}${fragment}`;
        } else if (!relativePath.startsWith('..') && !relativePath.startsWith('/')) {
          const kind = statSync(target, { throwIfNoEntry: false })?.isDirectory() ? 'tree' : 'blob';
          node.url = `https://github.com/sachncs/agent-guard/${kind}/master/${relativePath}${fragment}`;
        }
      }

      for (const child of node.children ?? []) visit(child);
    };

    visit(tree);
  };
}
