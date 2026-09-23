// @ts-check
import { defineConfig } from 'astro/config';
import react from '@astrojs/react';
import sitemap from '@astrojs/sitemap';
import tailwindcss from '@tailwindcss/vite';
import { remarkDocLinks } from './remark-doc-links.mjs';

export default defineConfig({
  site: 'https://sachncs.github.io',
  base: '/agent-guard',
  output: 'static',
  trailingSlash: 'always',
  integrations: [react(), sitemap()],
  markdown: {
    remarkPlugins: [remarkDocLinks],
  },
  vite: {
    plugins: [tailwindcss()],
    ssr: {
      noExternal: ['motion'],
    },
  },
  build: {
    inlineStylesheets: 'auto',
  },
  prefetch: {
    prefetchAll: false,
    defaultStrategy: 'hover',
  },
});
