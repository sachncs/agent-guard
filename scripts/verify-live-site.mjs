#!/usr/bin/env node

import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";

const DEFAULT_ATTEMPTS = 20;
const DEFAULT_DELAY_MS = 3_000;

export function extractLocations(xml) {
  return [...xml.matchAll(/<loc>([\s\S]*?)<\/loc>/gi)]
    .map((match) => match[1].replaceAll("&amp;", "&").trim())
    .filter(Boolean);
}

export function isWithinSite(url, siteUrl) {
  const base = new URL(siteUrl);
  const candidate = new URL(url);
  const basePath = base.pathname.endsWith("/") ? base.pathname : `${base.pathname}/`;
  const allowedPath = candidate.pathname === base.pathname.replace(/\/$/, "") ||
    candidate.pathname.startsWith(basePath);
  return candidate.origin === base.origin && allowedPath;
}

async function fetchWithRetry(url, {
  fetchImpl,
  attempts = DEFAULT_ATTEMPTS,
  delayMs = DEFAULT_DELAY_MS,
}) {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      const response = await fetchImpl(url, {
        headers: { accept: "text/html,application/xml,image/svg+xml,image/png" },
        signal: AbortSignal.timeout(10_000),
      });
      if (response.ok) return response;
      lastError = new Error(`${url} returned HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    if (attempt < attempts) await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
  throw lastError ?? new Error(`${url} did not become available`);
}

async function readText(response, url, expectedType) {
  const contentType = response.headers.get("content-type") ?? "";
  assert.match(contentType, expectedType, `${url} has the expected content type`);
  return response.text();
}

async function verifySite(siteUrl, fetchImpl = fetch) {
  const base = new URL(siteUrl);
  assert.equal(base.protocol, "https:", "published site URL must use HTTPS");
  if (!base.pathname.endsWith("/")) base.pathname += "/";
  const basePath = base.pathname.endsWith("/") ? base.pathname : `${base.pathname}/`;
  const indexUrl = new URL("sitemap-index.xml", base).href;
  const indexResponse = await fetchWithRetry(indexUrl, { fetchImpl });
  const indexXml = await readText(indexResponse, indexUrl, /application\/xml|text\/xml/i);
  const sitemapUrls = extractLocations(indexXml);
  assert.ok(sitemapUrls.length > 0, "sitemap index must contain at least one sitemap");
  for (const sitemapUrl of sitemapUrls) {
    assert.ok(isWithinSite(sitemapUrl, siteUrl), `sitemap URL is outside the site: ${sitemapUrl}`);
  }

  const pages = [];
  for (const sitemapUrl of sitemapUrls) {
    const response = await fetchWithRetry(sitemapUrl, { fetchImpl });
    const xml = await readText(response, sitemapUrl, /application\/xml|text\/xml/i);
    pages.push(...extractLocations(xml));
  }
  const uniquePages = [...new Set(pages)];
  assert.ok(uniquePages.length >= 20, `expected at least 20 published routes, got ${uniquePages.length}`);
  assert.ok(uniquePages.includes(new URL(basePath, base).href), "sitemap must include the home page");

  let verifiedPages = 0;
  for (let offset = 0; offset < uniquePages.length; offset += 5) {
    const batch = uniquePages.slice(offset, offset + 5);
    await Promise.all(batch.map(async (pageUrl) => {
      assert.ok(isWithinSite(pageUrl, siteUrl), `page URL is outside the site: ${pageUrl}`);
      const response = await fetchWithRetry(pageUrl, { fetchImpl });
      const html = await readText(response, pageUrl, /text\/html/i);
      assert.match(html, /<title[^>]*>[\s\S]*AgentGuard[\s\S]*<\/title>/i, `${pageUrl} has AgentGuard metadata`);
      verifiedPages++;
    }));
  }

  const assets = [
    { path: "agentguard-mark.svg", type: /image\/svg\+xml/i, content: /<svg\b/i },
    { path: "favicon.svg", type: /image\/svg\+xml/i, content: /<svg\b/i },
  ];
  for (const asset of assets) {
    const assetUrl = new URL(asset.path, base).href;
    const response = await fetchWithRetry(assetUrl, { fetchImpl });
    const body = await readText(response, assetUrl, asset.type);
    assert.match(body, asset.content, `${assetUrl} contains valid SVG markup`);
  }

  const socialUrl = new URL("og-image.png", base).href;
  const socialResponse = await fetchWithRetry(socialUrl, { fetchImpl });
  const socialBytes = new Uint8Array(await socialResponse.arrayBuffer());
  assert.match(socialResponse.headers.get("content-type") ?? "", /image\/png/i);
  assert.deepEqual([...socialBytes.slice(0, 8)], [137, 80, 78, 71, 13, 10, 26, 10], "social artwork is a PNG");
  assert.equal(new DataView(socialBytes.buffer, socialBytes.byteOffset).getUint32(16), 1200, "social artwork is 1200px wide");
  assert.equal(new DataView(socialBytes.buffer, socialBytes.byteOffset).getUint32(20), 630, "social artwork is 630px high");

  const homeUrl = new URL(basePath, base).href;
  const home = await (await fetchWithRetry(homeUrl, { fetchImpl })).text();
  assert.match(home, /property="og:image"/i, "home page advertises its social artwork");
  console.log(`live site smoke passed (${verifiedPages} sitemap routes, logo, favicon, and 1200×630 social artwork)`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const siteUrl = process.env.AGENTGUARD_SITE_URL;
  if (!siteUrl) {
    console.error("AGENTGUARD_SITE_URL is required");
    process.exitCode = 2;
  } else {
    verifySite(siteUrl).catch((error) => {
      console.error(`live site smoke failed: ${error instanceof Error ? error.message : String(error)}`);
      process.exitCode = 1;
    });
  }
}
