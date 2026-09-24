import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname, extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const siteBasePath = "/agent-guard/";
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const siteDist = resolve(repoRoot, "site/dist");
const contentTypes = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".png", "image/png"],
  [".svg", "image/svg+xml"],
  [".txt", "text/plain; charset=utf-8"],
  [".woff2", "font/woff2"],
  [".xml", "application/xml; charset=utf-8"],
]);

function createStaticServer() {
  return createServer(async (request, response) => {
    if (request.method !== "GET" && request.method !== "HEAD") {
      response.writeHead(405, { allow: "GET, HEAD" }).end();
      return;
    }
    let pathname;
    try {
      pathname = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
    } catch {
      response.writeHead(400).end();
      return;
    }
    if (!pathname.startsWith(siteBasePath)) {
      response.writeHead(404).end();
      return;
    }
    let relative = pathname.slice(siteBasePath.length);
    if (!relative || relative.endsWith("/")) relative += "index.html";
    const filePath = resolve(siteDist, relative);
    if (!filePath.startsWith(`${siteDist}${sep}`)) {
      response.writeHead(404).end();
      return;
    }
    try {
      const body = await readFile(filePath);
      response.writeHead(200, {
        "content-type": contentTypes.get(extname(filePath)) ?? "application/octet-stream",
        "cache-control": "no-store",
      });
      response.end(request.method === "HEAD" ? undefined : body);
    } catch {
      response.writeHead(404).end();
    }
  });
}

let browser;
const server = createStaticServer();
try {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const { port } = server.address();
  const origin = `http://127.0.0.1:${port}`;

  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({
    viewport: { width: 375, height: 812 },
    colorScheme: "light",
    reducedMotion: "reduce",
  });
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));

  await page.goto(new URL(siteBasePath, origin).href, { waitUntil: "networkidle" });
  assert.equal(await page.locator("html").getAttribute("data-theme"), "light");
  assert.equal(await page.locator("[data-theme-toggle]").getAttribute("aria-label"), "Switch to dark mode");
  assert.equal(await page.evaluate(() => getComputedStyle(document.documentElement).scrollBehavior), "auto");
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, "mobile layout must not overflow horizontally");

  await page.locator("[data-theme-toggle]").click();
  assert.equal(await page.locator("html").getAttribute("data-theme"), "dark");
  assert.equal(await page.locator("[data-theme-toggle]").getAttribute("aria-pressed"), "true");
  await page.reload({ waitUntil: "networkidle" });
  assert.equal(await page.locator("html").getAttribute("data-theme"), "dark", "manual choice persists across reloads");

  await page.evaluate(() => localStorage.removeItem("agentguard-theme"));
  await page.emulateMedia({ colorScheme: "dark" });
  await page.reload({ waitUntil: "networkidle" });
  assert.equal(await page.locator("html").getAttribute("data-theme"), "dark", "system dark preference is honored without an override");

  await page.goto(new URL(`${siteBasePath}docs/security/`, origin).href, { waitUntil: "networkidle" });
  assert.equal(await page.locator("[data-theme-toggle]").isVisible(), true, "theme control appears on documentation pages");
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, "documentation layout must fit mobile width");
  assert.deepEqual(pageErrors, [], "site pages should not emit uncaught browser errors");
  console.log("published site browser smoke passed (themes, persistence, reduced motion, docs, and mobile layout)");
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
} finally {
  await browser?.close();
  if (server.listening) await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
