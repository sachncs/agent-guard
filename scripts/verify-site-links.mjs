import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";

const siteRoot = resolve(process.argv[2] ?? "site/dist");
const publicBase = "/agent-guard";
const origin = "https://sachncs.github.io";
const failures = [];

function walk(directory) {
  return readdirSync(directory).flatMap((entry) => {
    const path = join(directory, entry);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });
}

function decodeAttribute(value) {
  return value
    .replaceAll("&amp;", "&")
    .replaceAll("&quot;", '"')
    .replaceAll("&#39;", "'")
    .replaceAll("&#x27;", "'");
}

function targetFile(url, sourceFile) {
  let pathname = decodeURIComponent(url.pathname);
  if (pathname.startsWith(`${siteRoot}${sep}`)) {
    return pathname.endsWith("/") ? join(pathname, "index.html") : pathname;
  }
  if (pathname === publicBase) pathname = `${publicBase}/`;
  if (pathname.startsWith(`${publicBase}/`)) pathname = pathname.slice(publicBase.length);
  else if (pathname.startsWith("/")) return null;

  const resolvedPath = pathname.startsWith("/")
    ? resolve(siteRoot, `.${pathname}`)
    : resolve(dirname(sourceFile), pathname);
  if (!resolvedPath.startsWith(`${siteRoot}${sep}`) && resolvedPath !== siteRoot) return null;
  if (pathname.endsWith("/")) return join(resolvedPath, "index.html");
  if (!pathname) return join(siteRoot, "index.html");
  if (pathname.endsWith(".html")) return resolvedPath;
  return resolvedPath;
}

function fragmentExists(html, fragment) {
  const escaped = fragment.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(?:id|name)=["']${escaped}["']`).test(html);
}

if (!statSync(siteRoot, { throwIfNoEntry: false })?.isDirectory()) {
  console.error(`built site directory not found: ${siteRoot}`);
  process.exit(1);
}

const authoredHtml = walk(siteRoot)
  .filter((file) => file.endsWith(".html"))
  // Rustdoc owns its generated navigation, JavaScript templates, and encoded
  // implementation anchors; validate its published crate entry points in
  // stage-api-reference.mjs and validate links into it from authored site pages here.
  .filter((file) => !relative(siteRoot, file).split(sep).includes("rustdoc"));

for (const sourceFile of authoredHtml) {
  const html = readFileSync(sourceFile, "utf8");
  for (const match of html.matchAll(/\b(?:href|src)=["']([^"']+)["']/gi)) {
    const rawTarget = decodeAttribute(match[1]);
    if (/^(?:#|[a-z][a-z\d+.-]*:|\/\/)/i.test(rawTarget)) {
      if (rawTarget.startsWith("#")) {
        const fragment = decodeURIComponent(rawTarget.slice(1));
        if (fragment && !fragmentExists(html, fragment)) {
          failures.push(`${relative(siteRoot, sourceFile)}: missing fragment #${fragment}`);
        }
      }
      continue;
    }

    let url;
    try {
      url = new URL(rawTarget, pathToFileURL(sourceFile));
    } catch {
      failures.push(`${relative(siteRoot, sourceFile)}: invalid link ${rawTarget}`);
      continue;
    }
    if (url.protocol === "file:") {
      const file = targetFile(url, sourceFile);
      if (file && !statSync(file, { throwIfNoEntry: false })?.isFile()) {
        failures.push(`${relative(siteRoot, sourceFile)}: missing target ${rawTarget}`);
      }
      if (url.hash && file && statSync(file, { throwIfNoEntry: false })?.isFile()) {
        const targetHtml = readFileSync(file, "utf8");
        const fragment = decodeURIComponent(url.hash.slice(1));
        if (fragment && !fragmentExists(targetHtml, fragment)) {
          failures.push(`${relative(siteRoot, sourceFile)}: ${rawTarget} has no #${fragment}`);
        }
      }
      continue;
    }

    if (url.origin === origin && url.pathname.startsWith(`${publicBase}/`)) {
      const file = targetFile(url, sourceFile);
      if (file && !statSync(file, { throwIfNoEntry: false })?.isFile()) {
        failures.push(`${relative(siteRoot, sourceFile)}: missing target ${rawTarget}`);
      } else if (url.hash && file) {
        const targetHtml = readFileSync(file, "utf8");
        const fragment = decodeURIComponent(url.hash.slice(1));
        if (fragment && !fragmentExists(targetHtml, fragment)) {
          failures.push(`${relative(siteRoot, sourceFile)}: ${rawTarget} has no #${fragment}`);
        }
      }
    }
  }
}

if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}

console.log(`built-site links passed (${authoredHtml.length} authored HTML pages; generated Rustdoc entry points checked separately)`);
