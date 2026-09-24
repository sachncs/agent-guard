import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");

function runTheme({ stored = null, prefersDark = false, storageAvailable = true } = {}) {
  const attributes = {};
  const root = {
    dataset: {},
    classList: { toggle: (name, enabled) => { attributes[name] = enabled; } },
  };
  const buttonAttributes = {};
  const button = { setAttribute: (name, value) => { buttonAttributes[name] = value; } };
  const colorMeta = { content: "" };
  let clickHandler;
  let mediaHandler;
  let readyHandler;
  const values = new Map(stored ? [["agentguard-theme", stored]] : []);
  const context = {
    document: {
      documentElement: root,
      querySelector: (selector) => selector === 'meta[name="theme-color"]' ? colorMeta : button,
      addEventListener: (name, handler) => {
        if (name === "click") clickHandler = handler;
        if (name === "DOMContentLoaded") readyHandler = handler;
      },
    },
    window: {
      matchMedia: () => ({
        matches: prefersDark,
        addEventListener: (_name, handler) => { mediaHandler = handler; },
      }),
    },
    localStorage: {
      getItem: (key) => {
        if (!storageAvailable) throw new Error("storage disabled");
        return values.get(key) ?? null;
      },
      setItem: (key, value) => {
        if (!storageAvailable) throw new Error("storage disabled");
        values.set(key, value);
      },
    },
  };
  vm.runInNewContext(read("./public/theme.js"), context);
  readyHandler();
  return { root, attributes, buttonAttributes, colorMeta, values, click: clickHandler, media: mediaHandler };
}

test("site theme follows system preference until the visitor makes a choice", () => {
  const light = runTheme();
  assert.equal(light.root.dataset.theme, "light");
  assert.equal(light.colorMeta.content, "#f7faf8");
  const dark = runTheme({ prefersDark: true });
  assert.equal(dark.root.dataset.theme, "dark");
  assert.equal(dark.attributes.dark, true);
  dark.media({ matches: false });
  assert.equal(dark.root.dataset.theme, "light");
});

test("a saved theme overrides the system and the control updates accessible state", () => {
  const theme = runTheme({ stored: "light", prefersDark: true });
  assert.equal(theme.root.dataset.theme, "light");
  assert.equal(theme.buttonAttributes["aria-label"], "Switch to dark mode");
  assert.equal(theme.buttonAttributes["aria-pressed"], "false");
  theme.click({ target: { closest: () => ({}) } });
  assert.equal(theme.root.dataset.theme, "dark");
  assert.equal(theme.values.get("agentguard-theme"), "dark");
  assert.equal(theme.buttonAttributes["aria-label"], "Switch to light mode");
  assert.equal(theme.buttonAttributes["aria-pressed"], "true");
  theme.media({ matches: false });
  assert.equal(theme.root.dataset.theme, "dark", "system changes do not override an explicit selection");
});

test("manual theme selection remains stable for the page when storage is unavailable", () => {
  const theme = runTheme({ storageAvailable: false, prefersDark: true });
  theme.click({ target: { closest: () => ({}) } });
  assert.equal(theme.root.dataset.theme, "light");
  theme.media({ matches: true });
  assert.equal(theme.root.dataset.theme, "light");
});

test("published layouts expose the theme control and light-mode design tokens", () => {
  const base = read("./src/layouts/base.astro");
  const header = read("./src/components/product/Header.astro");
  const css = read("./src/styles/globals.css");
  assert.match(base, /theme\.js/);
  assert.match(header, /data-theme-toggle[\s\S]*aria-label=/);
  assert.match(css, /\[data-theme="light"\][^{]*\{[^}]*color-scheme:light/);
  assert.match(css, /prefers-reduced-motion:reduce/);
});

test("CI browser-tests the built canonical site", () => {
  const workflow = read("../.github/workflows/ci.yml");
  assert.match(workflow, /name: Verify published site behavior in Chromium\s+run: pnpm --filter frontend test:site/);
  assert.match(read("../frontend/package.json"), /"test:site": "node scripts\/site-e2e\.mjs"/);
});
