import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const tokenCss = readFileSync(
  new URL("../typescript/packages/design-tokens/tokens.css", import.meta.url),
  "utf8",
);
const baseLayout = readFileSync(
  new URL("./src/layouts/base.astro", import.meta.url),
  "utf8",
);
const siteCss = readFileSync(new URL("./src/styles/globals.css", import.meta.url), "utf8");

function declarations(block) {
  return Object.fromEntries(
    [...block.matchAll(/(--[\w-]+):\s*(#[0-9a-fA-F]{6})\s*;/g)].map(([, key, value]) => [
      key,
      value,
    ]),
  );
}

function luminance(hex) {
  const channels = hex
    .slice(1)
    .match(/../g)
    .map((channel) => Number.parseInt(channel, 16) / 255)
    .map((channel) =>
      channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4,
    );
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

function contrastRatio(foreground, background) {
  const values = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
  return (values[0] + 0.05) / (values[1] + 0.05);
}

test("published dark theme applies high-contrast shared semantic tokens", () => {
  assert.match(baseLayout, /<html lang="en" class="dark" data-theme="dark">/);
  const rootBlock = tokenCss.match(/:root\s*\{([^}]+)\}/)?.[1];
  const darkBlock = tokenCss.match(/\.dark,\s*\[data-theme='dark'\]\s*\{([^}]+)\}/)?.[1];
  assert.ok(rootBlock, "shared root token block exists");
  assert.ok(darkBlock, "shared dark token block exists");
  const root = declarations(rootBlock);
  const dark = declarations(darkBlock);
  const background = root["--ag-color-surface-dark"];

  for (const key of [
    "--ag-color-text",
    "--ag-color-text-muted",
    "--ag-color-focus",
    "--ag-color-allow",
    "--ag-color-deny",
    "--ag-color-warning",
  ]) {
    assert.ok(dark[key], `dark mode defines ${key}`);
    assert.ok(
      contrastRatio(dark[key], background) >= 4.5,
      `${key} must meet WCAG AA for normal text on the published dark background`,
    );
  }
});

test("published light theme meets WCAG AA for semantic text and status colors", () => {
  const lightBlock = siteCss.match(/\[data-theme="light"\]\s*\{([^}]+)\}/)?.[1];
  assert.ok(lightBlock, "site light theme overrides its semantic tokens");
  const light = declarations(lightBlock);
  const background = light["--bg"];
  for (const key of ["--fg", "--muted", "--accent", "--warn", "--deny"]) {
    assert.ok(light[key], `light mode defines ${key}`);
    assert.ok(
      contrastRatio(light[key], background) >= 4.5,
      `${key} must meet WCAG AA for normal text on the light background`,
    );
  }
});
