import assert from "node:assert/strict";
import { test } from "node:test";
import { createHighlighter } from "shiki";
import { cedarLanguage } from "./src/languages/cedar.mjs";

test("Cedar policy and schema grammar highlights core syntax", async () => {
  const warnings = [];
  const originalWarn = console.warn;
  console.warn = (...args) => warnings.push(args.join(" "));
  try {
    const highlighter = await createHighlighter({
      langs: [cedarLanguage],
      langAlias: { cedarschema: "cedar" },
      themes: ["github-dark"],
    });
    try {
      for (const lang of ["cedar", "cedarschema"]) {
        const html = highlighter.codeToHtml('permit (principal == User::"alice");', {
          lang,
          theme: "github-dark",
        });
        assert.match(html, /<span style="color:[^"]+">permit<\/span>/, `${lang} should highlight Cedar keywords`);
        assert.match(html, /<span style="color:[^"]+">"alice"<\/span>/, `${lang} should highlight Cedar strings`);
      }
    } finally {
      highlighter.dispose();
    }
  } finally {
    console.warn = originalWarn;
  }
  assert.deepEqual(warnings, [], "Cedar fences should not trigger Shiki fallback warnings");
});
