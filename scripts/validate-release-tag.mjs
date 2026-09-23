import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const numericIdentifier = "(0|[1-9][0-9]*)";
const nonNumericIdentifier = "[0-9]*[A-Za-z-][0-9A-Za-z-]*";
const prereleaseIdentifier = `(?:${numericIdentifier}|${nonNumericIdentifier})`;
const semanticVersion = new RegExp(
  `^v${numericIdentifier}\\.${numericIdentifier}\\.${numericIdentifier}` +
    `(?:-${prereleaseIdentifier}(?:\\.${prereleaseIdentifier})*)?` +
    `(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$`,
);

export function isValidReleaseTag(tag) {
  return semanticVersion.test(tag);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const tag = process.argv[2] ?? "";
  if (!isValidReleaseTag(tag)) {
    console.error(`Expected a semantic version tag such as v0.3.0; got ${JSON.stringify(tag)}`);
    process.exitCode = 1;
  }
}
