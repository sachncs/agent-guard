#!/usr/bin/env node

import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const MINIMUM_NODE = { major: 22, minor: 12 };

export function isSupportedNodeVersion(value) {
  const match = /^v?(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?$/.exec(value);
  if (!match) return false;

  const [, majorText, minorText] = match;
  const major = Number(majorText);
  const minor = Number(minorText);
  return (
    major > MINIMUM_NODE.major ||
    (major === MINIMUM_NODE.major && minor >= MINIMUM_NODE.minor)
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (!isSupportedNodeVersion(process.versions.node)) {
    console.error(
      `Node.js >= ${MINIMUM_NODE.major}.${MINIMUM_NODE.minor}.0 is required; found ${process.versions.node}.`,
    );
    process.exitCode = 1;
  }
}
