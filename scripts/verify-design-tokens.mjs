import { existsSync, readFileSync } from "node:fs";

const tokenFile = "typescript/packages/design-tokens/tokens.css";
const consumers = [
  ["frontend/src/app/globals.css", '@import "@agentguard/design-tokens/tokens.css";'],
  ["site/src/styles/globals.css", "@import '../../../typescript/packages/design-tokens/tokens.css';"],
];
const failures = [];

if (!existsSync(tokenFile)) failures.push(`missing canonical token file: ${tokenFile}`);
for (const [file, importLine] of consumers) {
  if (!existsSync(file)) {
    failures.push(`missing token consumer: ${file}`);
    continue;
  }
  if (!readFileSync(file, "utf8").includes(importLine)) {
    failures.push(`${file}: does not import canonical design tokens`);
  }
}

const tokens = existsSync(tokenFile) ? readFileSync(tokenFile, "utf8") : "";
for (const name of [
  "--ag-color-brand-600",
  "--ag-color-allow",
  "--ag-color-deny",
  "--ag-color-warning",
  "--ag-color-focus",
]) {
  if (!tokens.includes(name)) failures.push(`${tokenFile}: missing ${name}`);
}

if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}
console.log("design token checks passed");
