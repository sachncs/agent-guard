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

for (const [name, consumers] of [
  ["--color-allow: var(--ag-color-allow)", ["frontend/src/app/globals.css"]],
  ["--color-deny: var(--ag-color-deny)", ["frontend/src/app/globals.css"]],
  ["border-allow text-allow", ["frontend/src/lib/decision_presentation.ts"]],
  ["border-deny text-deny", ["frontend/src/lib/decision_presentation.ts"]],
]) {
  for (const file of consumers) {
    if (!readFileSync(file, "utf8").includes(name)) failures.push(`${file}: missing semantic token use ${name}`);
  }
}

if (!tokens.includes("--ag-color-deny: #ff8b82")) {
  failures.push(`${tokenFile}: dark mode must define a readable deny color`);
}

if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}
console.log("design token checks passed");
