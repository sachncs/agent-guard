import { readFileSync } from "node:fs";

const files = ["README.md", "CONTRIBUTING.md", "SUPPORT.md", "SECURITY.md", "BRAND.md"];
const forbidden = ["agentguard_console", "agentguard_ console"];
const failures = [];

for (const file of files) {
  const text = readFileSync(file, "utf8");
  for (const value of forbidden) {
    if (text.includes(value)) failures.push(file + ": stale public string " + value);
  }
}

if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}
console.log("public surface checks passed");
