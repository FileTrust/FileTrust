// SPDX-License-Identifier: FSL-1.1-ALv2
// Check every compiled protocol artifact against the EIP-170 runtime limit.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const root = fileURLToPath(new URL("../artifacts/contracts/", import.meta.url));
const files = dir => fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
  const file = path.join(dir, entry.name);
  return entry.isDirectory() ? files(file) : entry.name.endsWith(".json") && !entry.name.endsWith(".dbg.json") ? [file] : [];
});
let count = 0, failed = false;
for (const file of files(root)) {
  const artifact = JSON.parse(fs.readFileSync(file, "utf8"));
  const bytes = ((artifact.deployedBytecode || "0x").length - 2) / 2;
  if (!bytes) continue;
  count++;
  if (bytes > 24576) {
    console.error(`${artifact.contractName}: ${bytes} runtime bytes exceeds EIP-170`);
    failed = true;
  }
}
console.log(`Checked ${count} protocol runtime artifacts against EIP-170.`);
if (failed) process.exitCode = 1;
