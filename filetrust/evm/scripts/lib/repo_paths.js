// Resolve the standalone FileTrust repository without sibling applications.
import fs from "node:fs";
import path from "node:path";

export function resolveRepoRoot(startDir) {
  if (process.env.FILETRUST_REPO_ROOT) return path.resolve(process.env.FILETRUST_REPO_ROOT);
  let dir = path.resolve(startDir);
  while (true) {
    if (fs.existsSync(path.join(dir, "go.mod")) && fs.existsSync(path.join(dir, "filetrust", "evm"))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) throw new Error("Cannot locate the FileTrust repository root");
    dir = parent;
  }
}

export function resolveReportsDir(startDir) {
  return path.join(resolveRepoRoot(startDir), "reports");
}
