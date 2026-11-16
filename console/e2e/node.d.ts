// The Node APIs the browser tests use, declared here: the console installs
// no Node type package (readFileSync as in src/test/node-fs.d.ts).
declare module "node:fs" {
  export function readFileSync(path: string | URL, encoding: "utf8"): string;
  /** realSetup.ts saves the seeded record ids for the specs. */
  export function writeFileSync(path: string, data: string): void;
}

/** realSetup.ts runs kavach-dev to sign system-of-record events. */
declare module "node:child_process" {
  export function execFileSync(file: string, args: readonly string[], options: { encoding: "utf8" }): string;
}
