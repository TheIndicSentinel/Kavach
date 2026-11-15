// The one Node API the browser tests use, declared here: the console
// installs no Node type package (the same declaration as src/test/node-fs.d.ts).
declare module "node:fs" {
  export function readFileSync(path: string | URL, encoding: "utf8"): string;
}
