// The one Node API a unit test uses (permissions.test.ts reads the Cedar
// policy file). The console installs no Node type package, so it is
// declared here; nothing in the browser build imports it.
declare module "node:fs" {
  export function readFileSync(path: string | URL, encoding: "utf8"): string;
}
