import { copyFile, mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = process.cwd();
const output = resolve(root, "dist");

await mkdir(output, { recursive: true });
await Promise.all([
  copyFile(resolve(root, "index.html"), resolve(output, "index.html")),
  copyFile(resolve(root, "login.html"), resolve(output, "login.html")),
  writeFile(resolve(output, "_redirects"), "/login /login.html 200\n", "utf8")
]);

console.log("Built the static Netlify site in dist/ (HTML files only).");
