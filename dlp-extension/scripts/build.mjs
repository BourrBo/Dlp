import { cp, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const options = { backendOrigin: "http://localhost:8000", aiHosts: [], target: "chrome", firefoxId: "", out: "" };
for (let i = 0; i < args.length; i += 1) {
  const flag = args[i];
  const value = args[i + 1];
  if (!value || value.startsWith("--")) throw new Error(`Missing value for ${flag}`);
  if (flag === "--backend-origin") options.backendOrigin = value;
  else if (flag === "--ai-host") options.aiHosts.push(value);
  else if (flag === "--target") options.target = value.toLowerCase();
  else if (flag === "--firefox-id") options.firefoxId = value;
  else if (flag === "--out") options.out = path.resolve(value);
  else throw new Error(`Unknown option: ${flag}`);
  i += 1;
}

if (!["chrome", "edge", "firefox"].includes(options.target)) throw new Error("--target must be chrome, edge, or firefox.");
if (options.target === "firefox" && !/^[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+$/.test(options.firefoxId)) {
  throw new Error("Firefox builds require --firefox-id in email-like format, for example dlp-guard@example.com.");
}
if (!options.out) options.out = path.join(root, "dist", options.target);

function parseBackendOrigin(value) {
  const url = new URL(value);
  const local = new Set(["localhost", "127.0.0.1", "::1"]).has(url.hostname);
  if (!new Set(["http:", "https:"]).has(url.protocol) || (url.protocol !== "https:" && !local)) {
    throw new Error("Backend origin must use HTTPS; HTTP is allowed only for localhost development.");
  }
  if (url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
    throw new Error("Pass only the backend origin, without credentials, path, query, or fragment.");
  }
  return `${url.protocol}//${url.host}/*`;
}

function hostPatterns(value) {
  let host = value.trim().toLowerCase();
  if (host.includes("://")) host = new URL(host).hostname;
  if (host.includes("/") || !host || host.startsWith(".") || host.endsWith(".")) throw new Error(`Invalid AI host: ${value}`);
  const canonical = host.replace(/^www\./, "");
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(canonical)) {
    throw new Error(`Invalid AI host: ${value}`);
  }
  return [`https://${canonical}/*`, `https://*.${canonical}/*`];
}

const source = JSON.parse(await readFile(path.join(root, "manifest.json"), "utf8"));
const defaultHosts = source.content_scripts[0].matches.map((match) => match.match(/^https:\/\/([^/*]+)/)?.[1]).filter(Boolean);
const hosts = [...new Set((options.aiHosts.length ? options.aiHosts : defaultHosts).map((host) => host.replace(/^www\./, "").toLowerCase()))];
const contentMatches = [...new Set(hosts.flatMap(hostPatterns))];
const apiHost = parseBackendOrigin(options.backendOrigin);
source.host_permissions = [...new Set([...contentMatches, apiHost])];
source.content_scripts[0].matches = contentMatches;
if (options.target === "firefox") {
  source.background = { scripts: ["extension-core.js", "personal-auth.js", "background.js"] };
  delete source.storage;
  source.browser_specific_settings = {
    gecko: {
      id: options.firefoxId,
      strict_min_version: "140.0",
      data_collection_permissions: { required: ["websiteContent", "websiteActivity"] },
    },
  };
} else {
  source.background = { service_worker: "background.js" };
}

await mkdir(options.out, { recursive: true });
for (const file of ["background.js", "content.js", "extension-core.js", "personal-auth.js", "options.html", "options.js", "popup.html", "popup.js", "managed-schema.json"]) {
  await cp(path.join(root, file), path.join(options.out, file));
}
await writeFile(path.join(options.out, "manifest.json"), `${JSON.stringify(source, null, 2)}\n`);
console.log(`Built ${options.target} extension for ${hosts.length} AI host(s), backend ${new URL(options.backendOrigin).origin}: ${options.out}`);
