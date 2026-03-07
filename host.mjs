#!/usr/bin/env node
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import { promises as fsp } from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";

const APP_ID = "cbgames-launcher-host-v1";
const DEFAULT_PORT = 8941;
const DEFAULT_HOST = "0.0.0.0";
const DEFAULT_STORE_DIR = path.resolve(process.cwd(), ".cbgames-launcher-host");
const DEFAULT_MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024; // 2 GiB
const DEFAULT_OTC_TTL_MS = 10 * 60 * 1000; // 10 minutes
const INDEX_FILE_NAME = "library.json";

function parseArgs(argv) {
  const options = {
    host: DEFAULT_HOST,
    port: DEFAULT_PORT,
    storeDir: DEFAULT_STORE_DIR,
    maxUploadBytes: DEFAULT_MAX_UPLOAD_BYTES,
    help: false
  };

  for (let i = 0; i < argv.length; i += 1) {
    const token = String(argv[i] || "");
    if (!token) {
      continue;
    }
    if (token === "--help" || token === "-h") {
      options.help = true;
      continue;
    }
    if (token === "--host") {
      options.host = String(argv[i + 1] || "").trim() || DEFAULT_HOST;
      i += 1;
      continue;
    }
    if (token === "--port" || token === "-p") {
      const parsed = Number(argv[i + 1]);
      if (Number.isFinite(parsed) && parsed > 0 && parsed < 65536) {
        options.port = Math.trunc(parsed);
      }
      i += 1;
      continue;
    }
    if (token === "--store") {
      const raw = String(argv[i + 1] || "").trim();
      if (raw) {
        options.storeDir = path.resolve(raw);
      }
      i += 1;
      continue;
    }
    if (token === "--max-upload-mb") {
      const parsed = Number(argv[i + 1]);
      if (Number.isFinite(parsed) && parsed > 0) {
        options.maxUploadBytes = Math.trunc(parsed * 1024 * 1024);
      }
      i += 1;
      continue;
    }
  }

  return options;
}

function printHelp() {
  console.log(
    [
      "CBGames launcher Host",
      "",
      "Usage:",
      "  node scripts/launcher-host.mjs [--host 0.0.0.0] [--port 8941] [--store ./.cbgames-launcher-host]",
      "",
      "Options:",
      "  --host <ip|name>        Bind host (default: 0.0.0.0)",
      "  --port, -p <port>       Bind port (default: 8941)",
      "  --store <path>          Storage directory (default: ./.cbgames-launcher-host)",
      "  --max-upload-mb <mb>    Max upload size in MB (default: 2048)",
      "  --help, -h              Show this help"
    ].join("\n")
  );
}

function getLauncherIpv4Addresses() {
  const interfaces = os.networkInterfaces();
  const addresses = [];
  for (const key of Object.keys(interfaces)) {
    const rows = interfaces[key] || [];
    for (const row of rows) {
      if (!row || row.internal || row.family !== "IPv4") {
        continue;
      }
      addresses.push(row.address);
    }
  }
  return Array.from(new Set(addresses)).sort();
}

function resolveAnnounceUrls(host, port) {
  const out = new Set();
  const normalizedHost = String(host || "").trim().toLowerCase();
  if (!normalizedHost || normalizedHost === "0.0.0.0" || normalizedHost === "::") {
    out.add("http://localhost:" + port);
    out.add("http://127.0.0.1:" + port);
    for (const ip of getLauncherIpv4Addresses()) {
      out.add("http://" + ip + ":" + port);
    }
    return Array.from(out);
  }
  out.add("http://" + host + ":" + port);
  return Array.from(out);
}

function normalizeZipType(rawType) {
  const value = String(rawType || "").trim().toLowerCase();
  if (value === "bundle") {
    return "bundle";
  }
  return "zip";
}

function parseBoolean(rawValue, fallback) {
  const value = String(rawValue || "").trim().toLowerCase();
  if (!value) {
    return fallback;
  }
  if (value === "1" || value === "true" || value === "yes" || value === "on") {
    return true;
  }
  if (value === "0" || value === "false" || value === "no" || value === "off") {
    return false;
  }
  return fallback;
}

function sanitizeZipName(rawName) {
  let name = String(rawName || "").trim();
  name = name.replace(/[\\/:*?"<>|]+/g, "-");
  name = name.replace(/\s+/g, " ").trim();
  if (!name) {
    name = "shared.zip";
  }
  if (!/\.zip$/i.test(name)) {
    name += ".zip";
  }
  return name;
}

function setCorsHeaders(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,HEAD,PUT,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function sendJson(res, statusCode, payload) {
  setCorsHeaders(res);
  res.statusCode = statusCode;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(payload));
}

function sendHtml(res, statusCode, html) {
  setCorsHeaders(res);
  res.statusCode = statusCode;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.end(html);
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function streamRequestToFile(req, targetPath, maxBytes) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let bytesRead = 0;
    const output = fs.createWriteStream(targetPath, { flags: "wx" });

    const fail = (error) => {
      if (settled) {
        return;
      }
      settled = true;
      req.unpipe(output);
      output.destroy();
      reject(error);
    };

    req.on("data", (chunk) => {
      bytesRead += chunk.length;
      if (bytesRead > maxBytes) {
        const error = new Error("Upload exceeds max size.");
        error.code = "PAYLOAD_TOO_LARGE";
        fail(error);
        req.destroy();
      }
    });
    req.on("error", fail);
    output.on("error", fail);
    output.on("finish", () => {
      if (settled) {
        return;
      }
      settled = true;
      resolve(bytesRead);
    });

    req.pipe(output);
  });
}

function formatBytes(bytes) {
  const safe = Number(bytes);
  if (!Number.isFinite(safe) || safe <= 0) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB", "TB"];
  const exponent = Math.min(Math.floor(Math.log(safe) / Math.log(1024)), units.length - 1);
  const value = safe / Math.pow(1024, exponent);
  return value.toFixed(value >= 10 || exponent === 0 ? 0 : 1) + " " + units[exponent];
}

function generateOneTimeCode(length = 6) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = "";
  for (let i = 0; i < length; i += 1) {
    const index = Math.floor(Math.random() * chars.length);
    out += chars.charAt(index);
  }
  return out;
}

function issueOneTimeCode(ttlMs) {
  const ttl = Number.isFinite(ttlMs) && ttlMs > 0 ? Math.trunc(ttlMs) : DEFAULT_OTC_TTL_MS;
  const now = Date.now();
  activeUploadCode = {
    code: generateOneTimeCode(6),
    issuedAt: now,
    expiresAt: now + ttl
  };
  return activeUploadCode;
}

function getOneTimeCodeState() {
  if (!activeUploadCode) {
    return { status: "none", message: "No one-time code has been issued." };
  }
  if (Date.now() >= activeUploadCode.expiresAt) {
    activeUploadCode = null;
    return { status: "expired", message: "The one-time code has expired." };
  }
  const secondsLeft = Math.max(0, Math.ceil((activeUploadCode.expiresAt - Date.now()) / 1000));
  return {
    status: "active",
    message: "Code " + activeUploadCode.code + " is active for " + secondsLeft + " more second(s).",
    code: activeUploadCode.code,
    expiresAt: activeUploadCode.expiresAt,
    secondsLeft
  };
}

function validateOneTimeCode(candidate) {
  const current = getOneTimeCodeState();
  if (current.status !== "active") {
    return { ok: false, error: "No active one-time code. Run `otc` in host terminal first." };
  }
  const value = String(candidate || "").trim().toUpperCase();
  if (!value) {
    return { ok: false, error: "Missing one-time code." };
  }
  if (value !== current.code) {
    return { ok: false, error: "Invalid one-time code." };
  }
  return { ok: true };
}

function toPublicItem(item) {
  return {
    id: item.id,
    name: item.name,
    type: item.type,
    size: item.size,
    shared: Boolean(item.shared),
    createdAt: item.createdAt,
    updatedAt: item.updatedAt,
    downloadUrl: "/download/" + encodeURIComponent(item.id)
  };
}

function createHostPage() {
  return `<!doctype html>
<html launcherg="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>CBGames launcher Host</title>
  <style>
    :root {
      color-scheme: dark;
      font-family: "Segoe UI", Tahoma, sans-serif;
    }
    body {
      margin: 0;
      background: #111;
      color: #f4f4f4;
      padding: 20px;
    }
    .layout {
      max-width: 980px;
      margin: 0 auto;
      display: grid;
      gap: 16px;
    }
    .card {
      border: 1px solid #2f2f2f;
      border-radius: 12px;
      background: #171717;
      padding: 14px;
      display: grid;
      gap: 10px;
    }
    h1, h2 {
      margin: 0;
      font-weight: 600;
    }
    h1 { font-size: 20px; }
    h2 { font-size: 15px; }
    p {
      margin: 0;
      color: #c8c8c8;
      font-size: 13px;
    }
    .row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }
    input[type="file"],
    select,
    button {
      min-height: 38px;
      border-radius: 10px;
      border: 1px solid #3a3a3a;
      background: #121212;
      color: #f2f2f2;
      padding: 0 10px;
      font-size: 13px;
    }
    button {
      cursor: pointer;
      background: #1e1e1e;
    }
    button:hover {
      border-color: #5f5f5f;
    }
    code {
      font-family: "Consolas", "SFMono-Regular", monospace;
      background: #0e0e0e;
      border: 1px solid #2f2f2f;
      padding: 2px 6px;
      border-radius: 6px;
      word-break: break-all;
    }
    .url-list {
      display: grid;
      gap: 6px;
    }
    .url-list a {
      color: #8dc4ff;
      text-decoration: none;
    }
    .status {
      color: #d0d0d0;
      min-height: 18px;
    }
    .status.error { color: #ffb0b0; }
    .status.success { color: #a9e7ac; }
    .items {
      display: grid;
      gap: 8px;
      max-height: 360px;
      overflow: auto;
      border: 1px solid #2e2e2e;
      border-radius: 10px;
      padding: 8px;
      background: #121212;
    }
    .item {
      display: grid;
      grid-template-columns: 1fr auto auto;
      gap: 10px;
      align-items: center;
      border: 1px solid #282828;
      border-radius: 8px;
      background: #151515;
      padding: 8px 10px;
      font-size: 13px;
    }
    .item-meta strong {
      display: block;
      font-size: 13px;
      color: #f0f0f0;
    }
    .item-meta small {
      display: block;
      color: #bcbcbc;
      margin-top: 2px;
    }
    .item a {
      color: #97caff;
      text-decoration: none;
      font-size: 12px;
    }
    .item-flag {
      font-size: 11px;
      color: #d6d6d6;
      border: 1px solid #333;
      border-radius: 999px;
      padding: 2px 8px;
      white-space: nowrap;
    }
    .item-flag.is-shared {
      color: #bfe3bf;
      border-color: #315231;
      background: #152015;
    }
    .item-flag.is-private {
      color: #e0d5b6;
      border-color: #4a4028;
      background: #1f1a10;
    }
    .empty-note {
      color: #b7b7b7;
      font-size: 13px;
      padding: 6px 2px;
    }
  </style>
</head>
<body>
  <div class="layout">
    <section class="card">
      <h1>CBGames launcher Host</h1>
      <p>Host dashboard for shared launcher files. Manage files from the host terminal only.</p>
      <div id="hostUrls" class="url-list"></div>
      <p>Manifest endpoint: <code id="manifestEndpoint">/api/manifest</code></p>
      <p>Client upload endpoint (OTC): <code>/api/client-upload?otc=CODE</code></p>
    </section>

    <section class="card">
      <h2>Hosted Files</h2>
      <p>Read-only in browser. Use host terminal commands to change sharing or delete items.</p>
      <div id="itemsList" class="items"></div>
    </section>
  </div>

  <script>
    const hostUrls = document.getElementById("hostUrls");
    const manifestEndpoint = document.getElementById("manifestEndpoint");
    const statusLine = document.getElementById("statusLine");
    const itemsList = document.getElementById("itemsList");

    let currentItems = [];

    function setStatus(message, tone) {
      statusLine.textContent = String(message || "").trim();
      statusLine.classList.toggle("error", tone === "error");
      statusLine.classList.toggle("success", tone === "success");
    }

    function formatBytes(bytes) {
      const safe = Number(bytes);
      if (!Number.isFinite(safe) || safe <= 0) return "0 B";
      const units = ["B", "KB", "MB", "GB", "TB"];
      const exponent = Math.min(Math.floor(Math.log(safe) / Math.log(1024)), units.length - 1);
      const value = safe / Math.pow(1024, exponent);
      return value.toFixed(value >= 10 || exponent === 0 ? 0 : 1) + " " + units[exponent];
    }

    async function api(path, options) {
      const response = await fetch(path, options);
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        const message = payload && payload.error ? payload.error : ("HTTP " + response.status);
        throw new Error(message);
      }
      return payload;
    }

    function renderHostUrls(info) {
      hostUrls.innerHTML = "";
      const urls = Array.isArray(info && info.urls) ? info.urls : [];
      for (const url of urls) {
        const row = document.createElement("div");
        const link = document.createElement("a");
        link.href = url;
        link.textContent = url;
        link.target = "_blauncherk";
        link.rel = "noreferrer noopener";
        row.append(link);
        hostUrls.append(row);
      }
      manifestEndpoint.textContent = (urls[0] || window.location.origin) + "/api/manifest";
    }

    function renderItems() {
      itemsList.innerHTML = "";
      if (!currentItems.length) {
        const empty = document.createElement("p");
        empty.className = "empty-note";
        empty.textContent = "No hosted files yet.";
        itemsList.append(empty);
        return;
      }

      for (const item of currentItems) {
        const row = document.createElement("div");
        row.className = "item";

        const meta = document.createElement("div");
        meta.className = "item-meta";
        const name = document.createElement("strong");
        name.textContent = item.name;
        const sub = document.createElement("small");
        sub.textContent = (item.type === "bundle" ? "Bundle ZIP" : "Game ZIP") + " • " + formatBytes(item.size);
        meta.append(name, sub);

        const visibility = document.createElement("span");
        visibility.className = "item-flag " + (item.shared ? "is-shared" : "is-private");
        visibility.textContent = item.shared ? "Shared" : "Private";

        const download = document.createElement("a");
        download.href = item.downloadUrl;
        download.textContent = "Download";
        download.target = "_blauncherk";
        download.rel = "noreferrer noopener";

        row.append(meta, visibility, download);
        itemsList.append(row);
      }
    }

    async function loadInfo() {
      const info = await api("/api/info");
      renderHostUrls(info);
    }

    async function loadItems() {
      const payload = await api("/api/items");
      currentItems = Array.isArray(payload.items) ? payload.items : [];
      renderItems();
    }

    Promise.all([loadInfo(), loadItems()])
      .then(() => setStatus("Host ready.", "success"))
      .catch((error) => setStatus(error.message || String(error), "error"));
  </script>
</body>
</html>`;
}

const args = parseArgs(process.argv.slice(2));
if (args.help) {
  printHelp();
  process.exit(0);
}

const storeDir = args.storeDir;
const filesDir = path.join(storeDir, "files");
const indexPath = path.join(storeDir, INDEX_FILE_NAME);

let library = {
  format: APP_ID,
  updatedAt: Date.now(),
  items: []
};

let activeUploadCode = null;

async function ensureStoreReady() {
  await fsp.mkdir(filesDir, { recursive: true });
}

async function loadLibrary() {
  try {
    const raw = await fsp.readFile(indexPath, "utf8");
    const parsed = JSON.parse(raw);
    if (!parsed || !Array.isArray(parsed.items)) {
      throw new Error("Invalid library format.");
    }
    library = {
      format: APP_ID,
      updatedAt: Number(parsed.updatedAt) || Date.now(),
      items: parsed.items
        .filter((item) => item && typeof item === "object")
        .map((item) => ({
          id: String(item.id || "").trim(),
          name: sanitizeZipName(item.name || ""),
          type: normalizeZipType(item.type),
          size: Math.max(0, Number(item.size) || 0),
          shared: Boolean(item.shared),
          storedFile: String(item.storedFile || ""),
          createdAt: Number(item.createdAt) || Date.now(),
          updatedAt: Number(item.updatedAt) || Date.now()
        }))
        .filter((item) => item.id && item.storedFile)
    };
  } catch (error) {
    if (error && error.code === "ENOENT") {
      await saveLibrary();
      return;
    }
    console.warn("Could not read library index, starting empty:", error.message || String(error));
    library = {
      format: APP_ID,
      updatedAt: Date.now(),
      items: []
    };
    await saveLibrary();
  }
}

async function saveLibrary() {
  library.updatedAt = Date.now();
  const payload = JSON.stringify(
    {
      format: APP_ID,
      updatedAt: library.updatedAt,
      items: library.items
    },
    null,
    2
  );
  const tempPath = indexPath + ".tmp";
  await fsp.writeFile(tempPath, payload, "utf8");
  await fsp.rename(tempPath, indexPath);
}

async function pruneMissingFiles() {
  const kept = [];
  for (const item of library.items) {
    const filePath = path.join(filesDir, item.storedFile);
    try {
      const stat = await fsp.stat(filePath);
      item.size = Math.max(0, Number(stat.size) || 0);
      kept.push(item);
    } catch (error) {
      if (!error || error.code !== "ENOENT") {
        throw error;
      }
    }
  }
  if (kept.length !== library.items.length) {
    library.items = kept;
    await saveLibrary();
  }
}

function getItemById(id) {
  const key = String(id || "");
  return library.items.find((item) => item.id === key) || null;
}

async function removeStoredFileSafe(storedFile) {
  const target = path.join(filesDir, storedFile);
  try {
    await fsp.unlink(target);
  } catch (error) {
    if (!error || error.code !== "ENOENT") {
      throw error;
    }
  }
}

async function storeUploadedZip(req, options) {
  const opts = options && typeof options === "object" ? options : {};
  const cleanName = sanitizeZipName(opts.name || "");
  const itemType = normalizeZipType(opts.type);
  const shared = Boolean(opts.shared);
  const id = randomUUID();
  const storedFile = id + ".zip";
  const tempPath = path.join(filesDir, storedFile + ".tmp");
  const finalPath = path.join(filesDir, storedFile);

  let writtenBytes = 0;
  try {
    writtenBytes = await streamRequestToFile(req, tempPath, args.maxUploadBytes);
    if (!writtenBytes) {
      throw new Error("Uploaded file was empty.");
    }
    await fsp.rename(tempPath, finalPath);
  } catch (error) {
    await removeStoredFileSafe(storedFile + ".tmp");
    await removeStoredFileSafe(storedFile);
    if (error && error.code === "PAYLOAD_TOO_LARGE") {
      const sizeError = new Error(
        "Upload exceeds max size of " + formatBytes(args.maxUploadBytes) + "."
      );
      sizeError.code = "PAYLOAD_TOO_LARGE";
      throw sizeError;
    }
    throw new Error(error && error.message ? error.message : "Upload failed.");
  }

  const now = Date.now();
  const item = {
    id,
    name: cleanName,
    type: itemType,
    size: writtenBytes,
    shared,
    storedFile,
    createdAt: now,
    updatedAt: now
  };
  library.items.unshift(item);
  await saveLibrary();
  return item;
}

async function importLocalZipFile(sourcePath, options) {
  const opts = options && typeof options === "object" ? options : {};
  const resolved = path.resolve(String(sourcePath || ""));
  if (!resolved) {
    throw new Error("Missing file path.");
  }
  const stat = await fsp.stat(resolved);
  if (!stat.isFile()) {
    throw new Error("Path is not a file: " + resolved);
  }

  const name = sanitizeZipName(opts.name || path.basename(resolved));
  const type = normalizeZipType(opts.type || "bundle");
  const shared = Object.prototype.hasOwnProperty.call(opts, "shared")
    ? Boolean(opts.shared)
    : true;
  const id = randomUUID();
  const storedFile = id + ".zip";
  const destination = path.join(filesDir, storedFile);
  await fsp.copyFile(resolved, destination);

  const now = Date.now();
  const item = {
    id,
    name,
    type,
    size: Math.max(0, Number(stat.size) || 0),
    shared,
    storedFile,
    createdAt: now,
    updatedAt: now
  };
  library.items.unshift(item);
  await saveLibrary();
  return item;
}

async function handleClientUpload(req, res, requestUrl) {
  const submittedOtc = String(
    requestUrl.searchParams.get("otc") ||
    requestUrl.searchParams.get("code") ||
    ""
  ).trim();
  const auth = validateOneTimeCode(submittedOtc);
  if (!auth.ok) {
    sendJson(res, 401, { error: auth.error });
    return;
  }

  const rawName = String(requestUrl.searchParams.get("name") || "").trim() || "cbgames-client-upload.zip";
  const itemType = normalizeZipType(requestUrl.searchParams.get("type") || "bundle");
  const shared = parseBoolean(requestUrl.searchParams.get("shared"), true);
  try {
    const item = await storeUploadedZip(req, {
      name: rawName,
      type: itemType,
      shared
    });
    // One-time code is consumed after the first successful client upload.
    activeUploadCode = null;
    sendJson(res, 201, {
      item: toPublicItem(item),
      totalItems: library.items.length
    });
  } catch (error) {
    if (error && error.code === "PAYLOAD_TOO_LARGE") {
      sendJson(res, 413, { error: error.message || "Upload too large." });
      return;
    }
    sendJson(res, 400, { error: error && error.message ? error.message : "Upload failed." });
  }
}

async function setItemShared(itemId, sharedValue) {
  const normalizedId = String(itemId || "").trim();
  if (!normalizedId) {
    throw new Error("Missing item id.");
  }
  const item = getItemById(normalizedId);
  if (!item) {
    throw new Error("Item not found: " + normalizedId);
  }
  item.shared = Boolean(sharedValue);
  item.updatedAt = Date.now();
  await saveLibrary();
  return item;
}

async function deleteItem(itemId) {
  const normalizedId = String(itemId || "").trim();
  if (!normalizedId) {
    throw new Error("Missing item id.");
  }
  const index = library.items.findIndex((entry) => entry.id === normalizedId);
  if (index < 0) {
    throw new Error("Item not found: " + normalizedId);
  }
  const [item] = library.items.splice(index, 1);
  await removeStoredFileSafe(item.storedFile);
  await saveLibrary();
  return item;
}

async function handleDownload(res, itemId, options = {}) {
  const headOnly = Boolean(options.headOnly);
  const item = getItemById(itemId);
  if (!item) {
    sendJson(res, 404, { error: "Item not found." });
    return;
  }
  const filePath = path.join(filesDir, item.storedFile);
  let stat;
  try {
    stat = await fsp.stat(filePath);
  } catch (error) {
    if (error && error.code === "ENOENT") {
      sendJson(res, 410, { error: "Stored file is missing." });
      return;
    }
    throw error;
  }
  setCorsHeaders(res);
  res.statusCode = 200;
  res.setHeader("Content-Type", "application/zip");
  res.setHeader("Content-Length", String(stat.size));
  res.setHeader("Content-Disposition", 'attachment; filename="' + escapeHtml(item.name) + '"');
  if (headOnly) {
    res.end();
    return;
  }
  fs.createReadStream(filePath).pipe(res);
}

function getInfoPayload() {
  const urls = resolveAnnounceUrls(args.host, args.port);
  const otcState = getOneTimeCodeState();
  return {
    app: APP_ID,
    host: args.host,
    port: args.port,
    storeDir,
    maxUploadBytes: args.maxUploadBytes,
    urls,
    manifestPath: "/api/manifest",
    clientUploadPath: "/api/client-upload",
    otcActive: otcState.status === "active",
    otcExpiresAt: otcState.status === "active" ? otcState.expiresAt : 0,
    now: Date.now()
  };
}

function getManifestPayload() {
  return {
    format: "cbgames-host-manifest-v1",
    generatedAt: Date.now(),
    items: library.items
      .filter((item) => item.shared)
      .map((item) => ({
        id: item.id,
        name: item.name,
        type: item.type,
        size: item.size,
        downloadUrl: "/download/" + encodeURIComponent(item.id)
      }))
  };
}

await ensureStoreReady();
await loadLibrary();
await pruneMissingFiles();

const server = http.createServer(async (req, res) => {
  try {
    const method = String(req.method || "GET").toUpperCase();
    if (method === "OPTIONS") {
      setCorsHeaders(res);
      res.statusCode = 204;
      res.end();
      return;
    }

    const url = new URL(req.url || "/", "http://localhost");
    const pathname = url.pathname || "/";

    if (method === "GET" && pathname === "/") {
      sendHtml(res, 200, createHostPage());
      return;
    }

    if (method === "GET" && pathname === "/api/info") {
      sendJson(res, 200, getInfoPayload());
      return;
    }

    if (method === "GET" && pathname === "/api/items") {
      sendJson(res, 200, {
        format: APP_ID,
        updatedAt: library.updatedAt,
        items: library.items.map((item) => toPublicItem(item))
      });
      return;
    }

    if (method === "GET" && pathname === "/api/manifest") {
      sendJson(res, 200, getManifestPayload());
      return;
    }

    if (method === "PUT" && pathname === "/api/upload") {
      sendJson(res, 403, {
        error: "Web UI/API upload is disabled. Use launcher OTC upload via /api/client-upload."
      });
      return;
    }

    if (method === "PUT" && pathname === "/api/client-upload") {
      await handleClientUpload(req, res, url);
      return;
    }

    const apiItemMatch = pathname.match(/^\/api\/items\/([^/]+)$/);
    if (apiItemMatch) {
      if (method === "PATCH") {
        sendJson(res, 403, {
          error: "Web UI/API item edits are disabled. Use host terminal command `share <item-id> <shared|private>`."
        });
        return;
      }
      if (method === "DELETE") {
        sendJson(res, 403, {
          error: "Web UI/API deletion is disabled. Use host terminal command `delete <item-id>`."
        });
        return;
      }
    }

    const downloadMatch = pathname.match(/^\/download\/([^/]+)$/);
    if (downloadMatch && (method === "GET" || method === "HEAD")) {
      const itemId = decodeURIComponent(downloadMatch[1]);
      await handleDownload(res, itemId, { headOnly: method === "HEAD" });
      return;
    }

    sendJson(res, 404, { error: "Not found." });
  } catch (error) {
    console.error(error);
    sendJson(res, 500, { error: error && error.message ? error.message : "Unexpected error." });
  }
});

server.on("error", (error) => {
  console.error("CBGames launcher host failed to start:", error && error.message ? error.message : String(error));
  process.exit(1);
});

function printCommandHelp() {
  console.log("Host commands:");
  console.log("  help               Show available commands");
  console.log("  status             Show library + OTC status");
  console.log("  urls               Print reachable host URLs");
  console.log("  import <path> [type] [shared|private]");
  console.log("                     Import local ZIP into host store (default type=bundle, shared)");
  console.log("  otc [minutes]      Issue a one-time upload code (default 10 minutes)");
  console.log("  clear-otc          Invalidate current one-time code");
  console.log("  list               List hosted files");
  console.log("  share <id> <shared|private>");
  console.log("                     Set whether item appears in launcher manifest");
  console.log("  delete <id>        Delete a hosted file from this host (host-only)");
  console.log("  exit | quit        Stop host");
}

function printLibraryList() {
  if (!library.items.length) {
    console.log("No hosted files.");
    return;
  }
  console.log("Hosted files:");
  for (const item of library.items) {
    console.log(
      " - " +
      item.id +
      " | " +
      item.name +
      " | " +
      (item.type === "bundle" ? "bundle" : "zip") +
      " | " +
      formatBytes(item.size) +
      " | shared=" +
      (item.shared ? "yes" : "no")
    );
  }
}

function printStatus() {
  console.log("Hosted items:", library.items.length);
  console.log(
    "Shared items:",
    library.items.reduce((count, item) => count + (item.shared ? 1 : 0), 0)
  );
  const otcState = getOneTimeCodeState();
  if (otcState.status === "active") {
    console.log(
      "OTC active:",
      otcState.code,
      "| expires in",
      otcState.secondsLeft + "s"
    );
  } else {
    console.log("OTC:", otcState.message);
  }
}

function parseImportCommand(rawLine) {
  const raw = String(rawLine || "").trim();
  const rest = raw.replace(/^import\s+/i, "").trim();
  if (!rest) {
    throw new Error("Usage: import <path.zip> [bundle|zip] [shared|private]");
  }

  let filePath = "";
  let remaining = "";
  if (rest.startsWith('"') || rest.startsWith("'")) {
    const quote = rest.charAt(0);
    const closeIndex = rest.indexOf(quote, 1);
    if (closeIndex <= 1) {
      throw new Error("Quoted path is missing closing quote.");
    }
    filePath = rest.slice(1, closeIndex);
    remaining = rest.slice(closeIndex + 1).trim();
  } else {
    const parts = rest.split(/\s+/);
    filePath = String(parts.shift() || "");
    remaining = parts.join(" ");
  }

  if (!filePath) {
    throw new Error("Missing file path.");
  }

  const extras = remaining ? remaining.split(/\s+/) : [];
  const type = extras.length ? normalizeZipType(extras[0]) : "bundle";
  let shared = true;
  if (extras.length >= 2) {
    const shareValue = String(extras[1] || "").trim().toLowerCase();
    if (shareValue === "private" || shareValue === "no" || shareValue === "false" || shareValue === "0") {
      shared = false;
    }
  }
  return { filePath, type, shared };
}

function parseSharedCommandValue(rawValue) {
  const value = String(rawValue || "").trim().toLowerCase();
  if (!value) {
    throw new Error("Usage: share <item-id> <shared|private>");
  }
  if (value === "shared" || value === "public" || value === "true" || value === "1" || value === "yes") {
    return true;
  }
  if (value === "private" || value === "hidden" || value === "false" || value === "0" || value === "no") {
    return false;
  }
  throw new Error("Share value must be `shared` or `private`.");
}

function startCommandConsole() {
  if (!process.stdin || !process.stdin.isTTY) {
    return;
  }
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: "launcher-host> "
  });

  rl.on("line", async (line) => {
    try {
      const raw = String(line || "").trim();
      if (!raw) {
        rl.prompt();
        return;
      }
      const parts = raw.split(/\s+/);
      const command = parts[0].toLowerCase();
      if (command === "help") {
        printCommandHelp();
        rl.prompt();
        return;
      }
      if (command === "status") {
        printStatus();
        rl.prompt();
        return;
      }
      if (command === "urls") {
        const info = getInfoPayload();
        console.log("Host URLs:");
        for (const url of info.urls) {
          console.log(" -", url);
        }
        rl.prompt();
        return;
      }
      if (command === "import") {
        const parsed = parseImportCommand(raw);
        const imported = await importLocalZipFile(parsed.filePath, {
          type: parsed.type,
          shared: parsed.shared
        });
        console.log(
          "Imported local ZIP:",
          imported.name,
          "|",
          formatBytes(imported.size),
          "| shared=" + (imported.shared ? "yes" : "no")
        );
        rl.prompt();
        return;
      }
      if (command === "list") {
        printLibraryList();
        rl.prompt();
        return;
      }
      if (command === "share") {
        const itemId = String(parts[1] || "").trim();
        const shared = parseSharedCommandValue(parts[2]);
        const updated = await setItemShared(itemId, shared);
        console.log(
          "Updated share state:",
          updated.id,
          "|",
          updated.name,
          "| shared=" + (updated.shared ? "yes" : "no")
        );
        rl.prompt();
        return;
      }
      if (command === "delete" || command === "remove" || command === "rm") {
        const itemId = String(parts[1] || "").trim();
        if (!itemId) {
          throw new Error("Usage: delete <item-id>");
        }
        const removed = await deleteItem(itemId);
        console.log("Deleted:", removed.id, "|", removed.name);
        rl.prompt();
        return;
      }
      if (command === "clear-otc") {
        activeUploadCode = null;
        console.log("One-time code cleared.");
        rl.prompt();
        return;
      }
      if (command === "otc") {
        const minutes = Number(parts[1]);
        const ttlMs = Number.isFinite(minutes) && minutes > 0
          ? Math.round(minutes * 60 * 1000)
          : DEFAULT_OTC_TTL_MS;
        const issued = issueOneTimeCode(ttlMs);
        const expiresLocal = new Date(issued.expiresAt).toLocaleTimeString();
        console.log("One-time code:", issued.code);
        console.log("Valid until:", expiresLocal);
        console.log("Use it with launcher upload to /api/client-upload.");
        rl.prompt();
        return;
      }
      if (command === "exit" || command === "quit") {
        rl.close();
        return;
      }

      console.log("Unknown command:", command);
      console.log("Run `help` for command list.");
      rl.prompt();
    } catch (error) {
      console.log("Command failed:", error && error.message ? error.message : String(error));
      rl.prompt();
    }
  });

  rl.on("close", () => {
    console.log("Stopping CBGames launcher host...");
    server.close(() => {
      process.exit(0);
    });
  });

  printCommandHelp();
  rl.prompt();
}

server.listen(args.port, args.host, () => {
  const info = getInfoPayload();
  console.log("CBGames launcher host running.");
  console.log("Store directory:", info.storeDir);
  console.log("Max upload size:", formatBytes(info.maxUploadBytes));
  console.log("Host URLs:");
  for (const url of info.urls) {
    console.log(" -", url);
  }
  console.log("Manifest URL:");
  if (info.urls.length) {
    console.log(" -", info.urls[0] + info.manifestPath);
  } else {
    console.log(" - /api/manifest");
  }
  console.log("Type `help` for host commands. Type `otc` to issue a one-time upload code.");
  startCommandConsole();
});
