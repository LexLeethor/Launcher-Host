#!/usr/bin/env node
import { pbkdf2Sync, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import { promises as fsp } from "node:fs";
import http from "node:http";
import https from "node:https";
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
const AUTH_FILE_NAME = "auth.json";
const DEFAULT_ADMIN_USER = "admin";
const DEFAULT_ADMIN_PASSWORD = "secret";
const AUTH_ITERATIONS = 120_000;
const AUTH_DIGEST = "sha256";
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours
const LAUNCHER_OWNER = "LexLeethor";
const LAUNCHER_REPO = "CBGames-Offline-Launcher";
const LAUNCHER_CACHE_DIR_NAME = "launcher";
const LAUNCHER_CACHE_FILE_NAME = "launcher.json";
const LAUNCHER_REFRESH_MS = 60 * 60 * 1000; // 1 hour

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
  res.setHeader("Access-Control-Allow-Methods", "GET,HEAD,PUT,POST,PATCH,DELETE,OPTIONS");
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

function parseCookies(req) {
  const header = String(req.headers.cookie || "");
  if (!header) {
    return {};
  }
  const out = {};
  const parts = header.split(";");
  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed) {
      continue;
    }
    const eq = trimmed.indexOf("=");
    if (eq === -1) {
      continue;
    }
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    if (key) {
      out[key] = decodeURIComponent(value);
    }
  }
  return out;
}

function hashPassword(password, salt, iterations, digest) {
  return pbkdf2Sync(password, salt, iterations, 32, digest).toString("base64");
}

function createAuthRecord(username, password) {
  const salt = randomBytes(16).toString("base64");
  const iterations = AUTH_ITERATIONS;
  const digest = AUTH_DIGEST;
  const hash = hashPassword(password, salt, iterations, digest);
  return { username, salt, iterations, digest, hash };
}

function verifyPassword(password, record) {
  if (!record || !record.salt || !record.hash) {
    return false;
  }
  const hash = hashPassword(
    String(password || ""),
    String(record.salt),
    Number(record.iterations) || AUTH_ITERATIONS,
    String(record.digest || AUTH_DIGEST)
  );
  const left = Buffer.from(hash);
  const right = Buffer.from(String(record.hash || ""));
  if (left.length !== right.length) {
    return false;
  }
  return timingSafeEqual(left, right);
}

function formatCookie(name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (typeof options.maxAge === "number") {
    parts.push(`Max-Age=${options.maxAge}`);
  }
  if (options.path) {
    parts.push(`Path=${options.path}`);
  }
  if (options.httpOnly) {
    parts.push("HttpOnly");
  }
  if (options.sameSite) {
    parts.push(`SameSite=${options.sameSite}`);
  }
  if (options.secure) {
    parts.push("Secure");
  }
  return parts.join("; ");
}

function readJsonBody(req, maxBytes = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        const error = new Error("Request body too large.");
        error.code = "PAYLOAD_TOO_LARGE";
        reject(error);
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("error", reject);
    req.on("end", () => {
      if (!chunks.length) {
        resolve({});
        return;
      }
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        const parsed = JSON.parse(raw);
        resolve(parsed && typeof parsed === "object" ? parsed : {});
      } catch (error) {
        reject(new Error("Invalid JSON body."));
      }
    });
  });
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
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>CBGames Launcher Host</title>
  <style>
    :root {
      color-scheme: dark;
      font-family: "Segoe UI", Tahoma, sans-serif;
      --bg-0: #0f0f0f;
      --bg-1: #121212;
      --bg-2: #171717;
      --card: #171717;
      --border: #2f2f2f;
      --muted: #c8c8c8;
      --text: #f4f4f4;
      --accent: #8dc4ff;
      --accent-2: #a9e7ac;
      --danger: #ffb0b0;
      --warning: #e0d5b6;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background: linear-gradient(180deg, #101010 0%, #0b0b0b 100%);
      color: var(--text);
    }
    header.topbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 18px 24px;
      border-bottom: 1px solid #2a2a2a;
      background: linear-gradient(90deg, #171717, #141414);
      position: sticky;
      top: 0;
      z-index: 5;
      backdrop-filter: blur(6px);
    }
    .brand {
      display: flex;
      gap: 12px;
      align-items: center;
    }
    .brand-badge {
      width: 40px;
      height: 40px;
      border-radius: 12px;
      background: #0f0f0f;
      border: 1px solid #2f2f2f;
      display: grid;
      place-items: center;
    }
    .brand-badge img {
      width: 28px;
      height: 28px;
      object-fit: contain;
      display: block;
    }
    .brand-title {
      font-size: 16px;
      font-weight: 600;
      margin: 0;
    }
    .brand-sub {
      color: var(--muted);
      font-size: 12px;
    }
    .nav {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }
    .nav button {
      border: 1px solid #2f2f2f;
      background: #1e1e1e;
      color: #d0d0d0;
      padding: 8px 12px;
      border-radius: 10px;
      font-size: 12px;
      cursor: pointer;
      transition: all 0.2s ease;
    }
    .nav button:hover {
      border-color: #5f5f5f;
      color: #ffffff;
    }
    .nav button.active {
      background: #232323;
      border-color: #5f5f5f;
      color: #ffffff;
      box-shadow: 0 0 0 1px rgba(141,196,255,0.35) inset;
    }
    main.layout {
      max-width: 1100px;
      margin: 0 auto;
      padding: 24px;
      display: grid;
      gap: 18px;
    }
    .page {
      display: grid;
      gap: 18px;
    }
    .card {
      border: 1px solid var(--border);
      border-radius: 16px;
      background: var(--card);
      padding: 18px;
      display: grid;
      gap: 12px;
      box-shadow: 0 18px 36px rgba(0,0,0,0.35);
    }
    .card-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }
    h1, h2 {
      margin: 0;
      font-weight: 600;
    }
    h2 { font-size: 16px; }
    p {
      margin: 0;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
    }
    .row {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
    }
    input[type="file"],
    input[type="text"],
    input[type="password"],
    select,
    button,
    .button {
      min-height: 40px;
      border-radius: 12px;
      border: 1px solid #3a3a3a;
      background: #121212;
      color: #f2f2f2;
      padding: 0 12px;
      font-size: 13px;
    }
    button, .button {
      cursor: pointer;
      background: #1e1e1e;
      transition: all 0.2s ease;
    }
    button:hover, .button:hover {
      border-color: #5f5f5f;
      color: #ffffff;
    }
    .button {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      text-decoration: none;
    }
    code {
      font-family: "Consolas", "SFMono-Regular", monospace;
      background: #0e0e0e;
      border: 1px solid #2f2f2f;
      padding: 2px 6px;
      border-radius: 8px;
      word-break: break-all;
    }
    .url-list {
      display: grid;
      gap: 6px;
    }
    .url-list a {
      color: var(--accent);
      text-decoration: none;
      font-size: 13px;
    }
    .status {
      color: #d0d0d0;
      min-height: 18px;
      font-size: 13px;
    }
    .status.error { color: var(--danger); }
    .status.success { color: var(--accent-2); }
    .status.warn { color: var(--warning); }
    .hidden { display: none !important; }
    .stat-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 12px;
    }
    .stat {
      padding: 12px;
      border-radius: 12px;
      border: 1px solid #2e2e2e;
      background: #121212;
    }
    .stat-label {
      color: var(--muted);
      font-size: 12px;
    }
    .stat-value {
      font-size: 20px;
      font-weight: 600;
      margin-top: 4px;
    }
    .items {
      display: grid;
      gap: 10px;
      max-height: 420px;
      overflow: auto;
      border: 1px solid #2e2e2e;
      border-radius: 14px;
      padding: 10px;
      background: #121212;
    }
    .item {
      display: grid;
      grid-template-columns: 1fr auto auto;
      gap: 10px;
      align-items: center;
      border: 1px solid #282828;
      border-radius: 12px;
      background: #151515;
      padding: 10px 12px;
      font-size: 13px;
    }
    .item-meta strong {
      display: block;
      font-size: 13px;
      color: #f0f4fb;
    }
    .item-meta small {
      display: block;
      color: #bcbcbc;
      margin-top: 2px;
    }
    .item a {
      color: var(--accent);
      text-decoration: none;
      font-size: 12px;
    }
    .item-actions {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
      justify-content: flex-end;
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
    .meta-row {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      align-items: center;
      font-size: 13px;
      color: var(--muted);
    }
    .section-note {
      font-size: 12px;
      color: var(--muted);
    }
  </style>
</head>
<body>
  <header class="topbar">
    <div class="brand">
      <div class="brand-badge">
        <img alt="CB" src="data:image/png;base64,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"/>
      </div>
      <div>
        <div class="brand-title">CBGames Host</div>
        <div class="brand-sub">Launcher library & distribution</div>
      </div>
    </div>
    <nav class="nav">
      <button data-nav="dashboard">Dashboard</button>
      <button data-nav="bundles">Bundles</button>
      <button data-nav="launcher">Launcher</button>
      <button data-nav="account" class="requires-auth hidden">Account</button>
      <button data-nav="signin" class="requires-anon">Sign In</button>
    </nav>
  </header>

  <main class="layout">
    <section class="page" data-page="dashboard">
      <div class="card">
        <div class="card-head">
          <h2>Host Status</h2>
          <span id="statusLine" class="status"></span>
        </div>
        <div class="stat-grid">
          <div class="stat">
            <div class="stat-label">Hosted items</div>
            <div id="statTotal" class="stat-value">0</div>
          </div>
          <div class="stat">
            <div class="stat-label">Shared items</div>
            <div id="statShared" class="stat-value">0</div>
          </div>
          <div class="stat">
            <div class="stat-label">Private items</div>
            <div id="statPrivate" class="stat-value">0</div>
          </div>
          <div class="stat">
            <div class="stat-label">Storage used</div>
            <div id="statStorage" class="stat-value">0 B</div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <h2>Host URLs</h2>
          <span class="section-note">Share the manifest URL with clients.</span>
        </div>
        <div id="hostUrls" class="url-list"></div>
        <div class="meta-row">Manifest: <code id="manifestEndpoint">/api/manifest</code></div>
        <div class="meta-row">OTC Upload: <code>/api/client-upload?otc=CODE</code></div>
      </div>
    </section>

    <section class="page hidden" data-page="bundles">
      <div class="card requires-auth hidden">
        <div class="card-head">
          <h2>Upload Bundle</h2>
          <span class="section-note">Admins can upload ZIPs directly to the host.</span>
        </div>
        <div class="row">
          <input id="uploadFile" type="file" accept=".zip,application/zip">
          <input id="uploadName" type="text" placeholder="Optional display name">
          <select id="uploadType">
            <option value="bundle">Bundle ZIP</option>
            <option value="zip">Game ZIP</option>
          </select>
          <select id="uploadShared">
            <option value="shared">Shared</option>
            <option value="private">Private</option>
          </select>
          <button id="uploadBtn">Upload</button>
        </div>
        <p id="uploadStatus" class="status"></p>
      </div>

      <div class="card">
        <div class="card-head">
          <h2>Hosted Files</h2>
          <span class="section-note">Sign in to rename, share, or delete items.</span>
        </div>
        <div id="itemsList" class="items"></div>
      </div>
    </section>

    <section class="page hidden" data-page="launcher">
      <div class="card">
        <div class="card-head">
          <h2>Launcher Download</h2>
          <button id="launcherSyncBtn" class="requires-auth hidden">Check For Updates</button>
        </div>
        <p id="launcherStatus" class="status"></p>
        <div class="stat-grid">
          <div class="stat">
            <div class="stat-label">Version</div>
            <div id="launcherVersion" class="stat-value">-</div>
          </div>
          <div class="stat">
            <div class="stat-label">Asset</div>
            <div id="launcherAsset" class="stat-value">-</div>
          </div>
          <div class="stat">
            <div class="stat-label">Size</div>
            <div id="launcherSize" class="stat-value">-</div>
          </div>
          <div class="stat">
            <div class="stat-label">Last checked</div>
            <div id="launcherChecked" class="stat-value">-</div>
          </div>
        </div>
        <div class="row">
          <a id="launcherDownloadLink" class="button" href="/download/launcher">Download Launcher</a>
        </div>
      </div>
    </section>

    <section class="page hidden" data-page="account">
      <div class="card">
        <h2>Account Settings</h2>
        <p class="section-note">Update your admin username and password.</p>
        <div class="row">
          <input id="newUsername" type="text" placeholder="New username">
          <input id="usernamePassword" type="password" placeholder="Current password">
          <button id="changeUsernameBtn">Change Username</button>
        </div>
        <p id="usernameStatus" class="status"></p>
      </div>

      <div class="card">
        <h2>Change Password</h2>
        <div class="row">
          <input id="currentPassword" type="password" placeholder="Current password" autocomplete="current-password">
          <input id="newPassword" type="password" placeholder="New password" autocomplete="new-password">
          <button id="changePasswordBtn">Change Password</button>
          <button id="logoutBtn" class="requires-auth hidden">Sign Out</button>
        </div>
        <p id="passwordStatus" class="status"></p>
      </div>
    </section>

    <section class="page hidden" data-page="signin">
      <div class="card">
        <h2>Admin Sign In</h2>
        <p>Use your admin credentials to manage bundles and launcher updates.</p>
        <div class="row">
          <input id="loginUser" type="text" placeholder="Username" autocomplete="username">
          <input id="loginPass" type="password" placeholder="Password" autocomplete="current-password">
          <button id="loginBtn">Sign In</button>
        </div>
        <p id="authStatus" class="status"></p>
      </div>
    </section>
  </main>

  <script>
    const hostUrls = document.getElementById("hostUrls");
    const manifestEndpoint = document.getElementById("manifestEndpoint");
    const statusLine = document.getElementById("statusLine");
    const itemsList = document.getElementById("itemsList");
    const loginUser = document.getElementById("loginUser");
    const loginPass = document.getElementById("loginPass");
    const loginBtn = document.getElementById("loginBtn");
    const logoutBtn = document.getElementById("logoutBtn");
    const authStatus = document.getElementById("authStatus");
    const uploadFile = document.getElementById("uploadFile");
    const uploadName = document.getElementById("uploadName");
    const uploadType = document.getElementById("uploadType");
    const uploadShared = document.getElementById("uploadShared");
    const uploadBtn = document.getElementById("uploadBtn");
    const uploadStatus = document.getElementById("uploadStatus");
    const currentPassword = document.getElementById("currentPassword");
    const newPassword = document.getElementById("newPassword");
    const changePasswordBtn = document.getElementById("changePasswordBtn");
    const passwordStatus = document.getElementById("passwordStatus");
    const newUsername = document.getElementById("newUsername");
    const usernamePassword = document.getElementById("usernamePassword");
    const changeUsernameBtn = document.getElementById("changeUsernameBtn");
    const usernameStatus = document.getElementById("usernameStatus");
    const launcherStatus = document.getElementById("launcherStatus");
    const launcherVersion = document.getElementById("launcherVersion");
    const launcherAsset = document.getElementById("launcherAsset");
    const launcherSize = document.getElementById("launcherSize");
    const launcherChecked = document.getElementById("launcherChecked");
    const launcherDownloadLink = document.getElementById("launcherDownloadLink");
    const launcherSyncBtn = document.getElementById("launcherSyncBtn");
    const statTotal = document.getElementById("statTotal");
    const statShared = document.getElementById("statShared");
    const statPrivate = document.getElementById("statPrivate");
    const statStorage = document.getElementById("statStorage");

    const pages = Array.from(document.querySelectorAll("[data-page]"));
    const navButtons = Array.from(document.querySelectorAll("[data-nav]"));

    let currentItems = [];
    let authState = { ok: false, username: "" };

    function setStatus(target, message, tone) {
      const el = target || statusLine;
      if (!el) {
        return;
      }
      el.textContent = String(message || "").trim();
      el.classList.toggle("error", tone === "error");
      el.classList.toggle("success", tone === "success");
      el.classList.toggle("warn", tone === "warn");
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

    function showPage(page) {
      pages.forEach((section) => {
        section.classList.toggle("hidden", section.dataset.page !== page);
      });
      navButtons.forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.nav === page);
      });
      const pathMap = {
        dashboard: "/",
        bundles: "/bundles",
        launcher: "/launcher",
        account: "/account",
        signin: "/signin"
      };
      const targetPath = pathMap[page] || "/";
      if (window.location.pathname !== targetPath) {
        window.history.pushState({}, "", targetPath);
      }
    }

    function setAuthVisibility(isAuthed) {
      document.querySelectorAll(".requires-auth").forEach((el) => {
        el.classList.toggle("hidden", !isAuthed);
      });
      document.querySelectorAll(".requires-anon").forEach((el) => {
        el.classList.toggle("hidden", isAuthed);
      });
      if (!isAuthed && window.location.pathname === "/account") {
        showPage("signin");
      }
    }

    async function checkAuth() {
      const payload = await api("/api/me");
      authState = payload && payload.authenticated
        ? { ok: true, username: payload.username || "" }
        : { ok: false, username: "" };
      setAuthVisibility(authState.ok);
      renderItems();
      if (authState.ok) {
        setStatus(authStatus, "Signed in as " + authState.username + ".", "success");
      } else {
        setStatus(authStatus, "Not signed in.", "");
      }
      return authState;
    }

    function renderHostUrls(info) {
      hostUrls.innerHTML = "";
      const urls = Array.isArray(info && info.urls) ? info.urls : [];
      for (const url of urls) {
        const row = document.createElement("div");
        const link = document.createElement("a");
        link.href = url;
        link.textContent = url;
        link.target = "_blank";
        link.rel = "noreferrer noopener";
        row.append(link);
        hostUrls.append(row);
      }
      manifestEndpoint.textContent = (urls[0] || window.location.origin) + "/api/manifest";
    }

    function updateStats() {
      const total = currentItems.length;
      const shared = currentItems.filter((item) => item.shared).length;
      const privateCount = total - shared;
      const totalBytes = currentItems.reduce((sum, item) => sum + Number(item.size || 0), 0);
      statTotal.textContent = total;
      statShared.textContent = shared;
      statPrivate.textContent = privateCount;
      statStorage.textContent = formatBytes(totalBytes);
    }

    function renderItems() {
      itemsList.innerHTML = "";
      if (!currentItems.length) {
        const empty = document.createElement("p");
        empty.className = "section-note";
        empty.textContent = "No hosted files yet.";
        itemsList.append(empty);
        updateStats();
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
        download.target = "_blank";
        download.rel = "noreferrer noopener";

        if (authState.ok) {
          const actions = document.createElement("div");
          actions.className = "item-actions";

          const renameBtn = document.createElement("button");
          renameBtn.textContent = "Rename";
          renameBtn.addEventListener("click", async () => {
            const nextName = prompt("New file name (.zip will be added if missing):", item.name);
            if (!nextName) {
              return;
            }
            try {
              await api("/api/items/" + encodeURIComponent(item.id), {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ name: nextName })
              });
              await loadItems();
            } catch (error) {
              setStatus(statusLine, error.message || String(error), "error");
            }
          });

          const shareBtn = document.createElement("button");
          shareBtn.textContent = item.shared ? "Make Private" : "Make Shared";
          shareBtn.addEventListener("click", async () => {
            try {
              await api("/api/items/" + encodeURIComponent(item.id), {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ shared: !item.shared })
              });
              await loadItems();
            } catch (error) {
              setStatus(statusLine, error.message || String(error), "error");
            }
          });

          const deleteBtn = document.createElement("button");
          deleteBtn.textContent = "Delete";
          deleteBtn.addEventListener("click", async () => {
            if (!confirm("Delete " + item.name + "? This cannot be undone.")) {
              return;
            }
            try {
              await api("/api/items/" + encodeURIComponent(item.id), {
                method: "DELETE"
              });
              await loadItems();
            } catch (error) {
              setStatus(statusLine, error.message || String(error), "error");
            }
          });

          actions.append(renameBtn, shareBtn, deleteBtn);
          row.style.gridTemplateColumns = "1fr auto auto auto";
          row.append(meta, visibility, download, actions);
        } else {
          row.append(meta, visibility, download);
        }
        itemsList.append(row);
      }
      updateStats();
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

    async function loadLauncherInfo(force) {
      try {
        const payload = force
          ? await api("/api/launcher/sync", { method: "POST" })
          : await api("/api/launcher");
        if (!payload.available) {
          setStatus(launcherStatus, payload.error || "Launcher not ready yet.", payload.error ? "error" : "warn");
          launcherDownloadLink.classList.add("hidden");
        } else {
          setStatus(launcherStatus, "Launcher ready for download.", "success");
          launcherDownloadLink.classList.remove("hidden");
        }
        launcherVersion.textContent = payload.release?.tagName || payload.release?.name || "-";
        launcherAsset.textContent = payload.asset?.name || "-";
        launcherSize.textContent = payload.asset?.size ? formatBytes(payload.asset.size) : "-";
        launcherChecked.textContent = payload.checkedAt
          ? new Date(payload.checkedAt).toLocaleString()
          : "-";
      } catch (error) {
        setStatus(launcherStatus, error.message || String(error), "error");
        launcherDownloadLink.classList.add("hidden");
      }
    }

    navButtons.forEach((button) => {
      button.addEventListener("click", () => {
        showPage(button.dataset.nav);
      });
    });

    loginBtn.addEventListener("click", async () => {
      try {
        const payload = await api("/api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            username: loginUser.value,
            password: loginPass.value
          })
        });
        authState = { ok: true, username: payload.username || loginUser.value };
        setAuthVisibility(true);
        loginPass.value = "";
        setStatus(authStatus, "Signed in as " + authState.username + ".", "success");
        await loadItems();
        showPage("dashboard");
      } catch (error) {
        setStatus(authStatus, error.message || String(error), "error");
      }
    });

    logoutBtn.addEventListener("click", async () => {
      try {
        await api("/api/logout", { method: "POST" });
      } catch (error) {
        setStatus(authStatus, error.message || String(error), "error");
      }
      authState = { ok: false, username: "" };
      setAuthVisibility(false);
      setStatus(authStatus, "Signed out.", "");
      await loadItems();
      showPage("signin");
    });

    uploadBtn.addEventListener("click", async () => {
      try {
        const file = uploadFile.files[0];
        if (!file) {
          setStatus(uploadStatus, "Pick a ZIP file first.", "error");
          return;
        }
        const params = new URLSearchParams();
        if (uploadName.value.trim()) {
          params.set("name", uploadName.value.trim());
        } else {
          params.set("name", file.name || "upload.zip");
        }
        params.set("type", uploadType.value || "bundle");
        params.set("shared", uploadShared.value === "shared" ? "true" : "false");
        setStatus(uploadStatus, "Uploading...", "");
        await api("/api/upload?" + params.toString(), {
          method: "PUT",
          body: file
        });
        uploadFile.value = "";
        uploadName.value = "";
        setStatus(uploadStatus, "Upload complete.", "success");
        await loadItems();
      } catch (error) {
        setStatus(uploadStatus, error.message || String(error), "error");
      }
    });

    changePasswordBtn.addEventListener("click", async () => {
      try {
        if (!currentPassword.value || !newPassword.value) {
          setStatus(passwordStatus, "Enter current and new password.", "error");
          return;
        }
        const payload = await api("/api/change-password", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            currentPassword: currentPassword.value,
            newPassword: newPassword.value
          })
        });
        currentPassword.value = "";
        newPassword.value = "";
        setStatus(passwordStatus, payload.message || "Password updated.", "success");
      } catch (error) {
        setStatus(passwordStatus, error.message || String(error), "error");
      }
    });

    changeUsernameBtn.addEventListener("click", async () => {
      try {
        if (!newUsername.value || !usernamePassword.value) {
          setStatus(usernameStatus, "Enter new username and current password.", "error");
          return;
        }
        const payload = await api("/api/change-username", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            newUsername: newUsername.value,
            currentPassword: usernamePassword.value
          })
        });
        usernamePassword.value = "";
        newUsername.value = "";
        setStatus(usernameStatus, payload.message || "Username updated.", "success");
      } catch (error) {
        setStatus(usernameStatus, error.message || String(error), "error");
      }
    });

    launcherSyncBtn.addEventListener("click", async () => {
      await loadLauncherInfo(true);
    });

    const pathToPage = {
      "/": "dashboard",
      "/bundles": "bundles",
      "/launcher": "launcher",
      "/account": "account",
      "/signin": "signin"
    };
    const initialPage = pathToPage[window.location.pathname] || "dashboard";
    showPage(initialPage);

    Promise.all([loadInfo(), checkAuth(), loadItems(), loadLauncherInfo(false)])
      .then(() => setStatus(statusLine, "Host ready.", "success"))
      .catch((error) => setStatus(statusLine, error.message || String(error), "error"));
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
const authPath = path.join(storeDir, AUTH_FILE_NAME);
const launcherDir = path.join(storeDir, LAUNCHER_CACHE_DIR_NAME);
const launcherCachePath = path.join(launcherDir, LAUNCHER_CACHE_FILE_NAME);

let library = {
  format: APP_ID,
  updatedAt: Date.now(),
  items: []
};

let activeUploadCode = null;
let authRecord = null;
const sessions = new Map();
let launcherCache = {
  checkedAt: 0,
  etag: "",
  release: null,
  asset: null,
  fileName: ""
};

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

async function saveAuthRecord() {
  if (!authRecord) {
    return;
  }
  const payload = JSON.stringify(authRecord, null, 2);
  const tempPath = authPath + ".tmp";
  await fsp.writeFile(tempPath, payload, "utf8");
  await fsp.rename(tempPath, authPath);
}

async function loadAuthRecord() {
  try {
    const raw = await fsp.readFile(authPath, "utf8");
    const parsed = JSON.parse(raw);
    if (!parsed || !parsed.username || !parsed.hash || !parsed.salt) {
      throw new Error("Invalid auth record.");
    }
    authRecord = {
      username: String(parsed.username || DEFAULT_ADMIN_USER),
      salt: String(parsed.salt),
      iterations: Number(parsed.iterations) || AUTH_ITERATIONS,
      digest: String(parsed.digest || AUTH_DIGEST),
      hash: String(parsed.hash)
    };
  } catch (error) {
    if (error && error.code !== "ENOENT") {
      console.warn("Could not read auth record, resetting to default:", error.message || String(error));
    }
    authRecord = createAuthRecord(DEFAULT_ADMIN_USER, DEFAULT_ADMIN_PASSWORD);
    await saveAuthRecord();
  }
}

async function ensureLauncherStore() {
  await fsp.mkdir(launcherDir, { recursive: true });
}

async function loadLauncherCache() {
  try {
    const raw = await fsp.readFile(launcherCachePath, "utf8");
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") {
      throw new Error("Invalid launcher cache.");
    }
    launcherCache = {
      checkedAt: Number(parsed.checkedAt) || 0,
      etag: String(parsed.etag || ""),
      release: parsed.release || null,
      asset: parsed.asset || null,
      fileName: String(parsed.fileName || "")
    };
  } catch (error) {
    if (error && error.code !== "ENOENT") {
      console.warn("Could not read launcher cache, starting empty:", error.message || String(error));
    }
    launcherCache = {
      checkedAt: 0,
      etag: "",
      release: null,
      asset: null,
      fileName: ""
    };
  }
}

async function saveLauncherCache() {
  const payload = JSON.stringify(launcherCache, null, 2);
  const tempPath = launcherCachePath + ".tmp";
  await fsp.writeFile(tempPath, payload, "utf8");
  await fsp.rename(tempPath, launcherCachePath);
}

function createSession(username) {
  const token = randomBytes(24).toString("base64url");
  const expiresAt = Date.now() + SESSION_TTL_MS;
  sessions.set(token, { username, expiresAt });
  return { token, expiresAt };
}

function getSession(req) {
  const cookies = parseCookies(req);
  const token = cookies.launcher_auth;
  if (!token) {
    return null;
  }
  const session = sessions.get(token);
  if (!session) {
    return null;
  }
  if (Date.now() >= session.expiresAt) {
    sessions.delete(token);
    return null;
  }
  return { token, ...session };
}

function requireAuth(req, res) {
  const session = getSession(req);
  if (!session) {
    sendJson(res, 401, { error: "Sign in required." });
    return null;
  }
  return session;
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

async function removeFileSafe(targetPath) {
  if (!targetPath) {
    return;
  }
  try {
    await fsp.unlink(targetPath);
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

async function updateItem(itemId, changes) {
  const normalizedId = String(itemId || "").trim();
  if (!normalizedId) {
    throw new Error("Missing item id.");
  }
  const item = getItemById(normalizedId);
  if (!item) {
    throw new Error("Item not found: " + normalizedId);
  }
  if (Object.prototype.hasOwnProperty.call(changes, "name")) {
    item.name = sanitizeZipName(changes.name || "");
  }
  if (Object.prototype.hasOwnProperty.call(changes, "shared")) {
    item.shared = Boolean(changes.shared);
  }
  if (Object.prototype.hasOwnProperty.call(changes, "type")) {
    item.type = normalizeZipType(changes.type);
  }
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
await loadAuthRecord();
await ensureLauncherStore();
await loadLauncherCache();
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

    if (method === "GET" && ["/", "/bundles", "/launcher", "/account", "/signin"].includes(pathname)) {
      sendHtml(res, 200, createHostPage());
      return;
    }

    if (method === "GET" && pathname === "/api/info") {
      sendJson(res, 200, getInfoPayload());
      return;
    }

    if (method === "GET" && pathname === "/api/launcher") {
      const info = await getLauncherInfo(false);
      sendJson(res, 200, {
        available: Boolean(info.asset && info.fileName),
        checkedAt: info.checkedAt,
        release: info.release,
        asset: info.asset,
        downloadPath: "/download/launcher",
        error: info.error || ""
      });
      return;
    }

    if (method === "POST" && pathname === "/api/launcher/sync") {
      const session = requireAuth(req, res);
      if (!session) {
        return;
      }
      const info = await getLauncherInfo(true);
      sendJson(res, 200, {
        available: Boolean(info.asset && info.fileName),
        checkedAt: info.checkedAt,
        release: info.release,
        asset: info.asset,
        downloadPath: "/download/launcher",
        error: info.error || ""
      });
      return;
    }

    if (method === "GET" && pathname === "/api/me") {
      const session = getSession(req);
      sendJson(res, 200, {
        authenticated: Boolean(session),
        username: session ? session.username : ""
      });
      return;
    }

    if (method === "POST" && pathname === "/api/login") {
      try {
        const body = await readJsonBody(req, 128 * 1024);
        const username = String(body.username || "").trim();
        const password = String(body.password || "");
        if (!username || !password) {
          sendJson(res, 400, { error: "Username and password are required." });
          return;
        }
        if (!authRecord || username !== authRecord.username) {
          sendJson(res, 401, { error: "Invalid username or password." });
          return;
        }
        if (!verifyPassword(password, authRecord)) {
          sendJson(res, 401, { error: "Invalid username or password." });
          return;
        }
        const session = createSession(authRecord.username);
        res.setHeader(
          "Set-Cookie",
          formatCookie("launcher_auth", session.token, {
            path: "/",
            maxAge: Math.round(SESSION_TTL_MS / 1000),
            httpOnly: true,
            sameSite: "Lax"
          })
        );
        sendJson(res, 200, {
          ok: true,
          username: authRecord.username,
          expiresAt: session.expiresAt
        });
        return;
      } catch (error) {
        if (error && error.code === "PAYLOAD_TOO_LARGE") {
          sendJson(res, 413, { error: error.message || "Request body too large." });
          return;
        }
        sendJson(res, 400, { error: error && error.message ? error.message : "Login failed." });
        return;
      }
    }

    if (method === "POST" && pathname === "/api/logout") {
      const session = getSession(req);
      if (session) {
        sessions.delete(session.token);
      }
      res.setHeader(
        "Set-Cookie",
        formatCookie("launcher_auth", "", {
          path: "/",
          maxAge: 0,
          httpOnly: true,
          sameSite: "Lax"
        })
      );
      sendJson(res, 200, { ok: true });
      return;
    }

    if (method === "POST" && pathname === "/api/change-password") {
      const session = requireAuth(req, res);
      if (!session) {
        return;
      }
      try {
        const body = await readJsonBody(req, 128 * 1024);
        const currentPassword = String(body.currentPassword || "");
        const nextPassword = String(body.newPassword || "");
        if (!verifyPassword(currentPassword, authRecord)) {
          sendJson(res, 401, { error: "Current password is incorrect." });
          return;
        }
        if (nextPassword.length < 6) {
          sendJson(res, 400, { error: "New password must be at least 6 characters." });
          return;
        }
        authRecord = createAuthRecord(authRecord.username, nextPassword);
        await saveAuthRecord();
        sessions.clear();
        const fresh = createSession(authRecord.username);
        res.setHeader(
          "Set-Cookie",
          formatCookie("launcher_auth", fresh.token, {
            path: "/",
            maxAge: Math.round(SESSION_TTL_MS / 1000),
            httpOnly: true,
            sameSite: "Lax"
          })
        );
        sendJson(res, 200, { ok: true, message: "Password updated." });
        return;
      } catch (error) {
        if (error && error.code === "PAYLOAD_TOO_LARGE") {
          sendJson(res, 413, { error: error.message || "Request body too large." });
          return;
        }
        sendJson(res, 400, { error: error && error.message ? error.message : "Password update failed." });
        return;
      }
    }

    if (method === "POST" && pathname === "/api/change-username") {
      const session = requireAuth(req, res);
      if (!session) {
        return;
      }
      try {
        const body = await readJsonBody(req, 128 * 1024);
        const currentPassword = String(body.currentPassword || "");
        const nextUsername = String(body.newUsername || "").trim();
        if (!verifyPassword(currentPassword, authRecord)) {
          sendJson(res, 401, { error: "Current password is incorrect." });
          return;
        }
        if (nextUsername.length < 3) {
          sendJson(res, 400, { error: "Username must be at least 3 characters." });
          return;
        }
        authRecord.username = nextUsername;
        await saveAuthRecord();
        sessions.clear();
        const fresh = createSession(authRecord.username);
        res.setHeader(
          "Set-Cookie",
          formatCookie("launcher_auth", fresh.token, {
            path: "/",
            maxAge: Math.round(SESSION_TTL_MS / 1000),
            httpOnly: true,
            sameSite: "Lax"
          })
        );
        sendJson(res, 200, { ok: true, message: "Username updated.", username: authRecord.username });
        return;
      } catch (error) {
        if (error && error.code === "PAYLOAD_TOO_LARGE") {
          sendJson(res, 413, { error: error.message || "Request body too large." });
          return;
        }
        sendJson(res, 400, { error: error && error.message ? error.message : "Username update failed." });
        return;
      }
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
      const session = requireAuth(req, res);
      if (!session) {
        return;
      }
      const rawName = String(url.searchParams.get("name") || "").trim() || "upload.zip";
      const itemType = normalizeZipType(url.searchParams.get("type") || "bundle");
      const shared = parseBoolean(url.searchParams.get("shared"), true);
      try {
        const item = await storeUploadedZip(req, {
          name: rawName,
          type: itemType,
          shared
        });
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
      return;
    }

    if (method === "PUT" && pathname === "/api/client-upload") {
      await handleClientUpload(req, res, url);
      return;
    }

    const apiItemMatch = pathname.match(/^\/api\/items\/([^/]+)$/);
    if (apiItemMatch) {
      const itemId = decodeURIComponent(apiItemMatch[1]);
      if (method === "PATCH") {
        const session = requireAuth(req, res);
        if (!session) {
          return;
        }
        try {
          const body = await readJsonBody(req, 128 * 1024);
          const updated = await updateItem(itemId, body || {});
          sendJson(res, 200, { item: toPublicItem(updated) });
        } catch (error) {
          if (error && error.code === "PAYLOAD_TOO_LARGE") {
            sendJson(res, 413, { error: error.message || "Request body too large." });
            return;
          }
          sendJson(res, 400, { error: error && error.message ? error.message : "Update failed." });
        }
        return;
      }
      if (method === "DELETE") {
        const session = requireAuth(req, res);
        if (!session) {
          return;
        }
        try {
          const removed = await deleteItem(itemId);
          sendJson(res, 200, { item: toPublicItem(removed) });
        } catch (error) {
          sendJson(res, 400, { error: error && error.message ? error.message : "Delete failed." });
        }
        return;
      }
    }

    const downloadMatch = pathname.match(/^\/download\/([^/]+)$/);
    if (downloadMatch && (method === "GET" || method === "HEAD")) {
      if (downloadMatch[1] === "launcher") {
        const headOnly = method === "HEAD";
        const info = await getLauncherInfo(false);
        if (!info.asset || !info.fileName) {
          sendJson(res, 404, { error: info.error || "Launcher is not available yet." });
          return;
        }
        const filePath = path.join(launcherDir, info.fileName);
        let stat;
        try {
          stat = await fsp.stat(filePath);
        } catch (error) {
          sendJson(res, 404, { error: "Launcher file is missing." });
          return;
        }
        setCorsHeaders(res);
        res.statusCode = 200;
        const contentType = info.asset.contentType ||
          (info.fileName.endsWith(".zip")
            ? "application/zip"
            : info.fileName.endsWith(".exe")
              ? "application/vnd.microsoft.portable-executable"
              : info.fileName.endsWith(".msi")
                ? "application/x-msi"
                : "application/octet-stream");
        res.setHeader("Content-Type", contentType);
        res.setHeader("Content-Length", String(stat.size));
        res.setHeader(
          "Content-Disposition",
          'attachment; filename="' + escapeHtml(info.asset.name || info.fileName) + '"'
        );
        if (headOnly) {
          res.end();
          return;
        }
        fs.createReadStream(filePath).pipe(res);
        return;
      }
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

function sanitizeFileName(rawName, fallback) {
  let name = String(rawName || "").trim();
  name = name.replace(/[\\/:*?"<>|]+/g, "-");
  name = name.replace(/\s+/g, " ").trim();
  if (!name) {
    name = fallback || "download.bin";
  }
  return name;
}

function httpsGet(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const request = https.request(
      {
        method: "GET",
        hostname: target.hostname,
        path: target.pathname + target.search,
        headers
      },
      (res) => resolve(res)
    );
    request.on("error", reject);
    request.end();
  });
}

async function fetchJsonWithRedirects(url, headers = {}, maxRedirects = 3) {
  const response = await httpsGet(url, headers);
  if ([301, 302, 303, 307, 308].includes(response.statusCode) && response.headers.location) {
    if (maxRedirects <= 0) {
      throw new Error("Too many redirects.");
    }
    response.resume();
    return fetchJsonWithRedirects(response.headers.location, headers, maxRedirects - 1);
  }
  const status = response.statusCode || 0;
  const chunks = [];
  let size = 0;
  response.on("data", (chunk) => {
    size += chunk.length;
    if (size > 2 * 1024 * 1024) {
      response.destroy();
    }
    chunks.push(chunk);
  });
  const body = await new Promise((resolve, reject) => {
    response.on("error", reject);
    response.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });
  return { status, headers: response.headers, body };
}

async function downloadFileWithRedirects(url, targetPath, headers = {}, maxRedirects = 3) {
  const response = await httpsGet(url, headers);
  if ([301, 302, 303, 307, 308].includes(response.statusCode) && response.headers.location) {
    if (maxRedirects <= 0) {
      throw new Error("Too many redirects.");
    }
    response.resume();
    return downloadFileWithRedirects(response.headers.location, targetPath, headers, maxRedirects - 1);
  }
  if (response.statusCode && response.statusCode >= 400) {
    response.resume();
    throw new Error("Download failed with HTTP " + response.statusCode + ".");
  }
  await new Promise((resolve, reject) => {
    const tempPath = targetPath + ".tmp";
    const output = fs.createWriteStream(tempPath, { flags: "w" });
    response.pipe(output);
    response.on("error", reject);
    output.on("error", reject);
    output.on("finish", async () => {
      try {
        await fsp.rename(tempPath, targetPath);
        resolve();
      } catch (error) {
        reject(error);
      }
    });
  });
}

async function refreshLauncherCache(force = false) {
  const now = Date.now();
  if (!force && launcherCache.asset && now - launcherCache.checkedAt < LAUNCHER_REFRESH_MS) {
    return launcherCache;
  }
  await ensureLauncherStore();
  const apiBase = `https://api.github.com/repos/${LAUNCHER_OWNER}/${LAUNCHER_REPO}`;
  const headers = {
    "User-Agent": "cbgames-launcher-host",
    "Accept": "application/vnd.github+json"
  };
  if (launcherCache.etag) {
    headers["If-None-Match"] = launcherCache.etag;
  }
  const latestResponse = await fetchJsonWithRedirects(apiBase + "/releases/latest", headers);
  if (latestResponse.status === 304) {
    launcherCache.checkedAt = now;
    await saveLauncherCache();
    return launcherCache;
  }

  let payload = null;
  let responseHeaders = {};
  if (latestResponse.status === 404) {
    const listResponse = await fetchJsonWithRedirects(apiBase + "/releases?per_page=5", headers);
    if (listResponse.status >= 200 && listResponse.status < 300) {
      const list = JSON.parse(listResponse.body || "[]");
      if (Array.isArray(list)) {
        payload = list.find((entry) => entry && !entry.draft && !entry.prerelease && Array.isArray(entry.assets) && entry.assets.length) || null;
      }
      responseHeaders = listResponse.headers || {};
    } else if (listResponse.status !== 404) {
      throw new Error("GitHub release check failed (HTTP " + listResponse.status + ").");
    }
  } else if (latestResponse.status >= 200 && latestResponse.status < 300) {
    payload = JSON.parse(latestResponse.body || "{}");
    responseHeaders = latestResponse.headers || {};
  } else {
    throw new Error("GitHub release check failed (HTTP " + latestResponse.status + ").");
  }

  if (payload) {
    const assets = Array.isArray(payload.assets) ? payload.assets : [];
    if (assets.length) {
      const asset =
        assets.find((entry) => /launcher/i.test(entry.name || "") && /\.exe$/i.test(entry.name || "")) ||
        assets.find((entry) => /launcher/i.test(entry.name || "") && /\.zip$/i.test(entry.name || "")) ||
        assets.find((entry) => /\.exe$/i.test(entry.name || "")) ||
        assets[0];
      if (asset && asset.browser_download_url) {
        const fileName = sanitizeFileName(asset.name, "launcher.bin");
        const filePath = path.join(launcherDir, fileName);
        const currentFile = launcherCache.fileName ? path.join(launcherDir, launcherCache.fileName) : "";
        const shouldDownload =
          launcherCache.asset?.browserDownloadUrl !== asset.browser_download_url ||
          !(await fsp.stat(filePath).then(() => true).catch(() => false));

        if (shouldDownload) {
          await downloadFileWithRedirects(asset.browser_download_url, filePath, {
            "User-Agent": "cbgames-launcher-host"
          });
          if (currentFile && currentFile !== filePath) {
            await removeFileSafe(currentFile);
          }
        }

        launcherCache = {
          checkedAt: now,
          etag: String(responseHeaders.etag || ""),
          release: {
            id: payload.id,
            tagName: payload.tag_name || "",
            name: payload.name || "",
            publishedAt: payload.published_at || ""
          },
          asset: {
            id: asset.id,
            name: asset.name || "",
            size: Number(asset.size) || 0,
            contentType: asset.content_type || "",
            browserDownloadUrl: asset.browser_download_url
          },
          fileName
        };
        await saveLauncherCache();
        return launcherCache;
      }
    }
  }

  const repoResponse = await fetchJsonWithRedirects(apiBase, headers);
  if (repoResponse.status < 200 || repoResponse.status >= 300) {
    throw new Error("GitHub repository check failed (HTTP " + repoResponse.status + ").");
  }
  const repo = JSON.parse(repoResponse.body || "{}");
  const defaultBranch = String(repo.default_branch || "main");
  const zipUrl = `https://api.github.com/repos/${LAUNCHER_OWNER}/${LAUNCHER_REPO}/zipball/${encodeURIComponent(defaultBranch)}`;
  const fileName = sanitizeFileName(`${LAUNCHER_REPO}-${defaultBranch}.zip`, "launcher.zip");
  const filePath = path.join(launcherDir, fileName);
  const currentFile = launcherCache.fileName ? path.join(launcherDir, launcherCache.fileName) : "";
  const shouldDownload =
    launcherCache.asset?.browserDownloadUrl !== zipUrl ||
    !(await fsp.stat(filePath).then(() => true).catch(() => false));

  if (shouldDownload) {
    await downloadFileWithRedirects(zipUrl, filePath, {
      "User-Agent": "cbgames-launcher-host",
      "Accept": "application/vnd.github+json"
    });
    if (currentFile && currentFile !== filePath) {
      await removeFileSafe(currentFile);
    }
  }

  const stat = await fsp.stat(filePath);
  launcherCache = {
    checkedAt: now,
    etag: String(repoResponse.headers.etag || ""),
    release: {
      id: repo.id || 0,
      tagName: defaultBranch,
      name: "Source archive",
      publishedAt: ""
    },
    asset: {
      id: 0,
      name: fileName,
      size: Number(stat.size) || 0,
      contentType: "application/zip",
      browserDownloadUrl: zipUrl
    },
    fileName
  };
  await saveLauncherCache();
  return launcherCache;
}

async function getLauncherInfo(force = false) {
  try {
    await refreshLauncherCache(force);
  } catch (error) {
    launcherCache.checkedAt = Date.now();
    await saveLauncherCache();
    return { ...launcherCache, error: error.message || String(error) };
  }
  return launcherCache;
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
  refreshLauncherCache(false).catch((error) => {
    console.warn("Launcher refresh failed:", error && error.message ? error.message : String(error));
  });
  setInterval(() => {
    refreshLauncherCache(false).catch((error) => {
      console.warn("Launcher refresh failed:", error && error.message ? error.message : String(error));
    });
  }, LAUNCHER_REFRESH_MS);
});
