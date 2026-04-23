const fs = require("fs");
const path = require("path");
const http = require("http");
const https = require("https");
const crypto = require("crypto");

function loadDotEnv(file = path.join(__dirname, ".env")) {
  if (!fs.existsSync(file)) return;

  const lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const match = trimmed.match(/^([A-Za-z0-9_]+)\s*=\s*(.*)$/);
    if (!match) continue;

    let value = match[2].trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    if (!process.env[match[1]]) {
      process.env[match[1]] = value;
    }
  }
}

loadDotEnv();

const PORT = Number(process.env.PORT || process.env.AUTH_PORT || 3000);
const AUTH_VERSION = process.env.AUTH_VERSION || "Hell Client v2";
const AUTH_ADMIN_TOKEN = process.env.AUTH_ADMIN_TOKEN || "";
const REQUIRE_CLAIMED_KEY = (process.env.REQUIRE_CLAIMED_KEY || "true").toLowerCase() !== "false";
const CLAIMS_DB_PATH = process.env.CLAIMS_DB_PATH || "./claims.json";
const DISCORD_AUTH_LOG_WEBHOOK_URL = process.env.DISCORD_AUTH_LOG_WEBHOOK_URL || "";
const KEYAUTH_API_URL = process.env.KEYAUTH_API_URL || "https://keyauth.win/api/1.3/";
const KEYAUTH_SELLER_API_URL = process.env.KEYAUTH_SELLER_API_URL || "https://keyauth.win/api/seller/";
const KEYAUTH_SELLER_KEY = process.env.KEYAUTH_SELLER_KEY || "";
const KEYAUTH_APP_NAME = process.env.KEYAUTH_APP_NAME || "";
const KEYAUTH_OWNER_ID = process.env.KEYAUTH_OWNER_ID || "";
const KEYAUTH_APP_VERSION = process.env.KEYAUTH_APP_VERSION || "1.0";
const KEYAUTH_INIT_HASH = process.env.KEYAUTH_INIT_HASH || "";
const KEYAUTH_TOKEN = process.env.KEYAUTH_TOKEN || "";
const KEYAUTH_TOKEN_HASH = process.env.KEYAUTH_TOKEN_HASH || "";
const KEYAUTH_2FA_CODE = process.env.KEYAUTH_2FA_CODE || "";

let keyAuthSessionId = "";
let claimsCache = null;

function normalizeKey(key) {
  return String(key || "").trim().toUpperCase();
}

function createSessionToken(key, hwid) {
  return crypto
    .createHash("sha256")
    .update(`${normalizeKey(key)}:${hwid}:${Date.now()}:${crypto.randomUUID()}`)
    .digest("hex");
}

function authHeader(req) {
  return String(req.headers.authorization || "").replace(/^Bearer\s+/i, "").trim();
}

function isAdminRequest(req) {
  return AUTH_ADMIN_TOKEN && authHeader(req) === AUTH_ADMIN_TOKEN;
}

function ensureSellerKey() {
  if (!KEYAUTH_SELLER_KEY) {
    throw new Error("keyauth_seller_key_not_configured");
  }
}

function readClaimsDb() {
  if (claimsCache) return claimsCache;

  try {
    const fs = require("fs");
    if (!fs.existsSync(CLAIMS_DB_PATH)) {
      claimsCache = { claims: [] };
      return claimsCache;
    }

    const parsed = JSON.parse(fs.readFileSync(CLAIMS_DB_PATH, "utf8"));
    claimsCache = { claims: Array.isArray(parsed.claims) ? parsed.claims : [] };
    return claimsCache;
  } catch {
    claimsCache = { claims: [] };
    return claimsCache;
  }
}

function writeClaimsDb(db) {
  claimsCache = db;

  try {
    const fs = require("fs");
    fs.writeFileSync(CLAIMS_DB_PATH, JSON.stringify(db, null, 2));
  } catch {
    // Render's free filesystem can be ephemeral; KeyAuth notes remain the source of truth.
  }
}

function upsertClaim(claim) {
  const db = readClaimsDb();
  db.claims = db.claims.filter(item =>
    item.discordId !== claim.discordId && normalizeKey(item.key) !== normalizeKey(claim.key)
  );
  db.claims.push(claim);
  writeClaimsDb(db);
}

function findLocalClaimByKey(key) {
  const normalized = normalizeKey(key);
  return readClaimsDb().claims.find(item => normalizeKey(item.key) === normalized) || null;
}

function findLocalClaimByDiscordId(discordId) {
  return readClaimsDb().claims.find(item => item.discordId === discordId) || null;
}

function makeClaimNote(claim) {
  return `HC_CLAIM:${JSON.stringify({
    discordId: claim.discordId,
    discordTag: claim.discordTag,
    duration: claim.duration,
    claimedAt: claim.claimedAt
  })}`;
}

function parseClaimNote(note, key = "") {
  const text = String(note || "");
  const marker = "HC_CLAIM:";
  const index = text.indexOf(marker);
  if (index === -1) return null;

  try {
    const claim = JSON.parse(text.slice(index + marker.length).trim());
    if (!claim.discordId) return null;
    return {
      key,
      discordId: String(claim.discordId),
      discordTag: String(claim.discordTag || "Unknown"),
      duration: claim.duration ? String(claim.duration) : "",
      claimedAt: String(claim.claimedAt || "Unknown")
    };
  } catch {
    return null;
  }
}

function formatDuration(info) {
  return String(info?.duration || info?.expiry || info?.expires || "Unknown");
}

function keyAuthSellerRequest(params) {
  ensureSellerKey();

  const url = new URL(KEYAUTH_SELLER_API_URL);
  url.searchParams.set("sellerkey", KEYAUTH_SELLER_KEY);

  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      url.searchParams.set(key, value);
    }
  }

  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      headers: {
        Accept: "application/json",
        "User-Agent": "HellClientAuth/1.0"
      }
    }, res => {
      let body = "";

      res.on("data", chunk => {
        body += chunk;
        if (body.length > 256 * 1024) {
          req.destroy(new Error("seller_response_too_large"));
        }
      });

      res.on("end", () => {
        try {
          resolve(JSON.parse(body));
        } catch {
          const preview = body.replace(/\s+/g, " ").slice(0, 80);
          reject(new Error(`seller_invalid_json_${res.statusCode}_${preview || "empty"}`));
        }
      });
    });

    req.setTimeout(10000, () => req.destroy(new Error("seller_timeout")));
    req.on("error", reject);
  });
}

async function verifyLicenseExists(key) {
  const response = await keyAuthSellerRequest({
    type: "verify",
    key: normalizeKey(key)
  });

  if (!response.success) {
    throw new Error(response.message || "invalid_key");
  }

  return response;
}

async function getLicenseInfo(key) {
  const response = await keyAuthSellerRequest({
    type: "info",
    key: normalizeKey(key)
  });

  if (!response.success) {
    throw new Error(response.message || "license_info_failed");
  }

  return response;
}

async function setLicenseNote(key, note) {
  const response = await keyAuthSellerRequest({
    type: "setnote",
    key: normalizeKey(key),
    note
  });

  if (!response.success) {
    throw new Error(response.message || "set_note_failed");
  }

  return response;
}

async function fetchAllLicenses() {
  const response = await keyAuthSellerRequest({
    type: "fetchallkeys"
  });

  if (!response.success) {
    throw new Error(response.message || "fetch_all_keys_failed");
  }

  return Array.isArray(response.keys) ? response.keys : [];
}

function extractKeyFromLicenseItem(item) {
  if (typeof item === "string") return item;
  return item?.key || item?.license || item?.value || "";
}

function extractNoteFromLicenseItem(item) {
  if (!item || typeof item === "string") return "";
  return item.note || item.notes || "";
}

async function findClaimByKey(key) {
  const local = findLocalClaimByKey(key);
  if (local) return local;

  if (!KEYAUTH_SELLER_KEY) return null;

  try {
    const info = await getLicenseInfo(key);
    const claim = parseClaimNote(info.note, normalizeKey(key));
    if (claim) {
      claim.duration = claim.duration || formatDuration(info);
      upsertClaim(claim);
    }
    return claim;
  } catch {
    return null;
  }
}

async function findClaimByDiscordId(discordId) {
  const local = findLocalClaimByDiscordId(discordId);
  if (local) return local;

  if (!KEYAUTH_SELLER_KEY) return null;

  try {
    const licenses = await fetchAllLicenses();
    for (const item of licenses) {
      const key = extractKeyFromLicenseItem(item);
      let claim = parseClaimNote(extractNoteFromLicenseItem(item), key);
      if (!claim && key) {
        const info = await getLicenseInfo(key).catch(() => null);
        claim = parseClaimNote(info?.note, key);
        if (claim) claim.duration = claim.duration || formatDuration(info);
      }
      if (claim?.discordId === discordId) {
        upsertClaim(claim);
        return claim;
      }
    }
  } catch {
    return null;
  }

  return null;
}

async function claimLicense({ key, discordId, discordTag, durationLabel }) {
  const normalizedKey = normalizeKey(key);
  const cleanDiscordId = String(discordId || "").trim();
  const cleanDiscordTag = String(discordTag || "Unknown").trim();

  if (!normalizedKey || !cleanDiscordId) {
    return { success: false, reason: "missing_key_or_user" };
  }

  try {
    await verifyLicenseExists(normalizedKey);
    const info = await getLicenseInfo(normalizedKey);
    const existingKeyClaim = parseClaimNote(info.note, normalizedKey) || findLocalClaimByKey(normalizedKey);

    if (existingKeyClaim && existingKeyClaim.discordId !== cleanDiscordId) {
      return { success: false, reason: "key_already_claimed" };
    }

    const existingUserClaim = await findClaimByDiscordId(cleanDiscordId);
    if (existingUserClaim && normalizeKey(existingUserClaim.key) !== normalizedKey) {
      return {
        success: false,
        reason: "user_already_claimed",
        claim: existingUserClaim
      };
    }

    const claim = {
      key: normalizedKey,
      discordId: cleanDiscordId,
      discordTag: cleanDiscordTag,
      duration: String(durationLabel || formatDuration(info) || "Unknown"),
      claimedAt: new Date().toISOString()
    };

    await setLicenseNote(normalizedKey, makeClaimNote(claim));
    upsertClaim(claim);

    return { success: true, claim };
  } catch (error) {
    return { success: false, reason: error.message || "claim_failed" };
  }
}

async function sendDiscordWebhook(payload, result, ip) {
  if (!DISCORD_AUTH_LOG_WEBHOOK_URL) {
    console.log("[WEBHOOK] Skipped: DISCORD_AUTH_LOG_WEBHOOK_URL is empty");
    return;
  }

  const claim = result.claim || null;
  const resolvedUser =
    (claim && `${claim.discordTag} (${claim.discordId})`) ||
    String(payload.user || payload.discordUser || result.username || "Unknown").slice(0, 256);

  const embed = {
    title: result.success ? "Auth approved" : "Auth rejected",
    color: result.success ? 0x39ff14 : 0xff0000,
    fields: [
      { name: "Ign", value: String(payload.ign || "Unknown").slice(0, 256), inline: true },
      { name: "User", value: resolvedUser, inline: true },
      { name: "Ip", value: `\`${String(ip || "unknown").split(",")[0].trim().slice(0, 256)}\``, inline: true },
      { name: "Hwid", value: `\`${String(payload.hwid || "missing").slice(0, 900)}\``, inline: false },
      { name: "KeyAuth", value: `\`${normalizeKey(payload.key || "missing").slice(0, 900)}\``, inline: false }
    ],
    timestamp: new Date().toISOString()
  };

  const body = JSON.stringify({ embeds: [embed] });
  const url = new URL(DISCORD_AUTH_LOG_WEBHOOK_URL);

  await new Promise(resolve => {
    const req = https.request(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(body)
      }
    }, res => {
      let responseBody = "";

      res.on("data", chunk => {
        responseBody += chunk;
      });

      res.on("end", () => {
        const ok = Number(res.statusCode) >= 200 && Number(res.statusCode) < 300;
        if (ok) {
          console.log(`[WEBHOOK] Sent auth log successfully (${res.statusCode})`);
        } else {
          const preview = String(responseBody || "").replace(/\s+/g, " ").slice(0, 200);
          console.error(`[WEBHOOK] Failed with status ${res.statusCode}: ${preview || "empty response"}`);
        }
        resolve();
      });
    });

    req.setTimeout(10000, () => {
      console.error("[WEBHOOK] Request timed out");
      req.destroy(new Error("webhook_timeout"));
    });

    req.on("error", error => {
      console.error("[WEBHOOK] Request error:", error.message || error);
      resolve();
    });
    req.write(body);
    req.end();
  });
}

function keyAuthRequest(params) {
  const url = new URL(KEYAUTH_API_URL);

  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      url.searchParams.set(key, value);
    }
  }

  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      headers: {
        Accept: "application/json",
        "User-Agent": "HellClientAuth/1.0"
      }
    }, res => {
      let body = "";

      res.on("data", chunk => {
        body += chunk;
        if (body.length > 64 * 1024) {
          req.destroy(new Error("keyauth_response_too_large"));
        }
      });

      res.on("end", () => {
        try {
          resolve(JSON.parse(body));
        } catch {
          const preview = body.replace(/\s+/g, " ").slice(0, 80);
          reject(new Error(`keyauth_invalid_json_${res.statusCode}_${preview || "empty"}`));
        }
      });
    });

    req.setTimeout(10000, () => req.destroy(new Error("keyauth_timeout")));
    req.on("error", reject);
  });
}

async function initKeyAuth() {
  if (keyAuthSessionId) return keyAuthSessionId;

  if (!KEYAUTH_APP_NAME || !KEYAUTH_OWNER_ID) {
    throw new Error("keyauth_not_configured");
  }

  const response = await keyAuthRequest({
    type: "init",
    ver: KEYAUTH_APP_VERSION,
    name: KEYAUTH_APP_NAME,
    ownerid: KEYAUTH_OWNER_ID,
    hash: KEYAUTH_INIT_HASH,
    token: KEYAUTH_TOKEN,
    thash: KEYAUTH_TOKEN_HASH
  });

  if (!response.success || !response.sessionid) {
    throw new Error(response.message || "keyauth_init_failed");
  }

  keyAuthSessionId = response.sessionid;
  return keyAuthSessionId;
}

async function validateKeyAuthLicense(payload) {
  const key = normalizeKey(payload.key);
  const hwid = String(payload.hwid || "").trim();
  const version = String(payload.version || "").trim();

  if (!key || !hwid) {
    return { success: false, reason: "missing_key_or_hwid" };
  }

  try {
    const claim = await findClaimByKey(key);
    if (REQUIRE_CLAIMED_KEY && KEYAUTH_SELLER_KEY && !claim) {
      return { success: false, reason: "key_not_claimed" };
    }

    const sessionid = await initKeyAuth();
    const response = await keyAuthRequest({
      type: "license",
      key,
      hwid,
      sessionid,
      name: KEYAUTH_APP_NAME,
      ownerid: KEYAUTH_OWNER_ID,
      code: KEYAUTH_2FA_CODE
    });

    if (!response.success) {
      const message = String(response.message || "keyauth_rejected").toLowerCase();
      if (message.includes("session")) {
        keyAuthSessionId = "";
      }

      return {
        success: false,
        reason: response.message || "keyauth_rejected",
        claim
      };
    }

    const subscription = response.info?.subscriptions?.[0];

    return {
      success: true,
      product: version || AUTH_VERSION,
      session: createSessionToken(key, hwid),
      reason: response.message || "authorized",
      username: response.info?.username || null,
      expiresAt: subscription?.expiry || null,
      claim
    };
  } catch (error) {
    return {
      success: false,
      reason: error.message || "keyauth_error"
    };
  }
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", chunk => {
      body += chunk;
      if (body.length > 16 * 1024) {
        reject(new Error("request_too_large"));
        req.destroy();
      }
    });

    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(new Error("invalid_json"));
      }
    });

    req.on("error", reject);
  });
}

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type"
  });
  res.end(JSON.stringify(payload));
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  if (req.method === "OPTIONS") {
    return sendJson(res, 200, { ok: true });
  }

  if (req.method === "GET" && url.pathname === "/") {
    return sendJson(res, 200, {
      ok: true,
      service: "hell-auth",
      version: AUTH_VERSION,
      endpoints: ["/health", "/auth"]
    });
  }

  if (req.method === "GET" && url.pathname === "/health") {
    return sendJson(res, 200, {
      ok: true,
      service: "hell-auth",
      version: AUTH_VERSION
    });
  }

  if (req.method !== "POST" || url.pathname !== "/auth") {
    return sendJson(res, 404, { success: false, reason: "not_found" });
  }

  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;

  try {
    const payload = await readJsonBody(req);
    console.log(`[AUTH] Incoming auth request key=${normalizeKey(payload.key || "").slice(0, 6) || "missing"} ign=${String(payload.ign || "Unknown")} hwid=${String(payload.hwid || "missing").slice(0, 32)}`);
    const result = await validateKeyAuthLicense(payload);
    console.log(`[AUTH] Result success=${result.success} reason=${String(result.reason || "authorized")}`);
    await sendDiscordWebhook(payload, result, ip);
    return sendJson(res, result.success ? 200 : 401, result);
  } catch (error) {
    console.error("[AUTH] Request failed:", error.message || error);
    return sendJson(res, 400, { success: false, reason: error.message || "bad_request" });
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Hell Client auth listening on port ${PORT}`);
  console.log(`Claim requirement: ${REQUIRE_CLAIMED_KEY ? "enabled" : "disabled"}`);
  console.log(`Discord webhook logging: ${DISCORD_AUTH_LOG_WEBHOOK_URL ? "enabled" : "disabled"}`);
});
