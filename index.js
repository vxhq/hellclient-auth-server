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

const PORT = Number(process.env.PORT || 3000);
const AUTH_VERSION = process.env.AUTH_VERSION || "Hell Client v2";
const KEYAUTH_API_URL = process.env.KEYAUTH_API_URL || "https://keyauth.win/api/1.3/";
const KEYAUTH_APP_NAME = process.env.KEYAUTH_APP_NAME || "HellClientAuth";
const KEYAUTH_OWNER_ID = process.env.KEYAUTH_OWNER_ID || "ZeXteXutvi";
const KEYAUTH_APP_VERSION = process.env.KEYAUTH_APP_VERSION || "1.0";
const KEYAUTH_INIT_HASH = process.env.KEYAUTH_INIT_HASH || "";
const KEYAUTH_TOKEN = process.env.KEYAUTH_TOKEN || "";
const KEYAUTH_TOKEN_HASH = process.env.KEYAUTH_TOKEN_HASH || "";
const KEYAUTH_2FA_CODE = process.env.KEYAUTH_2FA_CODE || "";

let keyAuthSessionId = "";

function normalizeKey(key) {
  return String(key || "").trim();
}

function createSessionToken(key, hwid) {
  return crypto
    .createHash("sha256")
    .update(`${normalizeKey(key)}:${hwid}:${Date.now()}:${crypto.randomUUID()}`)
    .digest("hex");
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
          const preview = body.replace(/\s+/g, " ").slice(0, 120);
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
        reason: response.message || "keyauth_rejected"
      };
    }

    return {
      success: true,
      product: version || AUTH_VERSION,
      session: createSessionToken(key, hwid),
      reason: response.message || "authorized",
      username: response.info?.username || null
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
      service: "hell-auth-render",
      version: AUTH_VERSION,
      endpoints: ["/health", "/auth"]
    });
  }

  if (req.method === "GET" && url.pathname === "/health") {
    return sendJson(res, 200, {
      ok: true,
      service: "hell-auth-render",
      version: AUTH_VERSION
    });
  }

  if (req.method !== "POST" || url.pathname !== "/auth") {
    return sendJson(res, 404, { success: false, reason: "not_found" });
  }

  try {
    const payload = await readJsonBody(req);
    const result = await validateKeyAuthLicense(payload);
    return sendJson(res, result.success ? 200 : 401, result);
  } catch (error) {
    return sendJson(res, 400, { success: false, reason: error.message || "bad_request" });
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Hell Client auth listening on port ${PORT}`);
});
