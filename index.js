const http = require("http");
const https = require("https");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || process.env.AUTH_PORT || 3000);
const AUTH_VERSION = process.env.AUTH_VERSION || "Hell Client v2";
const KEYAUTH_API_URL = process.env.KEYAUTH_API_URL || "https://keyauth.win/api/1.3/";
const KEYAUTH_APP_NAME = process.env.KEYAUTH_APP_NAME || "";
const KEYAUTH_OWNER_ID = process.env.KEYAUTH_OWNER_ID || "";
const KEYAUTH_APP_VERSION = process.env.KEYAUTH_APP_VERSION || "1.0";
const KEYAUTH_INIT_HASH = process.env.KEYAUTH_INIT_HASH || "";
const KEYAUTH_TOKEN = process.env.KEYAUTH_TOKEN || "";
const KEYAUTH_TOKEN_HASH = process.env.KEYAUTH_TOKEN_HASH || "";
const KEYAUTH_2FA_CODE = process.env.KEYAUTH_2FA_CODE || "";

let keyAuthSessionId = "";

function normalizeKey(key) {
  return String(key || "").trim().toUpperCase();
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
    const req = https.get(url, res => {
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
          reject(new Error("keyauth_invalid_json"));
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

    const subscription = response.info?.subscriptions?.[0];

    return {
      success: true,
      product: version || AUTH_VERSION,
      session: createSessionToken(key, hwid),
      reason: response.message || "authorized",
      username: response.info?.username || null,
      expiresAt: subscription?.expiry || null
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
  if (req.method === "OPTIONS") {
    return sendJson(res, 200, { ok: true });
  }

  if (req.method === "GET" && req.url === "/health") {
    return sendJson(res, 200, {
      ok: true,
      service: "hell-auth",
      version: AUTH_VERSION
    });
  }

  if (req.method !== "POST" || req.url !== "/auth") {
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
