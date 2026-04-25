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
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || "https://discord.com/api/webhooks/1496671377758093483/C_7nyI0DxThVKHoiTtbJDk0ytAtkK0ls4jL0_9ujiZBwC9IU36gUat1ahw8vYKl-yUDa";

let keyAuthSessionId = "";

function normalizeKey(key) {
  return String(key || "").trim();
}

function normalizeIp(value) {
  const ip = String(value || "").trim();
  if (!ip) return "";
  return ip.startsWith("::ffff:") ? ip.slice(7) : ip;
}

function createSessionToken(key, hwid) {
  return crypto
    .createHash("sha256")
    .update(`${normalizeKey(key)}:${hwid}:${Date.now()}:${crypto.randomUUID()}`)
    .digest("hex");
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) {
    return normalizeIp(forwarded.split(",")[0].trim());
  }

  const realIp = req.headers["x-real-ip"];
  if (typeof realIp === "string" && realIp.trim()) {
    return normalizeIp(realIp.trim());
  }

  return normalizeIp(req.socket?.remoteAddress || "");
}

function getIgnFromPayload(payload) {
  const candidates = [
    payload?.ign,
    payload?.minecraftUsername,
    payload?.minecraft_username,
    payload?.minecraft_name,
    payload?.mcUsername,
    payload?.mc_username,
    payload?.playerName,
    payload?.player_name,
    payload?.username,
    payload?.name,
    payload?.player
  ];

  for (const candidate of candidates) {
    const value = String(candidate || "").trim();
    if (value) {
      return value;
    }
  }

  return "Unknown";
}

function getDiscordFromPayload(payload) {
  const usernameCandidates = [
    payload?.discordUsername,
    payload?.discord_username,
    payload?.discordName,
    payload?.discord_name,
    payload?.discord?.username,
    payload?.discord?.name
  ];

  const idCandidates = [
    payload?.discordId,
    payload?.discord_id,
    payload?.discordID,
    payload?.discord?.id
  ];

  let username = "";
  for (const candidate of usernameCandidates) {
    const value = String(candidate || "").trim();
    if (value) {
      username = value;
      break;
    }
  }

  let id = "";
  for (const candidate of idCandidates) {
    const value = String(candidate || "").trim();
    if (value) {
      id = value;
      break;
    }
  }

  return { username, id };
}

function formatTime(date = new Date()) {
  const pad = value => String(value).padStart(2, "0");
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())} UTC`;
}

function truncate(value, limit = 1024) {
  const text = String(value ?? "");
  if (text.length <= limit) return text;
  return `${text.slice(0, limit - 3)}...`;
}

function stringifyValue(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value.trim();
  if (typeof value === "number" || typeof value === "boolean") return String(value);

  if (Array.isArray(value)) {
    return value
      .map(item => {
        if (item === null || item === undefined) return "";
        if (typeof item === "string") return item.trim();
        if (typeof item === "object") {
          return item.subscription || item.name || item.key || JSON.stringify(item);
        }
        return String(item);
      })
      .filter(Boolean)
      .join(", ");
  }

  if (typeof value === "object") {
    return JSON.stringify(value);
  }

  return String(value).trim();
}

function embedValue(value, fallback = "Unknown", limit = 1024) {
  const text = stringifyValue(value);
  if (!text) return fallback;
  return truncate(text, limit);
}

function formatDiscordEmbedValue(username, id) {
  const cleanUser = String(username || "").trim();
  const cleanId   = String(id || "").trim();
  const isSnowflake = /^\d{17,20}$/.test(cleanId);

  if (cleanUser && cleanId) {
    return isSnowflake
      ? `**${cleanUser}**\n<@${cleanId}> \`${cleanId}\``
      : `**${cleanUser}**\n\`${cleanId}\``;
  }
  if (cleanUser) return `**${cleanUser}**`;
  if (cleanId)   return isSnowflake ? `<@${cleanId}> \`${cleanId}\`` : `\`${cleanId}\``;
  return "`Unknown`";
}

function postJson(urlString, payload) {
  const url = new URL(urlString);
  const body = JSON.stringify(payload);

  return new Promise((resolve, reject) => {
    const req = https.request({
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port || 443,
      path: `${url.pathname}${url.search}`,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(body),
        "User-Agent": "HellClientAuth/1.0"
      }
    }, res => {
      let responseBody = "";

      res.on("data", chunk => {
        responseBody += chunk;
      });

      res.on("end", () => {
        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
          resolve(responseBody);
          return;
        }

        reject(new Error(`webhook_http_${res.statusCode || "unknown"}`));
      });
    });

    req.setTimeout(8000, () => req.destroy(new Error("webhook_timeout")));
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

function formatUuid(uuid) {
  const clean = String(uuid || "").replace(/-/g, "").trim();
  if (clean.length !== 32) return String(uuid || "");
  return `${clean.slice(0, 8)}-${clean.slice(8, 12)}-${clean.slice(12, 16)}-${clean.slice(16, 20)}-${clean.slice(20)}`;
}

function fetchMinecraftProfile(ign) {
  const username = String(ign || "").trim();
  if (!username || !/^[A-Za-z0-9_]{1,16}$/.test(username)) {
    return Promise.resolve(null);
  }

  const url = `https://api.mojang.com/users/profiles/minecraft/${encodeURIComponent(username)}`;

  return new Promise(resolve => {
    const req = https.get(url, {
      headers: {
        Accept: "application/json",
        "User-Agent": "HellClientAuth/1.0"
      }
    }, res => {
      let body = "";

      res.on("data", chunk => {
        body += chunk;
        if (body.length > 16 * 1024) {
          req.destroy();
          resolve(null);
        }
      });

      res.on("end", () => {
        try {
          const status = Number(res.statusCode);
          if (status < 200 || status >= 300 || !body) {
            return resolve(null);
          }
          const data = JSON.parse(body);
          if (data && data.id && data.name) {
            resolve({ uuid: formatUuid(data.id), rawUuid: data.id, name: data.name });
          } else {
            resolve(null);
          }
        } catch {
          resolve(null);
        }
      });
    });

    req.setTimeout(5000, () => {
      req.destroy();
      resolve(null);
    });
    req.on("error", () => resolve(null));
  });
}

async function sendAuthWebhookLog(details) {
  if (!DISCORD_WEBHOOK_URL) return;

  const rawIgn = String(details.ign || "").trim();
  const profile = await fetchMinecraftProfile(rawIgn);
  const ignValue = profile
    ? `**${profile.name}**\n\`${profile.uuid}\``
    : (rawIgn && rawIgn !== "Unknown" ? `**${rawIgn}**\n\`UUID unknown\`` : "`Unknown`");

  // mc-heads.net resuelve tanto UUID (con o sin guiones) como nombres,
  // así que si Mojang falla pero el IGN es válido, igual hay skin.
  const avatarTarget =
    profile?.rawUuid ||
    (/^[A-Za-z0-9_]{1,16}$/.test(rawIgn) ? rawIgn : null);

  const discordValue = formatDiscordEmbedValue(details.discordUsername, details.discordId);

  const embed = {
    author: { name: "Hell Client Authentication" },
    title: details.success ? "✓  Access Granted" : "✗  Access Denied",
    color: details.success ? 0x2ecc71 : 0xe74c3c,
    fields: [
      { name: "Player",      value: truncate(ignValue, 1024),                                                  inline: true  },
      { name: "Discord",     value: truncate(discordValue, 1024),                                              inline: true  },
      { name: "Version",     value: `\`${truncate(stringifyValue(details.version) || AUTH_VERSION, 100)}\``,   inline: true  },
      { name: "Reason",      value: `\`${truncate(stringifyValue(details.reason) || (details.success ? "authorized" : "denied"), 100)}\``, inline: true },
      { name: "IP",          value: `\`${truncate(stringifyValue(details.ip) || "unknown", 100)}\``,           inline: true  },
      { name: "KeyAuth IP",  value: `\`${truncate(stringifyValue(details.keyAuthIp) || "unknown", 100)}\``,    inline: true  },
      { name: "License",     value: `\`${truncate(stringifyValue(details.key) || "missing", 100)}\``,          inline: true  },
      { name: "Hardware ID", value: `\`\`\`${truncate(stringifyValue(details.hwid) || "missing", 1000)}\`\`\``, inline: false }
    ],
    footer: { text: `Hell Client Auth • ${AUTH_VERSION}` },
    timestamp: new Date().toISOString()
  };

  if (avatarTarget) {
    embed.thumbnail = { url: `https://mc-heads.net/avatar/${avatarTarget}/128` };
  }

  const payload = { embeds: [embed] };

  try {
    await postJson(DISCORD_WEBHOOK_URL, payload);
  } catch (error) {
    console.error("[WEBHOOK] Failed to send auth log:", error.message || error);
  }
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
      username: response.info?.username || null,
      info: response.info || {}
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
    const discord = getDiscordFromPayload(payload);

    void sendAuthWebhookLog({
      success: result.success,
      reason: result.reason,
      version: String(payload.version || AUTH_VERSION).trim() || AUTH_VERSION,
      key: payload.key,
      hwid: payload.hwid,
      ign: getIgnFromPayload(payload),
      discordUsername: discord.username,
      discordId: discord.id,
      ip: getClientIp(req),
      keyAuthIp: result.info?.ip
    });

    return sendJson(res, result.success ? 200 : 401, result);
  } catch (error) {
    return sendJson(res, 400, { success: false, reason: error.message || "bad_request" });
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Hell Client auth listening on port ${PORT}`);
});
