const encoder = new TextEncoder();
const LNURL_FETCH_TIMEOUT_MS = 8000;
const LNURL_MAX_RESPONSE_BYTES = 160 * 1024;

const CONFIG = Object.freeze({
  PUBLIC_DOMAIN: "yourdomain.com",
  ADMIN_ORIGIN: "https://admin.yourdomain.com",
});

async function fetchLnurlPayload(url) {
  let response;

  try {
    response = await fetch(url.toString(), {
      method: "GET",
      headers: {
        "Accept": "application/json"
      },
      redirect: "manual",
      signal: AbortSignal.timeout(LNURL_FETCH_TIMEOUT_MS),
    });
  } catch {
    throw new Error("Backend unreachable or timed out");
  }

  if (response.status >= 300 && response.status < 400) {
    throw new Error("Backend redirected — not allowed");
  }

  if (!response.ok) {
    throw new Error("Backend returned an error status");
  }

  const declaredLength =
    response.headers.get("content-length");

  if (
    declaredLength &&
    Number.isFinite(Number(declaredLength)) &&
    Number(declaredLength) > LNURL_MAX_RESPONSE_BYTES
  ) {
    throw new Error("Backend response too large");
  }

  if (!response.body) {
    throw new Error("Backend returned an empty response");
  }

  const reader = response.body.getReader();
  const chunks = [];
  let totalBytes = 0;

  while (true) {
    const { done, value } = await reader.read();

    if (done) {
      break;
    }

    totalBytes += value.byteLength;

    if (totalBytes > LNURL_MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error("Backend response too large");
    }

    chunks.push(value);
  }

  const bodyText =
    new TextDecoder().decode(
      concatChunks(chunks, totalBytes)
    );

  let data;

  try {
    data = JSON.parse(bodyText);
  } catch {
    throw new Error("Backend returned invalid JSON");
  }

  if (
    data.tag !== "payRequest" ||
    typeof data.callback !== "string" ||
    typeof data.metadata !== "string" ||
    typeof data.minSendable !== "number" ||
    typeof data.maxSendable !== "number" ||
    data.minSendable < 1 ||
    data.maxSendable < data.minSendable
  ) {
    throw new Error("Invalid LNURL-pay response");
  }

  return {
    data,
    bodyText
  };
}

function concatChunks(chunks, totalBytes) {
  const result = new Uint8Array(totalBytes);
  let offset = 0;

  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return result;
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const securityHeaders = {
      "Content-Security-Policy":
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "Cache-Control": "no-store",
      "Strict-Transport-Security": "max-age=31536000",
    };
// Admin must be accessed through the custom domain only
if (url.origin !== CONFIG.ADMIN_ORIGIN) {
  return new Response("Forbidden A: URL origin", {
    status: 403,
    headers: securityHeaders
  });
}

// CSRF protection for state-changing requests
if (request.method === "POST") {
  const origin = request.headers.get("Origin");
  const fetchSite = request.headers.get("Sec-Fetch-Site");

  if (fetchSite !== "same-origin") {
    return new Response("Forbidden", {
      status: 403,
      headers: securityHeaders
    });
  }

  if (
    origin &&
    origin !== "null" &&
    origin !== CONFIG.ADMIN_ORIGIN
  ) {
    return new Response("Forbidden", {
      status: 403,
      headers: securityHeaders
    });
  }
}
    // Logout
if (request.method === "POST" && url.pathname === "/logout") {
  const sessionId = getCookie(
    request.headers.get("Cookie") || "",
    "zapm_admin_session"
  );

  if (sessionId) {
    await env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE session_id = ?
      `)
      .bind(sessionId)
      .run();
  }

  return new Response(null, {
    status: 303,
    headers: {
      Location: "/",
      "Set-Cookie":
        "zapm_admin_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
    },
  });
}
    // Login
    if (request.method === "POST" && url.pathname === "/login") {
      const form = await request.formData();
      const password = String(form.get("password") || "");
const ip =
  request.headers.get("CF-Connecting-IP") || "unknown";

const ipHash =
  await sign(env.SESSION_SECRET, `login-ip:${ip}`);

const now = Date.now();

const loginAttempt = await env.DB
  .prepare(`
    SELECT
      fail_count,
      window_started_at,
      blocked_until
    FROM admin_login_attempts
    WHERE ip_hash = ?
    LIMIT 1
  `)
  .bind(ipHash)
  .first();

if (
  loginAttempt &&
  Number(loginAttempt.blocked_until) > now
) {
  const minutesLeft = Math.ceil(
    (Number(loginAttempt.blocked_until) - now) / 60000
  );

  return html(
    messagePage(
      "Login temporarily blocked",
      `Too many incorrect password attempts. Try again in about ${minutesLeft} minute(s).`
    ),
    429,
    securityHeaders
  );
}
      const valid = await secureEqual(password, env.ADMIN_PASSWORD);

  if (!valid) {
  const WINDOW_MS = 15 * 60 * 1000;
  const BLOCK_MS = 30 * 60 * 1000;

  let failCount = 1;
  let windowStartedAt = now;

  if (
    loginAttempt &&
    now - Number(loginAttempt.window_started_at) <= WINDOW_MS
  ) {
    failCount =
      Number(loginAttempt.fail_count) + 1;

    windowStartedAt =
      Number(loginAttempt.window_started_at);
  }

  const blockedUntil =
    failCount >= 5
      ? now + BLOCK_MS
      : 0;

  await env.DB
    .prepare(`
      INSERT INTO admin_login_attempts (
        ip_hash,
        fail_count,
        window_started_at,
        blocked_until,
        updated_at
      )
      VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)

      ON CONFLICT(ip_hash)
      DO UPDATE SET
        fail_count = excluded.fail_count,
        window_started_at = excluded.window_started_at,
        blocked_until = excluded.blocked_until,
        updated_at = CURRENT_TIMESTAMP
    `)
    .bind(
      ipHash,
      failCount,
      windowStartedAt,
      blockedUntil
    )
    .run();

  if (blockedUntil > now) {
    return html(
      messagePage(
        "Login temporarily blocked",
        "Too many incorrect password attempts. Try again in about 30 minutes."
      ),
      429,
      securityHeaders
    );
  }

  return html(
    loginPage(true),
    401,
    securityHeaders
  );
}
await env.DB
  .prepare(`
    DELETE FROM admin_login_attempts
    WHERE ip_hash = ?
  `)
  .bind(ipHash)
  .run();
      const session = await createSession(env);

      return new Response(null, {
        status: 303,
        headers: {
          Location: "/",
          "Set-Cookie":
            `zapm_admin_session=${session}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`,
        },
      });
    }

    // Check session
    const session = getCookie(
      request.headers.get("Cookie") || "",
      "zapm_admin_session"
    );

    const authenticated =
  session &&
  (await verifySession(session, env));

    // Login page
    if (!authenticated) {
      if (request.method === "GET" && url.pathname === "/") {
        return html(loginPage(false), 200, securityHeaders);
      }

      return new Response("Unauthorized", {
        status: 401,
        headers: securityHeaders,
      });
    }
    // Sign out everywhere
if (
  request.method === "POST" &&
  url.pathname === "/logout-all"
) {
  await env.DB
    .prepare(`
      DELETE FROM sessions
    `)
    .run();

  return new Response(null, {
    status: 303,
    headers: {
      Location: "/",
      "Set-Cookie":
        "zapm_admin_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
    },
  });
}
    // Add new Lightning ID
if (request.method === "POST" && url.pathname === "/add") {
  const form = await request.formData();

  const username = String(form.get("username") || "")
    .trim()
    .toLowerCase();

  const displayName = String(form.get("display_name") || "").trim();

  const backendUrl = String(form.get("backend_url") || "").trim();

  const notes = String(form.get("notes") || "").trim();

  // Username format
  if (!/^[a-z0-9._-]{1,64}$/.test(username)) {
    return html(
      messagePage(
        "Invalid username",
        "Use only a-z, 0-9, dot, underscore or hyphen."
      ),
      400,
      securityHeaders
    );
  }

  // Reserved names
  const reserved = new Set([
    "admin",
    "adminln",
    "api",
    "www",
    "support",
    "help",
    "login",
    "logout",
    "root",
    "abuse",
    "security",
    "billing",
    "system",
    "status",
    "null"
  ]);

  if (reserved.has(username)) {
    return html(
      messagePage(
        "Reserved username",
        "This username is reserved by ZAPM."
      ),
      400,
      securityHeaders
    );
  }

  // Validate HTTPS URL
  let backend;

  try {
    backend = new URL(backendUrl);

    if (backend.protocol !== "https:") {
      throw new Error("HTTPS required");
    }
  } catch {
    return html(
      messagePage(
        "Invalid backend URL",
        "Backend must be a valid HTTPS URL."
      ),
      400,
      securityHeaders
    );
  }

  // Verify LNURL-pay backend before saving
try {
  await fetchLnurlPayload(backend);
} catch {
  return html(
    messagePage(
      "Backend verification failed",
      "The URL did not return a valid, appropriately-sized LNURL-pay payRequest within the time limit."
    ),
    400,
    securityHeaders
  );
}

  // Check duplicate username
  const existing = await env.DB
    .prepare(`
      SELECT id
      FROM lightning_ids
      WHERE username = ?
      LIMIT 1
    `)
    .bind(username)
    .first();

  if (existing) {
    return html(
      messagePage(
        "Username already exists",
        `${username}@${CONFIG.PUBLIC_DOMAIN} is already registered.`
      ),
      409,
      securityHeaders
    );
  }

  // Save
  await env.DB
    .prepare(`
      INSERT INTO lightning_ids (
        username,
        display_name,
        backend_url,
        status,
        notes,
        updated_at
      )
      VALUES (?, ?, ?, 'active', ?, CURRENT_TIMESTAMP)
    `)
    .bind(
      username,
      displayName || null,
      backend.toString(),
      notes || null
    )
    .run();

  // Redirect back to dashboard
  return new Response(null, {
    status: 303,
    headers: {
      Location: "/"
    }
  });
}
// Enable / Disable Lightning ID
if (request.method === "POST" && url.pathname === "/status") {
  const form = await request.formData();

  const username = String(form.get("username") || "")
    .trim()
    .toLowerCase();

  const action = String(form.get("action") || "");

  if (!/^[a-z0-9._-]{1,64}$/.test(username)) {
    return html(
      messagePage(
        "Invalid username",
        "The Lightning ID username is invalid."
      ),
      400,
      securityHeaders
    );
  }

  if (action !== "enable" && action !== "disable") {
    return html(
      messagePage(
        "Invalid action",
        "Unknown status action."
      ),
      400,
      securityHeaders
    );
  }

  const user = await env.DB
    .prepare(`
      SELECT id, username, backend_url, status
      FROM lightning_ids
      WHERE username = ?
      LIMIT 1
    `)
    .bind(username)
    .first();

  if (!user) {
    return html(
      messagePage(
        "Lightning ID not found",
        `${username}@${CONFIG.PUBLIC_DOMAIN} does not exist.`
      ),
      404,
      securityHeaders
    );
  }
if (user.status === "retired") {
  return html(
    messagePage(
      "Lightning ID retired",
      `${username}@${CONFIG.PUBLIC_DOMAIN} has been permanently retired and cannot be re-enabled.`
    ),
    403,
    securityHeaders
  );
}
  const newStatus =
    action === "enable"
      ? "active"
      : "inactive";

  await env.DB
    .prepare(`
      UPDATE lightning_ids
      SET
        status = ?,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `)
    .bind(newStatus, user.id)
    .run();

  await env.DB
    .prepare(`
      INSERT INTO audit_log (
        lightning_id,
        action,
        old_backend_url,
        new_backend_url
      )
      VALUES (?, ?, ?, ?)
    `)
    .bind(
      user.id,
      action,
      user.backend_url,
      user.backend_url
    )
    .run();

  return new Response(null, {
    status: 303,
    headers: {
      Location: "/"
    }
  });
}
// Show retire confirmation page
if (request.method === "POST" && url.pathname === "/retire") {
  const form = await request.formData();

  const username = String(form.get("username") || "")
    .trim()
    .toLowerCase();

  if (!/^[a-z0-9._-]{1,64}$/.test(username)) {
    return html(
      messagePage(
        "Invalid username",
        "The Lightning ID username is invalid."
      ),
      400,
      securityHeaders
    );
  }

  const user = await env.DB
    .prepare(`
      SELECT id, username, display_name, backend_url, status
      FROM lightning_ids
      WHERE username = ?
      LIMIT 1
    `)
    .bind(username)
    .first();

  if (!user) {
    return html(
      messagePage(
        "Lightning ID not found",
        `${username}@${CONFIG.PUBLIC_DOMAIN} does not exist.`
      ),
      404,
      securityHeaders
    );
  }

  if (user.status === "retired") {
    return html(
      messagePage(
        "Already retired",
        `${username}@${CONFIG.PUBLIC_DOMAIN} has already been retired.`
      ),
      400,
      securityHeaders
    );
  }

  return html(
    retireConfirmPage(user),
    200,
    securityHeaders
  );
}
// Retire Lightning ID permanently
if (request.method === "POST" && url.pathname === "/retire-confirm") {
  const form = await request.formData();

  const username = String(form.get("username") || "")
    .trim()
    .toLowerCase();

  if (!/^[a-z0-9._-]{1,64}$/.test(username)) {
    return html(
      messagePage(
        "Invalid username",
        "The Lightning ID username is invalid."
      ),
      400,
      securityHeaders
    );
  }

  const user = await env.DB
    .prepare(`
      SELECT id, username, backend_url, status
      FROM lightning_ids
      WHERE username = ?
      LIMIT 1
    `)
    .bind(username)
    .first();

  if (!user) {
    return html(
      messagePage(
        "Lightning ID not found",
        `${username}@${CONFIG.PUBLIC_DOMAIN} does not exist.`
      ),
      404,
      securityHeaders
    );
  }

  if (user.status === "retired") {
    return html(
      messagePage(
        "Already retired",
        `${username}@${CONFIG.PUBLIC_DOMAIN} has already been retired.`
      ),
      400,
      securityHeaders
    );
  }

  await env.DB
    .prepare(`
      UPDATE lightning_ids
      SET
        status = 'retired',
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `)
    .bind(user.id)
    .run();

  await env.DB
    .prepare(`
      INSERT INTO audit_log (
        lightning_id,
        action,
        old_backend_url,
        new_backend_url
      )
      VALUES (?, 'retire', ?, ?)
    `)
    .bind(
      user.id,
      user.backend_url,
      user.backend_url
    )
    .run();

  return new Response(null, {
    status: 303,
    headers: {
      Location: "/"
    }
  });
}
// Edit Lightning payment backend
if (request.method === "POST" && url.pathname === "/edit") {
  const form = await request.formData();

  const username = String(form.get("username") || "")
    .trim()
    .toLowerCase();

  const backendUrl = String(form.get("backend_url") || "").trim();

  // Validate username
  if (!/^[a-z0-9._-]{1,64}$/.test(username)) {
    return html(
      messagePage(
        "Invalid username",
        "The Lightning ID username is invalid."
      ),
      400,
      securityHeaders
    );
  }

  // Find current record
  const user = await env.DB
    .prepare(`
      SELECT id, username, backend_url, status
      FROM lightning_ids
      WHERE username = ?
      LIMIT 1
    `)
    .bind(username)
    .first();

  if (!user) {
    return html(
      messagePage(
        "Lightning ID not found",
        `${username}@${CONFIG.PUBLIC_DOMAIN} does not exist.`
      ),
      404,
      securityHeaders
    );
  }
  if (user.status === "retired") {
  return html(
    messagePage(
      "Lightning ID retired",
      `${username}@${CONFIG.PUBLIC_DOMAIN} has been permanently retired and its backend cannot be changed.`
    ),
    403,
    securityHeaders
  );
}

  // Validate HTTPS URL
  let backend;

  try {
    backend = new URL(backendUrl);

    if (backend.protocol !== "https:") {
      throw new Error("HTTPS required");
    }
  } catch {
    return html(
      messagePage(
        "Invalid backend URL",
        "Backend must be a valid HTTPS URL."
      ),
      400,
      securityHeaders
    );
  }

  // Verify that the new backend really is LNURL-pay
try {
  await fetchLnurlPayload(backend);
} catch {
  return html(
    messagePage(
      "Backend verification failed",
      "The new URL did not return a valid, appropriately-sized LNURL-pay payRequest within the time limit."
    ),
    400,
    securityHeaders
  );
}

  // No change needed
  if (backend.toString() === user.backend_url) {
    return new Response(null, {
      status: 303,
      headers: {
        Location: "/"
      }
    });
  }

  // Update backend
  await env.DB
    .prepare(`
      UPDATE lightning_ids
      SET
        backend_url = ?,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `)
    .bind(backend.toString(), user.id)
    .run();

  // Save history
  await env.DB
    .prepare(`
      INSERT INTO audit_log (
        lightning_id,
        action,
        old_backend_url,
        new_backend_url
      )
      VALUES (?, 'backend_changed', ?, ?)
    `)
    .bind(
      user.id,
      user.backend_url,
      backend.toString()
    )
    .run();

  return new Response(null, {
    status: 303,
    headers: {
      Location: "/"
    }
  });
}
  // Admin dashboard - read only
if (request.method === "GET" && url.pathname === "/") {

  const result = await env.DB
    .prepare(`
      SELECT
        username,
        display_name,
        backend_url,
        status,
        created_at,
        updated_at
      FROM lightning_ids
      ORDER BY username
    `)
    .all();
const audit = await env.DB
  .prepare(`
    SELECT
      audit_log.action,
      audit_log.old_backend_url,
      audit_log.new_backend_url,
      audit_log.created_at,
      lightning_ids.username
    FROM audit_log
    LEFT JOIN lightning_ids
      ON lightning_ids.id = audit_log.lightning_id
    ORDER BY audit_log.id DESC
    LIMIT 20
  `)
  .all();
  return html(
    adminPage(
  result.results || [],
  audit.results || []
),
    200,
    securityHeaders
  );
}

    return new Response("Not Found", {
      status: 404,
      headers: securityHeaders,
    });
  },
};


// -----------------------------------------------------
// SESSION
// -----------------------------------------------------

async function createSession(env) {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const sessionId = base64url(bytes);

  const now = Date.now();
  const expiresAt = now + 8 * 60 * 60 * 1000;

  await env.DB
    .prepare(`
      DELETE FROM sessions
      WHERE expires_at <= ?
    `)
    .bind(now)
    .run();

  await env.DB
    .prepare(`
      INSERT INTO sessions (
        session_id,
        created_at,
        expires_at
      )
      VALUES (?, ?, ?)
    `)
    .bind(
      sessionId,
      now,
      expiresAt
    )
    .run();

  return sessionId;
}


async function verifySession(sessionId, env) {
  const row = await env.DB
    .prepare(`
      SELECT expires_at
      FROM sessions
      WHERE session_id = ?
      LIMIT 1
    `)
    .bind(sessionId)
    .first();

  if (!row) {
    return false;
  }

  if (Number(row.expires_at) <= Date.now()) {
    await env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE session_id = ?
      `)
      .bind(sessionId)
      .run();

    return false;
  }

  return true;
}
async function sign(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(message)
  );

  return base64url(new Uint8Array(signature));
}


function base64url(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}


// -----------------------------------------------------
// PASSWORD COMPARISON
// -----------------------------------------------------

async function secureEqual(a, b) {
  const [hashA, hashB] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(String(a))),
    crypto.subtle.digest("SHA-256", encoder.encode(String(b))),
  ]);

  const bytesA = new Uint8Array(hashA);
  const bytesB = new Uint8Array(hashB);

  let diff = 0;

  for (let i = 0; i < bytesA.length; i++) {
    diff |= bytesA[i] ^ bytesB[i];
  }

  return diff === 0;
}


// -----------------------------------------------------
// COOKIE
// -----------------------------------------------------

function getCookie(cookieHeader, name) {
  const cookies = cookieHeader.split(";");

  for (const cookie of cookies) {
    const [key, ...value] = cookie.trim().split("=");

    if (key === name) {
      return value.join("=");
    }
  }

  return null;
}


// -----------------------------------------------------
// HTML
// -----------------------------------------------------

function html(content, status, headers) {
  return new Response(content, {
    status,
    headers: {
      ...headers,
      "Content-Type": "text/html; charset=UTF-8",
    },
  });
}


function loginPage(error) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ZAPM Admin</title>

<style>
body {
  font-family: system-ui, sans-serif;
  background: #111;
  color: #fff;
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  margin: 0;
}

.box {
  width: 340px;
  padding: 32px;
  background: #1b1b1b;
  border-radius: 16px;
}

h1 {
  margin-top: 0;
}

input {
  width: 100%;
  box-sizing: border-box;
  padding: 12px;
  margin: 12px 0;
  border-radius: 8px;
  border: 1px solid #444;
  background: #111;
  color: white;
}

button {
  width: 100%;
  padding: 12px;
  border: 0;
  border-radius: 8px;
  font-weight: 700;
  cursor: pointer;
}

.error {
  color: #ff7777;
}
</style>
</head>

<body>

<div class="box">

<h1>ZAPM Admin</h1>

<p>Private administration</p>

${error ? `<p class="error">Incorrect password</p>` : ""}

<form method="POST" action="/login">

<input
  type="password"
  name="password"
  placeholder="Admin password"
  autocomplete="current-password"
  required
>

<button type="submit">
Sign in
</button>

</form>

</div>

</body>
</html>`;
}


function adminPage(users, audit) {

  const rows = users.map(user => `
    <div class="id-card">

      <div class="id-name">
        ${escapeHtml(user.username)}@${escapeHtml(CONFIG.PUBLIC_DOMAIN)}
      </div>

      <div class="status ${user.status === "active" ? "active" : ""}">
        ${escapeHtml(user.status)}
      </div>
      ${user.status !== "retired" ? `

<form method="POST" action="/status" class="status-form">

  <input
    type="hidden"
    name="username"
    value="${escapeHtml(user.username)}"
  >

  <input
    type="hidden"
    name="action"
    value="${user.status === "active" ? "disable" : "enable"}"
  >

  <button
    type="submit"
    class="${user.status === "active" ? "disable-btn" : "enable-btn"}"
  >
    ${user.status === "active" ? "Disable" : "Enable"}
  </button>

</form>


<form method="POST" action="/retire" class="status-form">

  <input
    type="hidden"
    name="username"
    value="${escapeHtml(user.username)}"
  >

  <button
    type="submit"
    class="retire-btn"
  >
    Retire
  </button>

</form>

` : ""}

      <div class="label">Display name</div>
      <div>${escapeHtml(user.display_name || "-")}</div>

      <div class="label">Backend</div>
      <div class="backend">
        ${escapeHtml(user.backend_url)}
      </div>
${user.status !== "retired" ? `

<form method="POST" action="/edit" class="edit-form">

  <input
    type="hidden"
    name="username"
    value="${escapeHtml(user.username)}"
  >

  <input
    type="url"
    name="backend_url"
    value="${escapeHtml(user.backend_url)}"
    required
  >

  <button type="submit">
    Save backend
  </button>

</form>

` : `
<div class="retired-lock">
  Backend locked — this Lightning ID is permanently retired.
</div>
`}
      <div class="label">Created</div>
      <div>${escapeHtml(user.created_at || "-")}</div>

    </div>
  `).join("");
const auditRows = audit.map(item => {

  let actionText = item.action;

  if (item.action === "backend_changed") {
    actionText = "Backend changed";
  }

  if (item.action === "enable") {
    actionText = "Enabled";
  }

  if (item.action === "disable") {
    actionText = "Disabled";
  }

  if (item.action === "retire") {
    actionText = "Retired";
  }

  const backendChange =
    item.action === "backend_changed"
      ? `
        <div class="audit-backend">
          <div>
            From:
            ${escapeHtml(item.old_backend_url || "-")}
          </div>

          <div>
            To:
            ${escapeHtml(item.new_backend_url || "-")}
          </div>
        </div>
      `
      : "";

  return `
    <div class="audit-item">

      <div class="audit-top">

        <strong>
          ${escapeHtml(item.username || "Unknown ID")}@${escapeHtml(CONFIG.PUBLIC_DOMAIN)}
        </strong>

        <span>
          ${escapeHtml(actionText)}
        </span>

      </div>

      ${backendChange}

      <div class="audit-time">
        ${escapeHtml(item.created_at || "-")}
      </div>

    </div>
  `;

}).join("");
  return `<!doctype html>
<html lang="en">

<head>

<meta charset="utf-8">

<meta
  name="viewport"
  content="width=device-width,initial-scale=1"
>

<title>ZAPM Admin</title>

<style>

body {
  font-family: system-ui, sans-serif;
  background: #0f0f0f;
  color: #fff;
  max-width: 1000px;
  margin: 50px auto;
  padding: 20px;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 35px;
}
.header-actions {
  display: flex;
  gap: 10px;
  align-items: center;
}

.logout-all-btn {
  background: #5b3a16;
  color: #fff;
  border: 0;
  border-radius: 6px;
}
h1 {
  margin: 0;
}

.summary {
  color: #aaa;
  margin-top: 8px;
}

.id-card {
  background: #1b1b1b;
  padding: 24px;
  border-radius: 14px;
  margin-bottom: 18px;
}

.id-name {
  font-size: 22px;
  font-weight: 700;
  margin-bottom: 8px;
}

.status {
  display: inline-block;
  padding: 4px 9px;
  border-radius: 6px;
  background: #444;
  margin-bottom: 18px;
  text-transform: uppercase;
  font-size: 12px;
}

.status.active {
  background: #176b35;
}

.label {
  color: #888;
  font-size: 13px;
  margin-top: 14px;
  margin-bottom: 3px;
}

.backend {
  word-break: break-all;
  font-family: monospace;
}

button {
  padding: 9px 16px;
  cursor: pointer;
}
.add-card {
  background: #1b1b1b;
  padding: 24px;
  border-radius: 14px;
  margin-bottom: 30px;
}

.add-card h2 {
  margin-top: 0;
}

.add-card label {
  display: block;
  color: #aaa;
  font-size: 13px;
  margin-top: 16px;
  margin-bottom: 6px;
}

.add-card input {
  width: 100%;
  box-sizing: border-box;
  padding: 11px;
  border: 1px solid #444;
  border-radius: 7px;
  background: #111;
  color: #fff;
}

.username-field {
  display: flex;
  align-items: center;
  gap: 10px;
}

.username-field input {
  flex: 1;
}

.username-field span {
  white-space: nowrap;
  color: #aaa;
}

.add-card button {
  margin-top: 20px;
}
  .status-form {
  display: inline-block;
  margin-left: 10px;
}

.status-form button {
  padding: 5px 10px;
  border: 0;
  border-radius: 6px;
  font-size: 12px;
  font-weight: 700;
  cursor: pointer;
}

.disable-btn {
  background: #7a2626;
  color: #fff;
}

.enable-btn {
  background: #176b35;
  color: #fff;
}
  .retire-btn {
  background: #5b3a16;
  color: #fff;
}
  .edit-form {
  margin-top: 10px;
  display: flex;
  gap: 8px;
  align-items: center;
}

.edit-form input {
  flex: 1;
  min-width: 0;
  box-sizing: border-box;
  padding: 9px 10px;
  border: 1px solid #444;
  border-radius: 6px;
  background: #111;
  color: #fff;
  font-family: monospace;
}

.edit-form button {
  white-space: nowrap;
  padding: 9px 12px;
  border: 0;
  border-radius: 6px;
  cursor: pointer;
  font-weight: 700;
}

@media (max-width: 700px) {
  .edit-form {
    flex-direction: column;
    align-items: stretch;
  }
}
  .audit-section {
  margin-top: 40px;
  padding-top: 10px;
}

.audit-section h2 {
  margin-bottom: 18px;
}

.audit-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.audit-item {
  background: #1b1b1b;
  padding: 18px 20px;
  border-radius: 12px;
}

.audit-top {
  display: flex;
  justify-content: space-between;
  gap: 20px;
  align-items: center;
}

.audit-top span {
  color: #aaa;
  font-size: 13px;
}

.audit-backend {
  margin-top: 12px;
  padding: 10px 12px;
  background: #111;
  border-radius: 8px;
  font-family: monospace;
  font-size: 13px;
  word-break: break-all;
}

.audit-backend div + div {
  margin-top: 6px;
}

.audit-time {
  margin-top: 10px;
  color: #777;
  font-size: 12px;
}

.empty-audit {
  color: #888;
}

@media (max-width: 700px) {
  .audit-top {
    flex-direction: column;
    align-items: flex-start;
    gap: 4px;
  }

  .header {
    align-items: flex-start;
  }

  .header-actions {
    flex-direction: column;
    align-items: stretch;
  }
}
  .retired-lock {
  margin-top: 10px;
  padding: 10px 12px;
  background: #2a2a2a;
  border: 1px solid #444;
  border-radius: 7px;
  color: #aaa;
  font-size: 13px;
}
</style>

</head>

<body>

<div class="header">

  <div>
    <h1>ZAPM Admin</h1>

    <div class="summary">
      ${users.length} Lightning ID${users.length === 1 ? "" : "s"}
    </div>
  </div>

  <div class="header-actions">

  <form method="POST" action="/logout">
    <button type="submit">
      Sign out
    </button>
  </form>

  <form method="POST" action="/logout-all">
    <button
      type="submit"
      class="logout-all-btn"
    >
      Sign out everywhere
    </button>
  </form>

</div>

</div>
<div class="add-card">

  <h2>Add Lightning ID</h2>

  <form method="POST" action="/add">

    <label>
      Username
    </label>

    <div class="username-field">
      <input
        type="text"
        name="username"
        placeholder="somchai"
        pattern="[a-zA-Z0-9._-]+"
        maxlength="64"
        required
      >
      <span>@${escapeHtml(CONFIG.PUBLIC_DOMAIN)}</span>
    </div>

    <label>
      Display name
    </label>

    <input
      type="text"
      name="display_name"
      placeholder="Somchai"
    >

    <label>
      LNURL-pay backend
    </label>

    <input
      type="url"
      name="backend_url"
      placeholder="https://provider.example/.well-known/lnurlp/username"
      required
    >

    <label>
      Note
    </label>

    <input
      type="text"
      name="notes"
      placeholder="Optional private note"
    >

    <button type="submit">
      + Add Lightning ID
    </button>

  </form>

</div>
${rows || "<p>No Lightning IDs found.</p>"}
<div class="audit-section">

  <h2>Recent Activity</h2>

  <div class="audit-list">
    ${auditRows || `<p class="empty-audit">No activity yet.</p>`}
  </div>

</div>
</body>

</html>`;
}
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
function messagePage(title, message) {
  return `<!doctype html>
<html lang="en">

<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">

<title>ZAPM Admin</title>

<style>

body {
  font-family: system-ui, sans-serif;
  background: #111;
  color: #fff;
  max-width: 700px;
  margin: 80px auto;
  padding: 20px;
}

.card {
  background: #1b1b1b;
  padding: 30px;
  border-radius: 16px;
}

a {
  color: #fff;
}

</style>

</head>

<body>

<div class="card">

<h1>${escapeHtml(title)}</h1>

<p>${escapeHtml(message)}</p>

<p>
  <a href="/">← Back to dashboard</a>
</p>

</div>

</body>
</html>`;
}
function retireConfirmPage(user) {
  return `<!doctype html>
<html lang="en">

<head>
<meta charset="utf-8">
<meta
  name="viewport"
  content="width=device-width,initial-scale=1"
>

<title>Confirm Retire — ZAPM Admin</title>

<style>

body {
  font-family: system-ui, sans-serif;
  background: #0f0f0f;
  color: #fff;
  max-width: 700px;
  margin: 70px auto;
  padding: 20px;
}

.card {
  background: #1b1b1b;
  padding: 30px;
  border-radius: 16px;
}

.warning {
  background: #3a2713;
  border: 1px solid #7a4f1d;
  padding: 16px;
  border-radius: 10px;
  margin: 22px 0;
}

.address {
  font-size: 22px;
  font-weight: 700;
  margin: 15px 0;
}

.label {
  color: #888;
  font-size: 13px;
  margin-top: 15px;
}

.backend {
  font-family: monospace;
  word-break: break-all;
}

.actions {
  display: flex;
  gap: 12px;
  margin-top: 26px;
}

.retire {
  background: #7a4f1d;
  color: #fff;
  border: 0;
  border-radius: 7px;
  padding: 11px 18px;
  font-weight: 700;
  cursor: pointer;
}

.cancel {
  display: inline-block;
  background: #333;
  color: #fff;
  text-decoration: none;
  border-radius: 7px;
  padding: 11px 18px;
}

</style>
</head>

<body>

<div class="card">

<h1>Confirm Retire</h1>

<div class="address">
  ${escapeHtml(user.username)}@${escapeHtml(CONFIG.PUBLIC_DOMAIN)}
</div>

<div class="warning">
  This action permanently retires this Lightning ID.
  It will stop receiving payments and cannot be enabled again.
  The username will remain reserved and will not be reassigned.
</div>

<div class="label">Display name</div>
<div>
  ${escapeHtml(user.display_name || "-")}
</div>

<div class="label">Current backend</div>
<div class="backend">
  ${escapeHtml(user.backend_url)}
</div>

<div class="actions">

  <form method="POST" action="/retire-confirm">

    <input
      type="hidden"
      name="username"
      value="${escapeHtml(user.username)}"
    >

    <button
      type="submit"
      class="retire"
    >
      Confirm Retire
    </button>

  </form>

  <a
    href="/"
    class="cancel"
  >
    Cancel
  </a>

</div>

</div>

</body>
</html>`;
}
