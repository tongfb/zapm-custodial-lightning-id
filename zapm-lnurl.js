const LNURL_FETCH_TIMEOUT_MS = 8000;
const LNURL_MAX_RESPONSE_BYTES = 160 * 1024;

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

    const jsonHeaders = {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "no-store"
    };

    // Accept only /.well-known/lnurlp/<username>
    const match = url.pathname.match(
      /^\/\.well-known\/lnurlp\/([a-z0-9._-]+)\/?$/i
    );

    if (request.method !== "GET" || !match) {
      return new Response("Not Found", { status: 404 });
    }

    const username = match[1].toLowerCase();

    try {
      const user = await env.DB
        .prepare(`
          SELECT username, backend_url, status
          FROM lightning_ids
          WHERE username = ?
          LIMIT 1
        `)
        .bind(username)
        .first();

      if (!user || user.status !== "active") {
        return new Response(
          JSON.stringify({
            status: "ERROR",
            reason: "Lightning Address not found"
          }),
          {
            status: 404,
            headers: jsonHeaders
          }
        );
      }

      let backend;

      try {
        backend = new URL(user.backend_url);

        if (backend.protocol !== "https:") {
          throw new Error("HTTPS required");
        }
      } catch {
        return new Response(
          JSON.stringify({
            status: "ERROR",
            reason: "Invalid Lightning payment backend"
          }),
          {
            status: 502,
            headers: jsonHeaders
          }
        );
      }

      const { bodyText } =
        await fetchLnurlPayload(backend);

      return new Response(bodyText, {
        status: 200,
        headers: jsonHeaders
      });

    } catch (error) {
      console.error("LNURL error:", error);

      return new Response(
        JSON.stringify({
          status: "ERROR",
          reason: "Lightning payment backend unavailable"
        }),
        {
          status: 502,
          headers: jsonHeaders
        }
      );
    }
  }
};
