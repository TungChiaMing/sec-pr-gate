// Intentionally vulnerable Node.js API (no framework, so package-lock stays small).
// TP = true positive the gate must catch, FP = context-dependent false positive.
const http = require("http");
const crypto = require("crypto");
const { exec } = require("child_process");
const axios = require("axios");
const _ = require("lodash");

// intentional TP: hardcoded live-looking secret (Semgrep p/secrets + Trivy secret scanner)
const STRIPE_KEY = "sk_live_51JsNodeSampleAbCdEfGhIjKlMnOpQrStUv0123";

// intentional TP: OS command injection (user input -> child_process.exec)
function ping(host, cb) {
  exec("ping -c 1 " + host, (err, stdout) => cb(err ? String(err) : stdout));
}

// intentional TP: eval() on user input -> RCE
function calc(expr) {
  return String(eval(expr));
}

// intentional TP: SSRF (user-controlled URL, no allowlist)
async function fetchUrl(url) {
  const r = await axios.get(url, { timeout: 3000 });
  return String(r.data).slice(0, 200);
}

// FP in context: md5 used as a non-security cache key
function cacheKey(payload) {
  return crypto.createHash("md5").update(payload).digest("hex");
}

// FP in context: Math.random() used for backoff jitter, not for security
function retryJitter() {
  return Math.random() * 500;
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, "http://127.0.0.1");
  const q = Object.fromEntries(u.searchParams);
  const send = (code, body) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
  try {
    if (u.pathname === "/ping") return ping(q.host || "127.0.0.1", (out) => send(200, { out }));
    if (u.pathname === "/calc") return send(200, { result: calc(q.expr || "1+1") });
    if (u.pathname === "/fetch") return send(200, { body: await fetchUrl(q.url || "") });
    if (u.pathname === "/health") return send(200, { key: cacheKey("health"), jitter: retryJitter(), v: _.VERSION });
    return send(404, { error: "not found" });
  } catch (e) {
    return send(500, { error: String(e) });
  }
});

server.listen(3000, "127.0.0.1", () => console.log("node-api-sample on http://127.0.0.1:3000"));
