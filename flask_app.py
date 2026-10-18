"""Traffic Light API - DevRev SE challenge (Part 3).

One file, Flask only, served by Gunicorn on Render:
- REST API secured with API keys (header: X-API-Key), one key per client, fail closed, constant-time check
- API explorer: Swagger UI at /docs
- Live updates + live request debugger: the page polls /state every second
"""
import hmac
import os
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, g, jsonify, request

# One key per client, so the debugger can show who made each call and each key can be revoked on its own.
# Values are environment variables on Render, never in the code.
CLIENT_KEYS = {
    "DevRev agent": os.environ.get("API_KEY_DEVREV", ""),
    "Browser (human)": os.environ.get("API_KEY_BROWSER", ""),
}
CLIENT_KEYS = {name: key for name, key in CLIENT_KEYS.items() if key}  # ignore clients with no key set
COLORS = ["red", "amber", "green"]

app = Flask(__name__)
state = {"color": "red"}
logs = []  # recent API calls shown in the live debugger


# ---------- Security ----------
def require_key(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not CLIENT_KEYS:  # fail closed: no key configured on the server = nobody gets in
            g.caller = "Unknown"
            return jsonify(error="Server not configured: API key missing"), 503
        given = request.headers.get("X-API-Key", "").encode()
        caller = None
        for name, key in CLIENT_KEYS.items():  # check every key, constant-time comparison each
            if hmac.compare_digest(given, key.encode()):
                caller = name
        if caller is None:
            g.caller = "Unknown (rejected)"
            return jsonify(error="Invalid or missing API key"), 401
        g.caller = caller
        return f(*args, **kwargs)
    return wrapper


# ---------- Live debugger: record every /api call ----------
@app.after_request
def log_api_call(response):
    if request.path.startswith("/api"):
        # show only meaningful headers: hides hosting/CDN noise and the caller's IP address
        shown = ("host", "user-agent", "content-type", "content-length", "accept", "x-api-key")
        headers = {k: v for k, v in request.headers.items() if k.lower() in shown}
        if "X-Api-Key" in headers:  # never show the secret on screen, not even part of it
            headers["X-Api-Key"] = "********"
        logs.append({
            "id": (logs[-1]["id"] + 1) if logs else 1,
            "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "caller": g.get("caller", "Unknown"),
            "method": request.method,
            "path": request.path,
            "status": response.status_code,
            "headers": headers,
            "payload": request.get_data(as_text=True),
            "response": response.get_data(as_text=True),
        })
        del logs[:-50]
    return response


# ---------- API ----------
@app.get("/api/light")
@require_key
def get_light():
    return jsonify(state)


@app.put("/api/light")
@require_key
def set_light():
    color = str((request.get_json(silent=True) or {}).get("color", "")).lower()
    if color not in COLORS:
        return jsonify(error=f"color must be one of {COLORS}"), 400
    state["color"] = color
    return jsonify(state)


@app.get("/api/colors")
@require_key
def list_colors():
    return jsonify(colors=COLORS)


# ---------- Feed for the page (read-only, no secrets) ----------
@app.get("/state")
def page_state():
    since = request.args.get("since", 0, type=int)
    return jsonify(color=state["color"], logs=[e for e in logs if e["id"] > since])


# ---------- API explorer (Swagger UI + OpenAPI description) ----------
OPENAPI = {
    "openapi": "3.0.3",
    "info": {"title": "Traffic Light API", "version": "1.0.0",
             "description": "Click **Authorize** and paste the browser API key. Each client (browser, DevRev agent) has its own key, shown as *caller* in the live debugger."},
    "components": {"securitySchemes": {"ApiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}}},
    "security": [{"ApiKey": []}],
    "paths": {
        "/api/light": {
            "get": {"summary": "Get current status", "responses": {"200": {"description": "Current color"},
                                                                    "401": {"description": "Missing/invalid key"},
                                                                    "503": {"description": "API key not configured on the server"}}},
            "put": {"summary": "Set light color",
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {
                        "type": "object", "required": ["color"],
                        "properties": {"color": {"type": "string", "enum": COLORS}}}}}},
                    "responses": {"200": {"description": "New color"}, "400": {"description": "Invalid color"},
                                  "401": {"description": "Missing/invalid key"}}},
        },
        "/api/colors": {
            "get": {"summary": "List available colors", "responses": {"200": {"description": "Valid colors"},
                                                                       "401": {"description": "Missing/invalid key"}}},
        },
    },
}


@app.get("/openapi.json")
def openapi():
    return jsonify(OPENAPI)


@app.get("/docs")
def docs():
    return """<!doctype html><html><head><meta charset="utf-8"><title>Traffic Light API</title>
<!-- SRI: the browser runs these files only if their fingerprint matches, so a tampered CDN file is blocked -->
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.17.14/swagger-ui.css"
      integrity="sha384-wxLW6kwyHktdDGr6Pv1zgm/VGJh99lfUbzSn6HNHBENZlCN7W602k9VkGdxuFvPn" crossorigin="anonymous"></head>
<body><div id="ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5.17.14/swagger-ui-bundle.js"
        integrity="sha384-wmyclcVGX/WhUkdkATwhaK1X1JtiNrr2EoYJ+diV3vj4v6OC5yCeSu+yW13SYJep" crossorigin="anonymous"></script>
<script>SwaggerUIBundle({url: "/openapi.json", dom_id: "#ui"});</script></body></html>"""


# ---------- UI ----------
@app.get("/")
def home():
    return PAGE


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Traffic Light</title>
<style>
  :root{--bg:#0f1115;--panel:#181b22;--line:#2a2f3a;--text:#e8eaf0;--muted:#8a93a6;
        --red:#ff3b30;--amber:#ffb000;--green:#22c55e}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
  header{display:flex;justify-content:space-between;align-items:center;padding:16px 24px;border-bottom:1px solid var(--line)}
  header h1{font-size:18px;margin:0}
  header a{color:var(--text);background:#2b3240;padding:8px 14px;border-radius:8px;text-decoration:none;font-size:14px}
  main{display:grid;grid-template-columns:320px 1fr;gap:24px;padding:24px;max-width:1200px;margin:auto}
  @media(max-width:800px){main{grid-template-columns:1fr}}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px}
  .light{width:150px;margin:10px auto;background:#111;border-radius:40px;padding:18px;display:grid;gap:16px;box-shadow:inset 0 0 0 3px #222}
  .lamp{width:114px;height:114px;border-radius:50%;opacity:.15;transition:all .35s}
  .lamp.red{background:var(--red);color:var(--red)}.lamp.amber{background:var(--amber);color:var(--amber)}
  .lamp.green{background:var(--green);color:var(--green)}
  .lamp.on{opacity:1;box-shadow:0 0 40px 6px currentColor}
  .status{text-align:center;color:var(--muted);margin-top:8px}
  .status b{color:var(--text);text-transform:uppercase}
  .dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#555;margin-right:6px}
  .dot.live{background:var(--green)}
  h2{font-size:15px;margin:0 0 12px;display:flex;justify-content:space-between}
  #log{display:grid;gap:10px;max-height:70vh;overflow:auto}
  .entry{border:1px solid var(--line);border-radius:10px;padding:10px 12px;font:13px ui-monospace,Menlo,monospace}
  .entry summary{cursor:pointer;display:flex;gap:10px;align-items:center}
  .m{font-weight:700;width:44px}.s{margin-left:auto;padding:1px 8px;border-radius:6px}
  .ok{background:#163d26;color:#7ee2a3}.ko{background:#4a1a1a;color:#ff9b9b}
  pre{white-space:pre-wrap;word-break:break-all;color:var(--muted);margin:8px 0 0}
  .empty{color:var(--muted)}
  .who{padding:1px 8px;border-radius:6px;font-size:12px;background:#2b3240;color:var(--muted)}
  .who.devrev{background:#3b2a5c;color:#d4bfff}.who.browser{background:#1f3550;color:#9cc8ff}
</style></head><body>
<header><h1>&#128678; Traffic Light</h1><a href="/docs" target="_blank">API explorer &#8599;</a></header>
<main>
  <section class="card">
    <div class="light">
      <div class="lamp red" id="red"></div><div class="lamp amber" id="amber"></div><div class="lamp green" id="green"></div>
    </div>
    <div class="status"><span class="dot" id="conn"></span>Current: <b id="cur">-</b></div>
  </section>
  <section class="card">
    <h2><span>Live API debugger</span><span class="empty" id="count">0 requests</span></h2>
    <div id="log"><div class="empty" id="none">Waiting for API calls...</div></div>
  </section>
</main>
<script>
let last = 0, n = 0;
const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
function show(c){ ["red","amber","green"].forEach(x => $(x).classList.toggle("on", x === c)); $("cur").textContent = c; }
const who = c => c.startsWith("DevRev") ? "devrev" : c.startsWith("Browser") ? "browser" : "";
function addLog(e){
  $("none")?.remove();
  const d = document.createElement("details"); d.className = "entry";
  d.innerHTML = `<summary><span class="m">${e.method}</span><span>${esc(e.path)}</span>
    <span class="who ${who(e.caller)}">${esc(e.caller)}</span>
    <span class="s ${e.status < 400 ? "ok" : "ko"}">${e.status}</span><span class="empty">${e.time}</span></summary>
    <pre><b>Headers</b>\\n${esc(JSON.stringify(e.headers, null, 2))}</pre>
    <pre><b>Payload</b>\\n${esc(e.payload || "(empty)")}</pre>
    <pre><b>Response</b>\\n${esc(e.response)}</pre>`;
  $("log").prepend(d);
  $("count").textContent = (++n) + " requests";
}
async function poll(){
  try {
    const r = await (await fetch("/state?since=" + last)).json()
    show(r.color);
    r.logs.forEach(e => { addLog(e); last = e.id; });
    $("conn").classList.add("live");
  } catch { $("conn").classList.remove("live"); }
  setTimeout(poll, 1000);  // short polling: 1 request per second, only while the page is open
}
poll();
</script></body></html>"""
