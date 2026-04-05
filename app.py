import os
import json
import re
import asyncio
import logging
import threading
import queue
from datetime import datetime

from flask import Flask, jsonify, request, Response, stream_with_context
from pyrogram import Client, filters
from pyrogram.raw.functions.account import GetPassword
from pyrogram.errors import (
    FloodWait, SessionPasswordNeeded, PhoneNumberBanned,
    AuthKeyUnregistered, UserDeactivated
)

# ─── App Setup ────────────────────────────────────────────────────────────────
app = Flask(__name__)
logging.basicConfig(level=logging.WARNING)
logging.getLogger("pyrogram").setLevel(logging.WARNING)

# ─── Shared State ────────────────────────────────────────────────────────────
state = {
    "status": "idle",   # idle | running | connecting | waiting_otp_trigger |
                        # waiting_otp | waiting_action | done | error
    "current_session": None,
    "phone_number": None,
    "otp_code": None,
    "sessions_processed": 0,
    "sessions_total": 0,
    "logs": [],
}
sse_listeners: list[queue.Queue] = []

# Threading sync primitives for user→bot communication
_action_event = threading.Event()
_action_value: dict = {"v": None}


# ─── SSE / State Helpers ─────────────────────────────────────────────────────
def _push(event_type: str, data):
    msg = json.dumps({"type": event_type, "data": data})
    dead = []
    for q in sse_listeners:
        try:
            q.put_nowait(msg)
        except Exception:
            dead.append(q)
    for d in dead:
        try:
            sse_listeners.remove(d)
        except ValueError:
            pass


def add_log(message: str, level: str = "info"):
    entry = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "message": message,
        "level": level,
    }
    state["logs"].append(entry)
    if len(state["logs"]) > 200:
        state["logs"] = state["logs"][-200:]
    _push("log", entry)


def update_state(**kwargs):
    state.update(kwargs)
    _push("state", {
        k: state[k]
        for k in [
            "status", "current_session", "phone_number",
            "otp_code", "sessions_processed", "sessions_total",
        ]
    })


# ─── Async Helpers ───────────────────────────────────────────────────────────
async def wait_for_user_action() -> str:
    """Suspend coroutine until a user action arrives via /action endpoint."""
    loop = asyncio.get_event_loop()
    _action_event.clear()
    _action_value["v"] = None
    await loop.run_in_executor(None, _action_event.wait)
    return _action_value["v"]


async def check_2fa(client: Client) -> bool:
    try:
        pwd = await client.invoke(GetPassword())
        return pwd.has_password
    except Exception:
        return False


# ─── Recovery Logic ──────────────────────────────────────────────────────────
def setup_directories():
    for folder in ["sessions", "recovered_sessions", "dead_sessions"]:
        os.makedirs(folder, exist_ok=True)


def load_config():
    if not os.path.exists("config.json"):
        raise FileNotFoundError("config.json not found")
    with open("config.json") as f:
        cfg = json.load(f)
    api_id = cfg.get("api_id")
    api_hash = cfg.get("api_hash")
    skip_2fa = bool(cfg.get("SKIP_2FA_enabled", False))
    if not api_id or not api_hash or api_hash == "API_HASH":
        raise ValueError("api_id / api_hash missing or not set in config.json")
    return int(api_id), api_hash, skip_2fa


def get_session_files():
    return [f for f in os.listdir("sessions") if f.endswith(".session")]


def move_session(session_file: str, target_folder: str):
    src = os.path.join("sessions", session_file)
    dst = os.path.join(target_folder, session_file)
    try:
        os.rename(src, dst)
        add_log(f"Moved {session_file} → {target_folder}/")
    except Exception as e:
        add_log(f"Error moving {session_file}: {e}", "error")


def save_recovered(session_file: str, phone: str):
    with open("recovered_numbers.txt", "a") as f:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{ts}] Session: {session_file} | Phone: {phone}\n")


async def process_session(session_file: str, api_id: int, api_hash: str, skip_2fa: bool):
    session_name = os.path.splitext(session_file)[0]
    update_state(
        current_session=session_file,
        phone_number=None,
        otp_code=None,
        status="connecting",
    )
    add_log(f"Processing: {session_file}")

    client = Client(
        name=os.path.join("sessions", session_name),
        api_id=api_id,
        api_hash=api_hash,
    )

    try:
        await client.start()

        if skip_2fa and await check_2fa(client):
            add_log(f"Skipped (2FA enabled): {session_file}", "warning")
            await client.stop()
            move_session(session_file, "dead_sessions")
            return

        me = await client.get_me()
        phone = getattr(me, "phone_number", None) or "Unknown"
        update_state(phone_number=phone, status="waiting_otp_trigger")
        add_log(f"Phone number: {phone}", "success")
        add_log("Click 'Send OTP' button to trigger the login code.")

        # ── Step 1: wait for user to trigger OTP send ────────────────────────
        action = await wait_for_user_action()
        if action == "skip":
            add_log(f"Skipped: {session_file}", "warning")
            await client.stop()
            return

        # ── Step 2: listen for OTP from Telegram ─────────────────────────────
        update_state(status="waiting_otp")
        add_log("Waiting for OTP message from Telegram (sender 777000)…")

        otp_event = asyncio.Event()
        otp_holder: dict = {"code": None}

        @client.on_message(filters.private & filters.user([777000]))
        async def handle_otp(c, message):
            text = message.text or ""
            match = re.search(
                r"(?:Login code|Code|Your code)[:\s]+(\d{5,6})\b",
                text,
                re.IGNORECASE,
            )
            if match:
                otp_holder["code"] = match.group(1)
                update_state(otp_code=otp_holder["code"])
                add_log(f"OTP received: {otp_holder['code']}", "success")
                otp_event.set()

        # OTP wait loop with 60-second timeout
        while True:
            try:
                await asyncio.wait_for(otp_event.wait(), timeout=60)
            except asyncio.TimeoutError:
                add_log("OTP not received in 60 seconds.", "warning")
                update_state(status="waiting_action")
                action = await wait_for_user_action()
                if action == "retry":
                    otp_event.clear()
                    update_state(status="waiting_otp")
                    add_log("Retrying OTP wait…")
                    continue
                else:  # fail or skip
                    add_log(f"Marked failed: {session_file}", "error")
                    await client.stop()
                    move_session(session_file, "dead_sessions")
                    return

            # OTP received — wait for user decision
            update_state(status="waiting_action")
            add_log("OTP ready. Choose an action: Recovered / Retry / Fail")
            action = await wait_for_user_action()

            if action == "recovered":
                add_log(f"✅ Recovered: {session_file}", "success")
                await client.stop()
                move_session(session_file, "recovered_sessions")
                save_recovered(session_file, phone)
                return
            elif action == "fail":
                add_log(f"❌ Failed: {session_file}", "error")
                await client.stop()
                move_session(session_file, "dead_sessions")
                return
            elif action == "retry":
                otp_event.clear()
                otp_holder["code"] = None
                update_state(otp_code=None, status="waiting_otp")
                add_log("Retrying OTP wait…")
                continue

    except SessionPasswordNeeded:
        add_log(f"2FA required: {session_file}", "warning")
        move_session(session_file, "dead_sessions")
    except (PhoneNumberBanned, UserDeactivated) as e:
        add_log(f"Account banned/deactivated: {e}", "error")
        move_session(session_file, "dead_sessions")
    except AuthKeyUnregistered:
        add_log(f"Session expired: {session_file}", "error")
        move_session(session_file, "dead_sessions")
    except FloodWait as e:
        add_log(f"FloodWait {e.value}s — moving to dead sessions.", "error")
        move_session(session_file, "dead_sessions")
    except Exception as e:
        add_log(f"Unexpected error: {e}", "error")
        move_session(session_file, "dead_sessions")
    finally:
        try:
            if client.is_connected:
                await client.stop()
        except Exception:
            pass


async def run_bot():
    setup_directories()
    try:
        api_id, api_hash, skip_2fa = load_config()
    except Exception as e:
        update_state(status="error")
        add_log(str(e), "error")
        return

    sessions = get_session_files()
    if not sessions:
        update_state(status="error")
        add_log("No .session files found in sessions/ folder!", "error")
        return

    update_state(sessions_total=len(sessions), sessions_processed=0, status="running")
    add_log(f"Found {len(sessions)} session(s). Starting…")

    for i, session_file in enumerate(sessions):
        await process_session(session_file, api_id, api_hash, skip_2fa)
        update_state(sessions_processed=i + 1)

    update_state(status="done", current_session=None, phone_number=None, otp_code=None)
    add_log("✅ All sessions processed!", "success")


# ─── HTML Template ────────────────────────────────────────────────────────────
HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Telegram OTP Recovery</title>
<style>
  :root {
    --bg: #0f0f13; --panel: #1a1a24; --border: #2e2e42;
    --accent: #5865f2; --green: #23a55a; --red: #f04747;
    --yellow: #faa61a; --text: #e0e0f0; --muted: #8888aa;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', sans-serif;
         min-height: 100vh; display: flex; flex-direction: column; align-items: center; padding: 24px 16px; }
  h1 { font-size: 1.5rem; margin-bottom: 6px; }
  .subtitle { color: var(--muted); font-size: .85rem; margin-bottom: 24px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
           padding: 20px; width: 100%; max-width: 640px; margin-bottom: 16px; }
  .card h2 { font-size: .9rem; text-transform: uppercase; letter-spacing: .08em;
              color: var(--muted); margin-bottom: 14px; }
  .info-row { display: flex; justify-content: space-between; align-items: center;
               padding: 8px 0; border-bottom: 1px solid var(--border); font-size: .9rem; }
  .info-row:last-child { border-bottom: none; }
  .info-row span:first-child { color: var(--muted); }
  .badge { padding: 2px 10px; border-radius: 20px; font-size: .75rem; font-weight: 600; }
  .badge-idle    { background:#2e2e42; color:var(--muted); }
  .badge-running { background:#1a3a5c; color:#5ab4f0; }
  .badge-done    { background:#1a3a24; color:var(--green); }
  .badge-error   { background:#3a1a1a; color:var(--red); }
  .badge-wait    { background:#3a2a1a; color:var(--yellow); }
  .otp-box { background:#0f0f13; border:1px solid var(--border); border-radius:8px;
              padding:14px; text-align:center; margin:14px 0; }
  .otp-box .label { color:var(--muted); font-size:.8rem; margin-bottom:4px; }
  .otp-code { font-size:2.4rem; font-weight:700; letter-spacing:.3em; color:var(--accent); font-family:monospace; }
  .btn-row { display:flex; gap:10px; flex-wrap:wrap; margin-top:14px; }
  button { flex:1; min-width:100px; padding:10px 14px; border:none; border-radius:8px;
           font-size:.9rem; font-weight:600; cursor:pointer; transition:opacity .2s; }
  button:disabled { opacity:.4; cursor:not-allowed; }
  button:hover:not(:disabled) { opacity:.85; }
  .btn-start    { background:var(--accent); color:#fff; }
  .btn-green    { background:var(--green);  color:#fff; }
  .btn-red      { background:var(--red);    color:#fff; }
  .btn-yellow   { background:var(--yellow); color:#000; }
  .btn-muted    { background:var(--border); color:var(--text); }
  .log-box { background:#0a0a10; border:1px solid var(--border); border-radius:8px;
              height:260px; overflow-y:auto; padding:10px; font-family:monospace; font-size:.78rem; }
  .log-line { padding: 1px 0; line-height:1.5; }
  .log-info    { color: var(--text); }
  .log-success { color: var(--green); }
  .log-warning { color: var(--yellow); }
  .log-error   { color: var(--red); }
  .progress-bar { background:var(--border); border-radius:4px; height:6px; margin:8px 0; overflow:hidden; }
  .progress-fill { height:100%; background:var(--accent); border-radius:4px; transition:width .4s; }
  #hint { color:var(--muted); font-size:.82rem; margin-top:10px; min-height:1.2em; }
</style>
</head>
<body>
<h1>📱 Telegram OTP Recovery</h1>
<p class="subtitle">Web interface for Pyrogram session recovery</p>

<div class="card">
  <h2>Status</h2>
  <div class="info-row">
    <span>Bot status</span>
    <span id="status-badge" class="badge badge-idle">Idle</span>
  </div>
  <div class="info-row">
    <span>Sessions</span>
    <span id="sessions-counter">—</span>
  </div>
  <div class="info-row">
    <span>Current session</span>
    <span id="current-session" style="color:var(--accent)">—</span>
  </div>
  <div class="info-row">
    <span>Phone number</span>
    <span id="phone-number" style="font-weight:600">—</span>
  </div>
  <div class="progress-bar"><div class="progress-fill" id="progress" style="width:0%"></div></div>
  <p id="hint">Press Start to begin processing sessions.</p>
</div>

<div class="card" id="otp-card" style="display:none">
  <h2>OTP Code</h2>
  <div class="otp-box">
    <div class="label">Received login code</div>
    <div class="otp-code" id="otp-display">——</div>
  </div>
</div>

<div class="card">
  <h2>Actions</h2>
  <div class="btn-row">
    <button class="btn-start" id="btn-start"    onclick="doStart()">▶ Start</button>
    <button class="btn-green" id="btn-otp"      onclick="doAction('otp_sent')"   disabled>📨 Send OTP</button>
    <button class="btn-green" id="btn-recovered" onclick="doAction('recovered')" disabled>✅ Recovered</button>
    <button class="btn-yellow" id="btn-retry"   onclick="doAction('retry')"      disabled>🔄 Retry OTP</button>
    <button class="btn-red"   id="btn-fail"     onclick="doAction('fail')"       disabled>❌ Fail</button>
    <button class="btn-muted" id="btn-skip"     onclick="doAction('skip')"       disabled>⏭ Skip</button>
  </div>
</div>

<div class="card">
  <h2>Logs</h2>
  <div class="log-box" id="log-box"></div>
</div>

<script>
const $ = id => document.getElementById(id);
let evtSource = null;

function startSSE() {
  if (evtSource) evtSource.close();
  evtSource = new EventSource('/events');
  evtSource.onmessage = e => {
    const msg = JSON.parse(e.data);
    if (msg.type === 'state') applyState(msg.data);
    if (msg.type === 'log')   appendLog(msg.data);
  };
}

function applyState(s) {
  // Status badge
  const badge = $('status-badge');
  const labels = {
    idle:'Idle', running:'Running', connecting:'Connecting',
    waiting_otp_trigger:'Waiting — Send OTP', waiting_otp:'Waiting for OTP',
    waiting_action:'Action Required', done:'Done', error:'Error', starting:'Starting…'
  };
  badge.textContent = labels[s.status] || s.status;
  badge.className = 'badge ' + (
    s.status === 'idle'   ? 'badge-idle' :
    s.status === 'done'   ? 'badge-done' :
    s.status === 'error'  ? 'badge-error' :
    (s.status.startsWith('waiting') || s.status === 'connecting') ? 'badge-wait' : 'badge-running'
  );

  $('current-session').textContent = s.current_session || '—';
  $('phone-number').textContent    = s.phone_number    || '—';
  $('sessions-counter').textContent =
    s.sessions_total ? `${s.sessions_processed} / ${s.sessions_total}` : '—';

  const pct = s.sessions_total ? (s.sessions_processed / s.sessions_total * 100) : 0;
  $('progress').style.width = pct + '%';

  // OTP card
  if (s.otp_code) {
    $('otp-card').style.display = 'block';
    $('otp-display').textContent = s.otp_code;
  } else {
    $('otp-card').style.display = 'none';
    $('otp-display').textContent = '——';
  }

  // Button states & hints
  const st = s.status;
  $('btn-start').disabled     = st !== 'idle' && st !== 'done' && st !== 'error';
  $('btn-otp').disabled       = st !== 'waiting_otp_trigger';
  $('btn-recovered').disabled = st !== 'waiting_action';
  $('btn-retry').disabled     = st !== 'waiting_action';
  $('btn-fail').disabled      = st !== 'waiting_action';
  $('btn-skip').disabled      = st !== 'waiting_otp_trigger' && st !== 'waiting_action';

  const hints = {
    idle: 'Press Start to begin.',
    starting: 'Initialising…',
    running: 'Processing sessions…',
    connecting: 'Connecting to Telegram…',
    waiting_otp_trigger: `Session connected. Phone: ${s.phone_number}. Click "Send OTP" after triggering a login on that number.`,
    waiting_otp: 'Listening for OTP message from Telegram (777000)…',
    waiting_action: s.otp_code
      ? `OTP received: ${s.otp_code}. Choose: Recovered / Retry / Fail.`
      : 'OTP timed out. Choose: Retry / Fail.',
    done: '✅ All sessions processed.',
    error: '❌ Error — check logs.',
  };
  $('hint').textContent = hints[st] || '';
}

function appendLog(entry) {
  const box = $('log-box');
  const line = document.createElement('div');
  line.className = `log-line log-${entry.level}`;
  line.textContent = `[${entry.time}] ${entry.message}`;
  box.appendChild(line);
  box.scrollTop = box.scrollHeight;
}

async function doStart() {
  $('log-box').innerHTML = '';
  await fetch('/start', { method: 'POST' });
}

async function doAction(action) {
  await fetch('/action', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action }),
  });
}

// Boot
startSSE();
fetch('/state').then(r => r.json()).then(s => {
  applyState(s);
  (s.logs || []).forEach(appendLog);
});
</script>
</body>
</html>"""


# ─── Flask Routes ─────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return HTML


@app.route("/start", methods=["POST"])
def start():
    st = state["status"]
    if st not in ("idle", "done", "error"):
        return jsonify({"error": "Already running"}), 400

    state["logs"].clear()
    update_state(
        status="starting",
        current_session=None,
        phone_number=None,
        otp_code=None,
        sessions_processed=0,
        sessions_total=0,
    )

    def run():
        asyncio.run(run_bot())

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"ok": True})


@app.route("/action", methods=["POST"])
def action():
    data = request.get_json(silent=True) or {}
    act = data.get("action")
    if not act:
        return jsonify({"error": "Missing action"}), 400
    _action_value["v"] = act
    _action_event.set()
    return jsonify({"ok": True})


@app.route("/events")
def events():
    q: queue.Queue = queue.Queue(maxsize=100)
    sse_listeners.append(q)

    # Immediately send current state + recent logs to new listener
    q.put(json.dumps({"type": "state", "data": {
        k: state[k]
        for k in ["status", "current_session", "phone_number",
                  "otp_code", "sessions_processed", "sessions_total"]
    }}))
    for log_entry in state["logs"][-50:]:
        q.put(json.dumps({"type": "log", "data": log_entry}))

    def generate():
        while True:
            try:
                msg = q.get(timeout=25)
                yield f"data: {msg}\n\n"
            except queue.Empty:
                yield 'data: {"type":"ping"}\n\n'

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/state")
def get_state():
    return jsonify(state)


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# ─── Entry Point ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
