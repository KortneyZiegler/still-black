"""STILL BLACK screening access service.

Public:  GET  /api/org/<code>          org name + lock status (send X-Access-Token to check a saved unlock)
         POST /api/org/<code>/unlock   {password} -> {token}
         GET  /api/film[?code=CODE]     temporary signed link to the private film
                                       (org pages need X-Access-Token; the open page needs none)
Admin:   GET  /admin                   admin page
         /api/admin/...                requires header X-Admin-Password
Org records live in a private GCS object.
"""
import copy
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time

import google.auth
from google.auth.transport import requests as ga_requests
from flask import Flask, jsonify, request, send_file
from google.api_core.exceptions import PreconditionFailed
from google.cloud import storage

CONFIG_BUCKET = os.environ["CONFIG_BUCKET"]
CONFIG_OBJECT = "orgs.json"
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]
TOKEN_SECRET = os.environ["TOKEN_SECRET"].encode()
SITE = "https://screening.zieglerlab.online/"
FILM_BUCKET = os.environ.get("FILM_BUCKET", "still-black-streaming")
FILM_OBJECT = os.environ.get("FILM_OBJECT", "STILLBLACKfilm-captioned (1).mp4")
FILM_LINK_HOURS = 3
OPEN_PAGE_PLAYS = os.environ.get("OPEN_PAGE_PLAYS", "1") == "1"
ALLOWED_ORIGINS = {o.strip() for o in os.environ.get(
    "ALLOWED_ORIGINS", "https://screening.zieglerlab.online").split(",")}
WORDS = ("amber aspen birch bloom brook cedar clay cloud coral cove crane dawn dove ember fern "
         "finch fox glade grove harbor hazel heron iris ivy jade juniper lark laurel maple meadow "
         "mesa mint moss oak olive orchid otter pearl pine plum quill raven reed ridge river robin "
         "sage shore slate sparrow spruce stone thistle tide violet willow wren").split()

app = Flask(__name__)
gcs = storage.Client()
config_bucket = gcs.bucket(CONFIG_BUCKET)
film = gcs.bucket(FILM_BUCKET).blob(FILM_OBJECT)
signer, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
_cache = {"at": 0.0, "orgs": {}, "gen": None}
_lock = threading.Lock()
_fails = {}


def norm(code):
    return re.sub(r"[^A-Z0-9]", "", str(code).upper())


def load(fresh=False):
    """Return (orgs, generation). Callers get a copy, so a failed save never
    leaves unsaved changes in the cache."""
    with _lock:
        if fresh or time.time() - _cache["at"] > 15:
            current = config_bucket.get_blob(CONFIG_OBJECT)
            if current is None:
                _cache["orgs"], _cache["gen"] = {}, 0
            else:
                _cache["orgs"] = json.loads(current.download_as_text(if_generation_match=current.generation))
                _cache["gen"] = current.generation
            _cache["at"] = time.time()
        return copy.deepcopy(_cache["orgs"]), _cache["gen"]


def save(orgs, gen):
    config_bucket.blob(CONFIG_OBJECT).upload_from_string(
        json.dumps(orgs, indent=2, sort_keys=True),
        content_type="application/json", if_generation_match=gen)
    _cache["at"] = 0


def resolve(code):
    orgs, _ = load()
    code = norm(code)
    if code in orgs:
        return code, orgs[code]
    for k, v in orgs.items():
        if code in v.get("aliases", []):
            return k, v
    return None, None


def token_for(code, rec):
    return hmac.new(TOKEN_SECRET, f"{code}:{rec['password']}".encode(), hashlib.sha256).hexdigest()


def expired(rec):
    return bool(rec.get("until")) and dt.date.today().isoformat() > rec["until"]


def new_password():
    return f"{secrets.choice(WORDS)}-{secrets.choice(WORDS)}-{secrets.randbelow(90) + 10}"


def client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()


@app.after_request
def cors(resp):
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Access-Token, X-Admin-Password"
        resp.headers["Vary"] = "Origin"
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------- public ----------
@app.route("/api/org/<code>", methods=["GET", "OPTIONS"])
def org_info(code):
    if request.method == "OPTIONS":
        return "", 204
    key, rec = resolve(code)
    if not rec or not rec.get("active", True):
        return jsonify(found=False), 404
    unlocked = hmac.compare_digest(request.headers.get("X-Access-Token", ""), token_for(key, rec))
    return jsonify(found=True, code=key, name=rec["name"], expired=expired(rec), unlocked=unlocked)


@app.route("/api/org/<code>/unlock", methods=["POST", "OPTIONS"])
def unlock(code):
    if request.method == "OPTIONS":
        return "", 204
    ip, now = client_ip(), time.time()
    recent = [t for t in _fails.get(ip, []) if now - t < 600]
    _fails[ip] = recent
    if len(recent) >= 10:
        return jsonify(error="Too many attempts. Please wait a few minutes and try again."), 429
    key, rec = resolve(code)
    if not rec or not rec.get("active", True):
        return jsonify(error="This screening page isn't available."), 404
    if expired(rec):
        return jsonify(error="This screening license has ended. Please contact your host to renew."), 403
    entered = str((request.get_json(silent=True) or {}).get("password", "")).strip().lower()
    if not hmac.compare_digest(entered, rec["password"].lower()):
        _fails.setdefault(ip, []).append(now)
        return jsonify(error="That password doesn’t match. Check with your screening host."), 401
    return jsonify(token=token_for(key, rec))


@app.route("/api/film", methods=["GET", "OPTIONS"])
def film_link():
    if request.method == "OPTIONS":
        return "", 204
    code = request.args.get("code", "")
    if code:
        key, rec = resolve(code)
        if not rec or not rec.get("active", True) or expired(rec):
            return jsonify(error="This screening page isn't available."), 403
        if not hmac.compare_digest(request.headers.get("X-Access-Token", ""), token_for(key, rec)):
            return jsonify(error="Please enter your screening password."), 401
    elif not OPEN_PAGE_PLAYS:
        return jsonify(error="Please use your organization's screening link."), 403
    lifetime = dt.timedelta(hours=FILM_LINK_HOURS)
    signer.refresh(ga_requests.Request())
    url = film.generate_signed_url(version="v4", expiration=lifetime, method="GET",
                                   service_account_email=signer.service_account_email,
                                   access_token=signer.token)
    return jsonify(url=url, expiresAt=(dt.datetime.now(dt.timezone.utc) + lifetime).isoformat())


# ---------- admin ----------
_admin_fails = {}


def admin_ok():
    """Admin password check, locked for 15 minutes after 5 wrong tries from one address."""
    ip, now = client_ip(), time.time()
    recent = [t for t in _admin_fails.get(ip, []) if now - t < 900]
    _admin_fails[ip] = recent
    if len(recent) >= 5:
        return False
    if hmac.compare_digest(request.headers.get("X-Admin-Password", ""), ADMIN_PASSWORD):
        return True
    recent.append(now)
    return False


@app.route("/admin")
def admin_page():
    return send_file(os.path.join(os.path.dirname(__file__), "admin.html"))


@app.route("/api/admin/orgs", methods=["GET", "POST"])
def admin_orgs():
    if not admin_ok():
        time.sleep(1)
        return jsonify(error="Wrong admin password."), 401
    if request.method == "GET":
        orgs, _ = load(fresh=True)
        out = [dict(code=k, link=f"{SITE}?key={k}", expired=expired(v), **v) for k, v in orgs.items()]
        return jsonify(orgs=sorted(out, key=lambda o: o.get("created", ""), reverse=True))
    body = request.get_json(silent=True) or {}
    name = str(body.get("name", "")).strip()
    code = norm(body.get("code") or name)[:24]
    if not name or not code:
        return jsonify(error="Please enter the organization's name."), 400
    for _ in range(3):
        orgs, gen = load(fresh=True)
        if code in orgs or any(code in v.get("aliases", []) for v in orgs.values()):
            return jsonify(error=f"The code {code} is already in use. Choose a different code."), 409
        orgs[code] = {"name": name, "password": str(body.get("password") or new_password()).strip(),
                      "until": body.get("until") or "", "active": True,
                      "created": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
        try:
            save(orgs, gen)
            return jsonify(code=code, link=f"{SITE}?key={code}", **orgs[code])
        except PreconditionFailed:
            continue
    return jsonify(error="Please try again."), 409


@app.route("/api/admin/orgs/<code>", methods=["POST"])
def admin_update(code):
    if not admin_ok():
        time.sleep(1)
        return jsonify(error="Wrong admin password."), 401
    body = request.get_json(silent=True) or {}
    action = body.get("action")
    for _ in range(3):
        orgs, gen = load(fresh=True)
        code = norm(code)
        if code not in orgs:
            return jsonify(error="Organization not found."), 404
        rec = orgs[code]
        if action == "reset":
            rec["password"] = new_password()
        elif action == "until":
            rec["until"] = body.get("until") or ""
        elif action == "rename":
            rec["name"] = str(body.get("name", rec["name"])).strip() or rec["name"]
        elif action in ("disable", "enable"):
            rec["active"] = action == "enable"
        elif action == "delete":
            del orgs[code]
        else:
            return jsonify(error="Unknown action."), 400
        try:
            save(orgs, gen)
            return jsonify(ok=True, org=None if action == "delete" else dict(code=code, link=f"{SITE}?key={code}", **rec))
        except PreconditionFailed:
            continue
    return jsonify(error="Please try again."), 409


@app.route("/healthz")
def healthz():
    return "ok"
