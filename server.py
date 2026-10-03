import os
import secrets
import json
import uuid
import time
from pathlib import Path
from datetime import datetime
from functools import wraps

import boto3
import os
from flask import (
    Flask, request, jsonify, session, redirect,
    send_from_directory, make_response
)
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename


# =========================================================
# PATHS
# =========================================================

BASE = Path(__file__).resolve().parent

# Vercel's deployment filesystem is read-only.
IS_VERCEL = bool(os.environ.get("VERCEL"))

DATA_DIR = BASE / "data"
R2_ACCOUNT_ID = os.getenv("R2_ACCOUNT_ID")
R2_ACCESS_KEY_ID = os.getenv("R2_ACCESS_KEY_ID")
R2_SECRET_ACCESS_KEY = os.getenv("R2_SECRET_ACCESS_KEY")
R2_BUCKET_NAME = os.getenv("R2_BUCKET_NAME")
R2_PUBLIC_URL = os.getenv("R2_PUBLIC_URL", "").rstrip("/")

R2_ENDPOINT = f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com"

r2 = boto3.client(
    "s3",
    endpoint_url=R2_ENDPOINT,
    aws_access_key_id=R2_ACCESS_KEY_ID,
    aws_secret_access_key=R2_SECRET_ACCESS_KEY,
    region_name="auto",
)

UPLOAD_DIR = BASE / "uploads"
COVERS_DIR = UPLOAD_DIR / "covers"
VIDEOS_DIR = UPLOAD_DIR / "videos"

# Vercel bundles catalog.json at the function root.
# Local development keeps using data/catalog.json.
if IS_VERCEL:
    CATALOG_FILE = BASE / "catalog.json"
else:
    CATALOG_FILE = DATA_DIR / "catalog.json"

ADMIN_FILE = BASE / "admin_config.json"
SECRET_FILE = BASE / ".secret_key"

if not IS_VERCEL:
    DATA_DIR.mkdir(exist_ok=True)
    UPLOAD_DIR.mkdir(exist_ok=True)
    COVERS_DIR.mkdir(exist_ok=True)
    VIDEOS_DIR.mkdir(exist_ok=True)


# =========================================================
# APP
# =========================================================

app = Flask(__name__)


if os.environ.get("SECRET_KEY"):
    SECRET_KEY = os.environ["SECRET_KEY"]
elif SECRET_FILE.exists():
    SECRET_KEY = SECRET_FILE.read_text().strip()
elif not IS_VERCEL:
    SECRET_KEY = os.urandom(32).hex()
    SECRET_FILE.write_text(SECRET_KEY)
else:
    SECRET_KEY = os.urandom(32).hex()

app.secret_key = SECRET_KEY

# Session security.
# HTTPS-only cookies are enabled automatically in production.
IS_PRODUCTION = os.environ.get("DRAMAHUB_ENV", "").lower() == "production"

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
)

# Up to 2 GB per individual upload request.
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024 * 1024


# Browser security headers.
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )

    if IS_PRODUCTION:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

    return response


# =========================================================
# CATALOG
# =========================================================

DEFAULT_ANALYTICS = {
    "visits": 0,
    "unique_visitors": 0,
    "drama_views": {},
    "episode_views": {},
    "daily": {},
    "activity": []
}


def load_catalog():

    if IS_VERCEL:
        try:
            response = r2.get_object(
                Bucket=R2_BUCKET_NAME,
                Key="data/catalog.json"
            )

            data = json.loads(
                response["Body"].read().decode("utf-8")
            )

        except Exception:
            # First deployment: use the bundled catalog.json
            if CATALOG_FILE.exists():
                try:
                    data = json.loads(
                        CATALOG_FILE.read_text(
                            encoding="utf-8"
                        )
                    )
                except Exception:
                    data = {}
            else:
                data = {}

    else:

        if not CATALOG_FILE.exists():

            data = {
                "dramas": [],
                "episodes": [],
                "homepage": {
                    "hero": [],
                    "new_releases": [],
                    "trending": [],
                    "for_you": [],
                    "popular": []
                },
                "analytics": DEFAULT_ANALYTICS.copy()
            }

            save_catalog(data)
            return data

        try:
            data = json.loads(
                CATALOG_FILE.read_text(
                    encoding="utf-8"
                )
            )

        except Exception:
            data = {}

    data.setdefault("dramas", [])
    data.setdefault("episodes", [])

    data.setdefault("homepage", {})

    for section in [
        "hero",
        "new_releases",
        "trending",
        "for_you",
        "popular"
    ]:
        data["homepage"].setdefault(section, [])

    data.setdefault("analytics", {})

    for key, value in DEFAULT_ANALYTICS.items():

        if key not in data["analytics"]:

            if isinstance(value, dict):
                data["analytics"][key] = {}

            elif isinstance(value, list):
                data["analytics"][key] = []

            else:
                data["analytics"][key] = value

    return data


def save_catalog(data):

    if IS_VERCEL:

        r2.put_object(
            Bucket=R2_BUCKET_NAME,
            Key="data/catalog.json",
            Body=json.dumps(
                data,
                indent=2,
                ensure_ascii=False
            ).encode("utf-8"),
            ContentType="application/json"
        )

        return

    temp = CATALOG_FILE.with_suffix(".tmp")

    temp.write_text(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    temp.replace(CATALOG_FILE)



# =========================================================
# AUTH
# =========================================================

def get_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def validate_csrf():
    expected = session.get("csrf_token")
    provided = request.headers.get("X-CSRF-Token", "")

    if not expected or not provided or not secrets.compare_digest(
        expected, provided
    ):
        return False

    return True


def admin_required(fn):

    @wraps(fn)
    def wrapper(*args, **kwargs):

        if not session.get("admin_logged_in"):

            if request.path.startswith("/api/"):

                return jsonify({
                    "error": "Authentication required"
                }), 401

            return redirect("/admin/login")

        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            if not validate_csrf():
                return jsonify({
                    "error": "CSRF validation failed"
                }), 403

        return fn(*args, **kwargs)

    return wrapper


# =========================================================
# ACTIVITY
# =========================================================

def record_activity(action, details=""):

    data = load_catalog()

    activity = data["analytics"].setdefault(
        "activity",
        []
    )

    activity.insert(
        0,
        {
            "time": datetime.now().isoformat(
                timespec="seconds"
            ),
            "action": action,
            "details": details
        }
    )

    data["analytics"]["activity"] = activity[:100]

    save_catalog(data)


# =========================================================
# SECURITY HELPERS
# =========================================================

def safe_path(root, filename):

    filename = secure_filename(filename)

    path = (root / filename).resolve()

    if root.resolve() not in path.parents:
        return None

    return path


def allowed_video(filename):

    return Path(
        filename or ""
    ).suffix.lower() in {
        ".mp4",
        ".webm",
        ".mov",
        ".m4v",
        ".mkv"
    }


# =========================================================
# VIDEO WATERMARK
# =========================================================

WATERMARK_FILE = BASE / "short_reels_watermark.png"


def watermark_video(input_path, output_path):
    """Burn the Short Reels watermark into a video using FFmpeg."""
    import subprocess

    if not WATERMARK_FILE.exists():
        raise RuntimeError(
            f"Watermark file not found: {WATERMARK_FILE}"
        )

    cmd = [
        "ffmpeg",
        "-hide_banner",
        "-loglevel", "error",
        "-y",
        "-i", str(input_path),
        "-i", str(WATERMARK_FILE),
        "-filter_complex",
        "[1:v]format=rgba,colorchannelmixer=aa=0.85[wm];"
        "[0:v][wm]overlay=W-w-18:18:format=auto,"
        "format=yuv420p[v]",
        "-map", "[v]",
        "-map", "0:a?",
        "-c:v", "libx264",
        "-preset", "ultrafast",
        "-crf", "23",
        "-threads", "0",
        "-c:a", "aac",
        "-b:a", "128k",
        "-movflags", "+faststart",
        str(output_path),
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        try:
            Path(output_path).unlink(missing_ok=True)
        except Exception:
            pass

        raise RuntimeError(
            "FFmpeg watermarking failed: "
            + (result.stderr[-2000:] or "unknown error")
        )


def allowed_image(filename):

    return Path(
        filename or ""
    ).suffix.lower() in {
        ".jpg",
        ".jpeg",
        ".png",
        ".webp"
    }


def find_drama(data, drama_id):

    return next(
        (
            drama
            for drama in data["dramas"]
            if drama.get("id") == drama_id
        ),
        None
    )


def find_episode(data, episode_id):

    return next(
        (
            episode
            for episode in data["episodes"]
            if episode.get("id") == episode_id
        ),
        None
    )


def update_episode_count(data, drama_id):

    drama = find_drama(data, drama_id)

    if drama:

        drama["episodes"] = len([
            episode
            for episode in data["episodes"]
            if episode.get("drama_id") == drama_id
        ])


# =========================================================
# WEBSITE
# =========================================================

@app.route("/drama/<drama_id>")
def public_drama_page(drama_id):
    data = load_catalog()
    drama = find_drama(data, drama_id)

    if not drama or not drama.get("published", False):
        return "Drama not found", 404

    title = str(drama.get("title", "Short Reels"))
    description = str(
        drama.get("description")
        or f"Watch {title} on Short Reels."
    )
    cover = str(drama.get("cover", ""))

    base = request.url_root.rstrip("/")
    if cover.startswith("/"):
        cover_url = base + cover
    else:
        cover_url = cover

    safe_title = title.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    safe_description = (
        description.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{safe_title} - Short Reels</title>
<meta name="description" content="{safe_description}">
<meta name="robots" content="index, follow">
<link rel="canonical" href="{base}/drama/{drama_id}">
<meta property="og:type" content="video.other">
<meta property="og:site_name" content="Short Reels">
<meta property="og:title" content="{safe_title} - Short Reels">
<meta property="og:description" content="{safe_description}">
<meta property="og:url" content="{base}/drama/{drama_id}">
{"<meta property=\"og:image\" content=\"" + cover_url + "\">" if cover_url else ""}
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{safe_title} - Short Reels">
<meta name="twitter:description" content="{safe_description}">
{"<meta name=\"twitter:image\" content=\"" + cover_url + "\">" if cover_url else ""}
</head>
<body>
<main>
<h1>{safe_title}</h1>
<p>{safe_description}</p>
{f'<img src="{cover_url}" alt="{safe_title}">' if cover_url else ""}
<p><a href="/#/watch/{drama_id}/1">Watch on Short Reels</a></p>
</main>
</body>
</html>"""

    return html, 200, {"Content-Type": "text/html; charset=utf-8"}


@app.route("/privacy")
def privacy():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Privacy Policy | Short Reels</title>
  <meta name="description" content="Read the Short Reels Privacy Policy to learn how cookies, visitor information, and website usage data are handled.">
  <meta name="robots" content="index, follow">

  <style>
    *{box-sizing:border-box}

    body{
      margin:0;
      background:#0b0b0b;
      color:#f5f5f5;
      font-family:Arial,Helvetica,sans-serif;
      line-height:1.7;
    }

    .privacy-page{
      width:100%;
      max-width:900px;
      margin:0 auto;
      padding:55px 24px 80px;
    }

    .brand{
      display:inline-block;
      margin-bottom:35px;
      color:#fff;
      text-decoration:none;
      font-size:18px;
      font-weight:700;
    }

    h1{
      margin:0 0 8px;
      font-size:38px;
      line-height:1.2;
      letter-spacing:-.5px;
    }

    .updated{
      margin:0 0 45px;
      color:#888;
      font-size:14px;
    }

    h2{
      margin:38px 0 12px;
      font-size:22px;
      line-height:1.3;
      color:#fff;
    }

    p{
      margin:0 0 18px;
      color:#cfcfcf;
      font-size:15px;
    }

    a{
      color:#fff;
    }

    .contact-box{
      margin-top:20px;
      padding:22px;
      background:#151515;
      border:1px solid #2b2b2b;
      border-radius:12px;
    }

    .contact-box p{
      margin:0;
    }

    .contact-email{
      display:inline-block;
      margin-top:6px;
      font-weight:700;
      text-decoration:none;
    }

    .back{
      display:inline-block;
      margin-top:45px;
      padding:11px 18px;
      border:1px solid #333;
      border-radius:8px;
      text-decoration:none;
      font-size:14px;
    }

    .back:hover{
      background:#181818;
    }

    @media(max-width:600px){
      .privacy-page{
        padding:35px 20px 60px;
      }

      h1{
        font-size:32px;
      }

      h2{
        font-size:20px;
      }

      p{
        font-size:14px;
      }
    }
  </style>
</head>

<body>
  <main class="privacy-page">

    <a class="brand" href="/">Short Reels</a>

    <h1>Privacy Policy</h1>
    <p class="updated">Last updated: September 25, 2026</p>

    <p>
      At Short Reels, we respect your privacy and are committed to being
      transparent about how our website uses cookies and limited visitor
      information.
    </p>

    <h2>1. Information We Collect</h2>

    <p>
      Short Reels may use cookies and similar technologies to keep the website
      functioning, remember preferences, maintain security, and understand
      general website usage.
    </p>

    <p>
      Our website may use a randomly generated visitor identifier to help us
      measure unique visits and understand overall traffic. This identifier is
      not intended to directly identify you by name.
    </p>

    <h2>2. Cookies</h2>

    <p>
      Cookies are small pieces of information stored by your web browser.
      Short Reels may use cookies for essential website functionality,
      visitor measurement, preferences, and cookie-consent management.
    </p>

    <h2>3. How We Use Information</h2>

    <p>
      Information associated with your use of Short Reels may be used to
      operate, maintain, secure, improve, and understand the performance of
      our website and services.
    </p>

    <h2>4. Personal Information</h2>

    <p>
      Short Reels does not sell your personal information to third parties.
      We aim to collect and use only information reasonably necessary for
      operating and improving the website.
    </p>

    <h2>5. Third-Party Services</h2>

    <p>
      Short Reels may use third-party providers for hosting, infrastructure,
      analytics, video delivery, security, or other website functions.
      These providers may process information as necessary to provide their
      services and may have their own privacy policies.
    </p>

    <h2>6. Your Choices</h2>

    <p>
      You can control or delete cookies through your browser settings.
      Please note that disabling certain cookies may affect some website
      functionality.
    </p>

    <h2>7. Changes to This Privacy Policy</h2>

    <p>
      We may update this Privacy Policy from time to time to reflect changes
      to our services, technology, or legal requirements. Any updates will be
      published on this page together with a revised "Last updated" date.
    </p>

    <h2>8. Contact Us</h2>

    <div class="contact-box">
      <p>
        If you have questions, concerns, or requests regarding this Privacy
        Policy or the privacy practices of Short Reels, please contact us at:
      </p>

      <a class="contact-email" href="mailto:shortreels432@gmail.com">
        shortreels432@gmail.com
      </a>
    </div>

    <a class="back" href="/">← Back to Short Reels</a>

  </main>
</body>
</html>
"""

@app.route("/robots.txt")
def robots_txt():
    return (
        "User-agent: *\n"
        "Allow: /\n\n"
        "Sitemap: /sitemap.xml\n",
        200,
        {"Content-Type": "text/plain; charset=utf-8"}
    )


@app.route("/sitemap.xml")
def sitemap_xml():
    base = request.url_root.rstrip("/")
    data = load_catalog()

    urls = [f"{base}/"]

    for drama in data.get("dramas", []):
        if drama.get("published", False) and drama.get("id"):
            urls.append(f"{base}/drama/{drama['id']}")

    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
    ]

    for url in urls:
        parts.append(f"<url><loc>{url}</loc></url>")

    parts.append("</urlset>")

    return "\n".join(parts), 200, {
        "Content-Type": "application/xml; charset=utf-8"
    }


@app.route("/")
def home():

    response = make_response(
        send_from_directory(
            BASE,
            "index.html"
        )
    )

    visitor_id = request.cookies.get(
        "sr_visitor"
    )

    data = load_catalog()

    today = datetime.now().strftime(
        "%Y-%m-%d"
    )

    data["analytics"]["daily"].setdefault(
        today,
        {
            "visits": 0,
            "unique_visitors": 0
        }
    )

    data["analytics"]["visits"] += 1

    data["analytics"]["daily"][today][
        "visits"
    ] += 1

    if not visitor_id:

        visitor_id = uuid.uuid4().hex

        response.set_cookie(
            "sr_visitor",
            visitor_id,
            max_age=60 * 60 * 24 * 365,
            httponly=True,
            samesite="Lax"
        )

        data["analytics"]["unique_visitors"] += 1

        data["analytics"]["daily"][today][
            "unique_visitors"
        ] += 1

    save_catalog(data)

    return response


@app.route("/images/<path:filename>")
def images(filename):

    return send_from_directory(
        BASE / "images",
        filename
    )


@app.route("/videos/<path:filename>")
def videos(filename):

    return send_from_directory(
        BASE / "videos",
        filename
    )


@app.route("/uploads/<path:filename>")
def uploads(filename):

    return send_from_directory(
        UPLOAD_DIR,
        filename
    )


# =========================================================
# ADMIN PAGES
# =========================================================

@app.route("/admin")
def admin():

    if session.get("admin_logged_in"):
        return redirect("/admin/dashboard")

    return redirect("/admin/login")


@app.route("/admin/login")
def admin_login_page():

    return send_from_directory(
        BASE / "admin",
        "login.html"
    )


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():

    return send_from_directory(
        BASE / "admin",
        "dashboard.html"
    )


# =========================================================
# LOGIN RATE LIMITING
# =========================================================

LOGIN_ATTEMPTS = {}
LOGIN_WINDOW_SECONDS = 600
LOGIN_MAX_FAILURES = 5
LOGIN_LOCKOUT_SECONDS = 900


def get_client_ip():
    # Do not trust forwarded headers directly here.
    return request.remote_addr or "unknown"


def login_rate_limited(ip):
    now = time.time()
    entry = LOGIN_ATTEMPTS.get(ip)

    if not entry:
        return False

    if now - entry["first_attempt"] > LOGIN_WINDOW_SECONDS:
        LOGIN_ATTEMPTS.pop(ip, None)
        return False

    return (
        entry["failures"] >= LOGIN_MAX_FAILURES
        and now - entry["last_failure"] < LOGIN_LOCKOUT_SECONDS
    )


def record_login_failure(ip):
    now = time.time()
    entry = LOGIN_ATTEMPTS.get(ip)

    if not entry or now - entry["first_attempt"] > LOGIN_WINDOW_SECONDS:
        LOGIN_ATTEMPTS[ip] = {
            "first_attempt": now,
            "last_failure": now,
            "failures": 1,
        }
        return

    entry["failures"] += 1
    entry["last_failure"] = now


def clear_login_failures(ip):
    LOGIN_ATTEMPTS.pop(ip, None)


# =========================================================
# ADMIN AUTH
# =========================================================

@app.route(
    "/api/admin/login",
    methods=["POST"]
)
def admin_login():

    client_ip = get_client_ip()

    if login_rate_limited(client_ip):
        return jsonify({
            "error": "Too many failed login attempts. Please try again later."
        }), 429

    # Production uses Vercel environment variables.
    # Local development continues to use admin_config.json.
    if os.environ.get("ADMIN_USERNAME") and os.environ.get("ADMIN_PASSWORD_HASH"):
        admin = {
            "username": os.environ.get("ADMIN_USERNAME", ""),
            "email": os.environ.get("ADMIN_EMAIL", ""),
            "password_hash": os.environ.get("ADMIN_PASSWORD_HASH", "")
        }
    else:
        if not ADMIN_FILE.exists():
            return jsonify({
                "error": "Admin configuration is missing."
            }), 500

        try:
            admin = json.loads(
                ADMIN_FILE.read_text(
                    encoding="utf-8"
                )
            )
        except Exception:
            return jsonify({
                "error": "Admin configuration is invalid."
            }), 500

    body = request.get_json(
        silent=True
    ) or {}

    identity = str(
        body.get("identity", "")
    ).strip().lower()

    password = str(
        body.get("password", "")
    )

    valid_identity = (
        identity
        == str(
            admin.get("username", "")
        ).lower()
        or
        identity
        == str(
            admin.get("email", "")
        ).lower()
    )

    valid_password = check_password_hash(
        admin.get("password_hash", ""),
        password
    )

    if not valid_identity or not valid_password:

        record_login_failure(client_ip)

        return jsonify({
            "error":
            "Invalid username/email or password."
        }), 401

    clear_login_failures(client_ip)

    session.clear()

    session["admin_logged_in"] = True
    session["csrf_token"] = secrets.token_urlsafe(32)

    session["admin_username"] = (
        admin.get("username", "")
    )

    record_activity(
        "admin_login",
        "Administrator signed in"
    )

    return jsonify({
        "ok": True,
        "redirect":
        "/admin/dashboard"
    })


@app.route(
    "/api/admin/logout",
    methods=["POST"]
)
def admin_logout():

    if session.get("admin_logged_in"):

        record_activity(
            "admin_logout",
            "Administrator signed out"
        )

    session.clear()

    return jsonify({
        "ok": True
    })


@app.route("/api/admin/csrf")
@admin_required
def admin_csrf():
    return jsonify({
        "csrf_token": get_csrf_token()
    })


@app.route("/api/admin/me")
@admin_required
def admin_me():

    return jsonify({
        "logged_in": True,
        "username":
        session.get("admin_username")
    })


# =========================================================
# DRAMAS
# =========================================================

@app.route("/api/dramas")
@admin_required
def get_dramas():

    return jsonify(
        load_catalog()["dramas"]
    )


@app.route(
    "/api/dramas",
    methods=["POST"]
)
@admin_required
def create_drama():

    body = request.get_json(
        silent=True
    ) or {}

    title = str(
        body.get("title", "")
    ).strip()

    if not title:

        return jsonify({
            "error":
            "Drama title is required"
        }), 400

    data = load_catalog()

    requested_id = str(
        body.get("id", "")
    ).strip()

    drama_id = secure_filename(
        requested_id
        or
        title.lower().replace(
            " ",
            "_"
        )
    )

    if not drama_id:

        drama_id = uuid.uuid4().hex[:12]

    if find_drama(
        data,
        drama_id
    ):

        return jsonify({
            "error":
            "Drama ID already exists"
        }), 409

    tags = body.get(
        "tags",
        []
    )

    if isinstance(tags, str):

        tags = [
            x.strip()
            for x in tags.split(",")
            if x.strip()
        ]

    placements = body.get(
        "placements",
        []
    )

    if not isinstance(
        placements,
        list
    ):

        placements = []

    drama = {

        "id": drama_id,

        "title": title,

        "description":
        str(
            body.get(
                "description",
                ""
            )
        ),

        "cover":
        str(
            body.get(
                "cover",
                ""
            )
        ),

        "category":
        str(
            body.get(
                "category",
                ""
            )
        ),

        "tags": tags,

        "placements":
        placements,

        "published":
        bool(
            body.get(
                "published",
                True
            )
        ),

        "episodes": 0,

        "created_at":
        datetime.now().isoformat(
            timespec="seconds"
        ),

        "updated_at":
        datetime.now().isoformat(
            timespec="seconds"
        )
    }

    data["dramas"].append(
        drama
    )

    save_catalog(data)

    record_activity(
        "drama_created",
        title
    )

    return jsonify(
        drama
    ), 201


@app.route(
    "/api/dramas/<drama_id>",
    methods=["PUT"]
)
@admin_required
def update_drama(drama_id):

    data = load_catalog()

    drama = find_drama(
        data,
        drama_id
    )

    if not drama:

        return jsonify({
            "error":
            "Drama not found"
        }), 404

    body = request.get_json(
        silent=True
    ) or {}

    allowed = [
        "title",
        "description",
        "cover",
        "category",
        "tags",
        "placements",
        "published"
    ]

    for key in allowed:

        if key in body:

            value = body[key]

            if key == "tags":

                if isinstance(
                    value,
                    str
                ):

                    value = [
                        x.strip()
                        for x in value.split(",")
                        if x.strip()
                    ]

                elif not isinstance(
                    value,
                    list
                ):

                    value = []

            if key == "placements":

                if not isinstance(
                    value,
                    list
                ):

                    value = []

            drama[key] = value

    drama["updated_at"] = (
        datetime.now().isoformat(
            timespec="seconds"
        )
    )

    save_catalog(data)

    record_activity(
        "drama_updated",
        drama.get(
            "title",
            drama_id
        )
    )

    return jsonify(
        drama
    )


@app.route(
    "/api/dramas/<drama_id>",
    methods=["DELETE"]
)
@admin_required
def delete_drama(drama_id):

    data = load_catalog()

    drama = find_drama(
        data,
        drama_id
    )

    if not drama:

        return jsonify({
            "error":
            "Drama not found"
        }), 404

    title = drama.get(
        "title",
        drama_id
    )

    # Remove uploaded episode files.
    for episode in list(
        data["episodes"]
    ):

        if episode.get(
            "drama_id"
        ) != drama_id:

            continue

        video_url = episode.get(
            "video",
            ""
        )

        if video_url.startswith(
            "/uploads/videos/"
        ):

            filename = video_url.split(
                "/uploads/videos/",
                1
            )[1]

            path = safe_path(
                VIDEOS_DIR,
                filename
            )

            if path and path.exists():

                try:
                    path.unlink()
                except Exception:
                    pass

    data["dramas"] = [
        d
        for d in data["dramas"]
        if d.get("id") != drama_id
    ]

    data["episodes"] = [
        e
        for e in data["episodes"]
        if e.get("drama_id") != drama_id
    ]

    # Remove deleted drama from homepage
    # placement lists.
    for section in data[
        "homepage"
    ]:

        data["homepage"][section] = [
            x
            for x in data[
                "homepage"
            ][section]
            if x != drama_id
        ]

    save_catalog(data)

    record_activity(
        "drama_deleted",
        title
    )

    return jsonify({
        "ok": True
    })


# =========================================================
# EPISODES — READ
# =========================================================

@app.route("/api/admin/backup", methods=["POST"])
@admin_required
def create_admin_backup():
    import tarfile
    stamp=datetime.now().strftime("%Y%m%d_%H%M%S")
    backup=BASE.parent / f"Dramahub_backup_{stamp}.tar.gz"
    with tarfile.open(backup, "w:gz") as t:
        for item in BASE.iterdir():
            if item.name == "uploads":
                continue
            t.add(item, arcname=f"Dramahub/{item.name}")
    return jsonify({"success": True, "file": backup.name})

@app.route("/api/episodes")
@admin_required
def get_episodes():

    data = load_catalog()

    drama_id = request.args.get(
        "drama_id"
    )

    episodes = data[
        "episodes"
    ]

    if drama_id:

        episodes = [
            e
            for e in episodes
            if e.get(
                "drama_id"
            ) == drama_id
        ]

    result = []

    for episode in episodes:

        item = dict(
            episode
        )

        drama = find_drama(
            data,
            episode.get(
                "drama_id"
            )
        )

        item["drama_title"] = (
            drama.get("title")
            if drama
            else "Unknown"
        )

        result.append(item)

    result.sort(
        key=lambda x: (
            x.get(
                "drama_title",
                ""
            ).lower(),
            int(
                x.get(
                    "number",
                    0
                )
            )
        )
    )

    return jsonify(
        result
    )



# =========================================================
# EPISODE CREATOR — R2 SOURCE UPLOAD + SPLIT JOB
# =========================================================

@app.route("/api/episode-creator/presign", methods=["POST"])
@admin_required
def episode_creator_presign():

    body = request.get_json(silent=True) or {}

    filename = str(body.get("filename") or "").strip()
    content_type = str(
        body.get("content_type") or "video/mp4"
    ).strip()

    if not filename:
        return jsonify({"error": "Source filename is required"}), 400

    if not allowed_video(filename):
        return jsonify({
            "error": "Unsupported video format"
        }), 400

    extension = Path(filename).suffix.lower() or ".mp4"
    source_id = uuid.uuid4().hex

    key = f"sources/{source_id}{extension}"

    try:
        upload_url = r2.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": R2_BUCKET_NAME,
                "Key": key,
                "ContentType": content_type
            },
            ExpiresIn=3600
        )

        public_url = f"{R2_PUBLIC_URL}/{key}"

        return jsonify({
            "ok": True,
            "key": key,
            "upload_url": upload_url,
            "url": public_url
        })

    except Exception as e:
        return jsonify({
            "error": f"Could not create upload URL: {str(e)}"
        }), 500




@app.route("/api/episode-creator/multipart/init", methods=["POST"])
@admin_required
def episode_creator_multipart_init():

    body = request.get_json(silent=True) or {}

    filename = str(body.get("filename") or "").strip()
    content_type = str(
        body.get("content_type") or "video/mp4"
    ).strip()

    if not filename:
        return jsonify({
            "error": "Source filename is required"
        }), 400

    if not allowed_video(filename):
        return jsonify({
            "error": "Unsupported video format"
        }), 400

    extension = Path(filename).suffix.lower() or ".mp4"
    source_id = uuid.uuid4().hex
    key = f"sources/{source_id}{extension}"

    try:
        result = r2.create_multipart_upload(
            Bucket=R2_BUCKET_NAME,
            Key=key,
            ContentType=content_type
        )

        return jsonify({
            "ok": True,
            "key": key,
            "upload_id": result["UploadId"],
            "url": f"{R2_PUBLIC_URL}/{key}",
            "content_type": content_type
        })

    except Exception as e:
        return jsonify({
            "error": f"Could not start multipart upload: {str(e)}"
        }), 500


@app.route("/api/episode-creator/multipart/part-url", methods=["POST"])
@admin_required
def episode_creator_multipart_part_url():

    body = request.get_json(silent=True) or {}

    key = str(body.get("key") or "").strip()
    upload_id = str(body.get("upload_id") or "").strip()

    try:
        part_number = int(body.get("part_number") or 0)
    except Exception:
        part_number = 0

    if not key or not upload_id or part_number < 1:
        return jsonify({
            "error": "key, upload_id and part_number are required"
        }), 400

    try:
        upload_url = r2.generate_presigned_url(
            "upload_part",
            Params={
                "Bucket": R2_BUCKET_NAME,
                "Key": key,
                "UploadId": upload_id,
                "PartNumber": part_number
            },
            ExpiresIn=3600
        )

        return jsonify({
            "ok": True,
            "upload_url": upload_url,
            "part_number": part_number
        })

    except Exception as e:
        return jsonify({
            "error": f"Could not create part upload URL: {str(e)}"
        }), 500


@app.route("/api/episode-creator/multipart/complete", methods=["POST"])
@admin_required
def episode_creator_multipart_complete():

    body = request.get_json(silent=True) or {}

    key = str(body.get("key") or "").strip()
    upload_id = str(body.get("upload_id") or "").strip()
    parts = body.get("parts") or []

    if not key or not upload_id:
        return jsonify({
            "error": "key and upload_id are required"
        }), 400

    if not isinstance(parts, list) or not parts:
        return jsonify({
            "error": "Multipart parts are required"
        }), 400

    clean_parts = []

    try:
        for part in parts:
            part_number = int(part.get("PartNumber"))
            etag = str(part.get("ETag") or "").strip()

            if part_number < 1 or not etag:
                raise ValueError("Invalid multipart part")

            clean_parts.append({
                "PartNumber": part_number,
                "ETag": etag
            })

        clean_parts.sort(key=lambda x: x["PartNumber"])

        result = r2.complete_multipart_upload(
            Bucket=R2_BUCKET_NAME,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={
                "Parts": clean_parts
            }
        )

        return jsonify({
            "ok": True,
            "key": key,
            "url": f"{R2_PUBLIC_URL}/{key}",
            "etag": result.get("ETag")
        })

    except Exception as e:
        return jsonify({
            "error": f"Could not complete multipart upload: {str(e)}"
        }), 500


@app.route("/api/episode-creator/multipart/abort", methods=["POST"])
@admin_required
def episode_creator_multipart_abort():

    body = request.get_json(silent=True) or {}

    key = str(body.get("key") or "").strip()
    upload_id = str(body.get("upload_id") or "").strip()

    if not key or not upload_id:
        return jsonify({
            "error": "key and upload_id are required"
        }), 400

    try:
        r2.abort_multipart_upload(
            Bucket=R2_BUCKET_NAME,
            Key=key,
            UploadId=upload_id
        )

        return jsonify({
            "ok": True
        })

    except Exception as e:
        return jsonify({
            "error": f"Could not abort multipart upload: {str(e)}"
        }), 500


@app.route("/api/episode-creator/auto-segments", methods=["POST"])
@admin_required
def auto_episode_segments():

    body = request.get_json(silent=True) or {}

    try:
        duration = float(body.get("duration", 0))
    except (TypeError, ValueError):
        duration = 0

    if duration <= 0:
        return jsonify({
            "error": "Valid video duration is required"
        }), 400

    drama_id = str(body.get("drama_id") or "").strip()

    if not drama_id:
        return jsonify({
            "error": "Drama is required"
        }), 400

    data = load_catalog()

    drama = find_drama(data, drama_id)

    if not drama:
        return jsonify({
            "error": "Drama not found"
        }), 404

    # 2.5 minutes = 150 seconds
    EPISODE_LENGTH = 150

    existing_numbers = {
        int(e.get("number", 0))
        for e in data.get("episodes", [])
        if e.get("drama_id") == drama_id
    }

    episode_count = int(
        (duration + EPISODE_LENGTH - 0.001)
        // EPISODE_LENGTH
    )

    # Start after the highest existing episode number.
    next_number = max(existing_numbers, default=0) + 1

    segments = []

    for index in range(episode_count):

        start = index * EPISODE_LENGTH
        end = min(
            start + EPISODE_LENGTH,
            duration
        )

        number = next_number + index

        segments.append({
            "number": number,
            "start": round(start, 3),
            "end": round(end, 3),
            "title": f"Episode {number}",
            "thumbnail": "",
            "status": "queued"
        })

    return jsonify({
        "ok": True,
        "episode_length": EPISODE_LENGTH,
        "duration": round(duration, 3),
        "count": len(segments),
        "segments": segments
    })


@app.route("/api/episode-creator/job", methods=["POST"])
@admin_required
def create_episode_creator_job():

    body = request.get_json(silent=True) or {}

    drama_id = str(body.get("drama_id") or "").strip()
    source_key = str(body.get("source_key") or "").strip()
    source_url = str(body.get("source_url") or "").strip()
    segments = body.get("segments") or []

    if not drama_id:
        return jsonify({"error": "Drama is required"}), 400

    if not source_key:
        return jsonify({"error": "Source video is required"}), 400

    if not isinstance(segments, list) or not segments:
        return jsonify({"error": "At least one episode segment is required"}), 400

    data = load_catalog()

    drama = find_drama(data, drama_id)

    if not drama:
        return jsonify({"error": "Drama not found"}), 404

    clean_segments = []

    for index, segment in enumerate(segments, start=1):

        try:
            number = int(segment.get("number", index))
            start = float(segment.get("start", 0))
            end = float(segment.get("end", 0))
        except (TypeError, ValueError):
            return jsonify({
                "error": f"Invalid segment {index}"
            }), 400

        if number < 1:
            return jsonify({
                "error": f"Invalid episode number in segment {index}"
            }), 400

        if start < 0 or end <= start:
            return jsonify({
                "error": f"Invalid time range in segment {index}"
            }), 400

        clean_segments.append({
            "number": number,
            "start": round(start, 3),
            "end": round(end, 3),
            "title": str(
                segment.get("title")
                or f"Episode {number}"
            ).strip(),
            "thumbnail": str(
                segment.get("thumbnail") or ""
            ).strip(),
            "status": "queued"
        })

    existing_numbers = {
        int(e.get("number", 0))
        for e in data.get("episodes", [])
        if e.get("drama_id") == drama_id
    }

    duplicates = [
        x["number"]
        for x in clean_segments
        if x["number"] in existing_numbers
    ]

    if duplicates:
        return jsonify({
            "error": (
                "These episode numbers already exist: "
                + ", ".join(map(str, duplicates))
            )
        }), 409

    job = {
        "id": uuid.uuid4().hex,
        "type": "episode_split",
        "status": "queued",
        "progress": 0,
        "drama_id": drama_id,
        "drama_title": drama.get("title", ""),
        "source_key": source_key,
        "source_url": source_url,
        "segments": clean_segments,
        "created_at": datetime.now().isoformat(
            timespec="seconds"
        ),
        "updated_at": datetime.now().isoformat(
            timespec="seconds"
        )
    }

    data.setdefault("episode_jobs", [])
    data["episode_jobs"].append(job)

    save_catalog(data)

    record_activity(
        "episode_split_job_created",
        (
            f"{drama.get('title', drama_id)} "
            f"- {len(clean_segments)} episode(s)"
        )
    )

    return jsonify({
        "ok": True,
        "job": job
    }), 201


@app.route("/api/episode-creator/jobs/<job_id>")
@admin_required
def get_episode_creator_job(job_id):

    data = load_catalog()

    job = next(
        (
            x for x in data.get("episode_jobs", [])
            if x.get("id") == job_id
        ),
        None
    )

    if not job:
        return jsonify({
            "error": "Job not found"
        }), 404

    return jsonify(job)



# =========================================================
# EPISODES — DIRECT R2 UPLOAD
# =========================================================

@app.route("/api/episodes/presign", methods=["POST"])
@admin_required
def episode_presign():

    body = request.get_json(silent=True) or {}

    filename = str(body.get("filename") or "").strip()
    content_type = str(
        body.get("content_type") or "video/mp4"
    ).strip()

    if not filename:
        return jsonify({
            "error": "Video filename is required"
        }), 400

    if not allowed_video(filename):
        return jsonify({
            "error": "Unsupported video format"
        }), 400

    extension = Path(filename).suffix.lower() or ".mp4"
    upload_id = uuid.uuid4().hex
    key = f"episodes/{upload_id}{extension}"

    try:
        upload_url = r2.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": R2_BUCKET_NAME,
                "Key": key,
                "ContentType": content_type
            },
            ExpiresIn=3600
        )

        public_url = f"{R2_PUBLIC_URL}/{key}"

        return jsonify({
            "ok": True,
            "key": key,
            "url": public_url,
            "upload_url": upload_url,
            "content_type": content_type
        })

    except Exception as e:
        return jsonify({
            "error": f"Could not create upload URL: {str(e)}"
        }), 500


# =========================================================
# EPISODES — CREATE
# =========================================================

@app.route(
    "/api/episodes",
    methods=["POST"]
)
@admin_required
def create_episode():

    is_json = bool(
        request.content_type
        and request.content_type.startswith(
            "application/json"
        )
    )

    if is_json:

        body = request.get_json(
            silent=True
        ) or {}

        drama_id = str(
            body.get("drama_id") or ""
        ).strip()

        number = str(
            body.get("number") or ""
        ).strip()

        title = str(
            body.get("title") or ""
        ).strip()

        video_key = str(
            body.get("video_key") or ""
        ).strip()

        video = None

    else:

        drama_id = request.form.get(
            "drama_id",
            ""
        ).strip()

        number = request.form.get(
            "number",
            ""
        ).strip()

        title = request.form.get(
            "title",
            ""
        ).strip()

        video = request.files.get(
            "video"
        )

        video_key = ""

    if not drama_id or not number:

        return jsonify({
            "error":
            "Drama and episode number are required"
        }), 400

    data = load_catalog()

    drama = find_drama(
        data,
        drama_id
    )

    if not drama:

        return jsonify({
            "error":
            "Drama not found"
        }), 404

    try:

        ep_number = int(number)

        if ep_number < 1:
            raise ValueError

    except ValueError:

        return jsonify({
            "error":
            "Invalid episode number"
        }), 400

    duplicate = next(
        (
            e
            for e in data["episodes"]
            if e.get("drama_id") == drama_id
            and int(
                e.get("number", 0)
            ) == ep_number
        ),
        None
    )

    if duplicate:

        return jsonify({
            "error":
            "That episode number already exists"
        }), 409

    # -----------------------------------------------------
    # New direct-to-R2 upload path.
    # -----------------------------------------------------
    if is_json:

        if not video_key:

            return jsonify({
                "error":
                "Video upload is required"
            }), 400

        if not video_key.startswith(
            "episodes/"
        ):

            return jsonify({
                "error":
                "Invalid episode upload"
            }), 400

        video_url = (
            f"{R2_PUBLIC_URL}/{video_key}"
        )

    # -----------------------------------------------------
    # Existing multipart path kept as fallback.
    # -----------------------------------------------------
    else:

        if not video:

            return jsonify({
                "error":
                "Video file is required"
            }), 400

        if not allowed_video(
            video.filename
        ):

            return jsonify({
                "error":
                "Unsupported video format"
            }), 400

        extension = (
            Path(video.filename)
            .suffix
            .lower()
            or ".mp4"
        )

        filename = (
            f"ep_{ep_number}_"
            f"{uuid.uuid4().hex[:10]}"
            f"{extension}"
        )

        destination = (
            VIDEOS_DIR /
            filename
        )

        try:

            video.save(
                destination
            )

        except Exception as e:

            try:
                destination.unlink(
                    missing_ok=True
                )
            except Exception:
                pass

            return jsonify({
                "error":
                str(e)
            }), 500

        video_url = (
            f"/uploads/videos/{filename}"
        )

    now = datetime.now().isoformat(
        timespec="seconds"
    )

    episode = {

        "id":
        uuid.uuid4().hex,

        "drama_id":
        drama_id,

        "number":
        ep_number,

        "title":
        title
        or
        f"Episode {ep_number}",

        "video":
        video_url,

        "created_at":
        now,

        "updated_at":
        now
    }

    data["episodes"].append(
        episode
    )

    update_episode_count(
        data,
        drama_id
    )

    # Move the drama to the front whenever a new episode is added.
    drama["updated_at"] = now

    save_catalog(
        data
    )

    record_activity(
        "episode_added",
        (
            f"{drama.get('title', drama_id)}"
            f" - Episode {ep_number}"
        )
    )

    return jsonify(
        episode
    ), 201




# =========================================================
# EPISODES — BULK CREATE
# =========================================================

@app.route(
    "/api/episodes/bulk",
    methods=["POST"]
)
@admin_required
def bulk_create_episodes():

    drama_id = request.form.get(
        "drama_id",
        ""
    ).strip()

    start_number = request.form.get(
        "start_number",
        "1"
    ).strip()

    videos = request.files.getlist("videos")

    if not drama_id:
        return jsonify({
            "error": "Drama is required"
        }), 400

    if not videos:
        return jsonify({
            "error": "No videos selected"
        }), 400

    data = load_catalog()

    drama = find_drama(data, drama_id)

    if not drama:
        return jsonify({
            "error": "Drama not found"
        }), 404

    try:
        next_number = int(start_number)
        if next_number < 1:
            raise ValueError
    except ValueError:
        return jsonify({
            "error": "Invalid starting episode number"
        }), 400

    created = []
    failed = []

    for video in videos:

        if not video or not video.filename:
            continue

        ep_number = next_number

        duplicate = next(
            (
                e for e in data["episodes"]
                if e.get("drama_id") == drama_id
                and int(e.get("number", 0)) == ep_number
            ),
            None
        )

        if duplicate:
            failed.append({
                "file": video.filename,
                "episode": ep_number,
                "error": f"Episode {ep_number} already exists"
            })
            next_number += 1
            continue

        if not allowed_video(video.filename):
            failed.append({
                "file": video.filename,
                "episode": ep_number,
                "error": "Unsupported video format"
            })
            next_number += 1
            continue

        filename = (
            f"ep_{ep_number}_"
            f"{uuid.uuid4().hex[:10]}"
            f"{Path(video.filename).suffix.lower()}"
        )

        destination = VIDEOS_DIR / filename

        try:
            # Fast upload: save original video directly.
            video.save(destination)

            episode = {
                "id": uuid.uuid4().hex,
                "drama_id": drama_id,
                "number": ep_number,
                "title": f"Episode {ep_number}",
                "video": f"/uploads/videos/{filename}",
                "created_at": datetime.now().isoformat(
                    timespec="seconds"
                ),
                "updated_at": datetime.now().isoformat(
                    timespec="seconds"
                )
            }

            data["episodes"].append(episode)
            created.append(episode)

        except Exception as e:

            try:
                destination.unlink(missing_ok=True)
            except Exception:
                pass

            failed.append({
                "file": video.filename,
                "episode": ep_number,
                "error": str(e)
            })

        next_number += 1

    update_episode_count(
        data,
        drama_id
    )

    # Move the drama to the front whenever new episodes are bulk uploaded.
    if created:
        drama["updated_at"] = max(
            e.get("created_at", "")
            for e in created
        )

    save_catalog(data)

    for episode in created:
        record_activity(
            "episode_added",
            (
                f"{drama.get('title', drama_id)}"
                f" - Episode {episode['number']}"
            )
        )

    return jsonify({
        "created": created,
        "failed": failed
    }), 201


# =========================================================
# EPISODES — UPDATE
# =========================================================

@app.route(
    "/api/episodes/<episode_id>",
    methods=["PUT"]
)
@admin_required
def update_episode(episode_id):

    data = load_catalog()

    episode = find_episode(
        data,
        episode_id
    )

    if not episode:

        return jsonify({
            "error":
            "Episode not found"
        }), 404

    old_video = episode.get(
        "video",
        ""
    )

    # PUT with multipart/form-data.
    if request.content_type and (
        request.content_type.startswith(
            "multipart/form-data"
        )
    ):

        number = request.form.get(
            "number",
            str(
                episode.get(
                    "number",
                    1
                )
            )
        ).strip()

        title = request.form.get(
            "title",
            episode.get(
                "title",
                ""
            )
        ).strip()

        video = request.files.get(
            "video"
        )

    else:

        body = request.get_json(
            silent=True
        ) or {}

        number = str(
            body.get(
                "number",
                episode.get(
                    "number",
                    1
                )
            )
        ).strip()

        title = str(
            body.get(
                "title",
                episode.get(
                    "title",
                    ""
                )
            )
        ).strip()

        video = None

    try:

        ep_number = int(number)

        if ep_number < 1:
            raise ValueError

    except ValueError:

        return jsonify({
            "error":
            "Invalid episode number"
        }), 400

    drama_id = episode.get(
        "drama_id"
    )

    duplicate = next(
        (
            e
            for e in data["episodes"]
            if e.get("id") != episode_id
            and e.get("drama_id")
            == drama_id
            and int(
                e.get(
                    "number",
                    0
                )
            ) == ep_number
        ),
        None
    )

    if duplicate:

        return jsonify({
            "error":
            "That episode number already exists"
        }), 409

    episode["number"] = ep_number

    episode["title"] = (
        title
        or
        f"Episode {ep_number}"
    )

    if video and video.filename:

        if not allowed_video(
            video.filename
        ):

            return jsonify({
                "error":
                "Unsupported video format"
            }), 400

        # Save the replacement video directly for fast uploads.
        source_suffix = Path(video.filename).suffix.lower()

        filename = (
            f"ep_{ep_number}_"
            f"{uuid.uuid4().hex[:10]}"
            f"{source_suffix}"
        )

        destination = VIDEOS_DIR / filename

        try:
            video.save(destination)
        except Exception as e:
            try:
                destination.unlink(missing_ok=True)
            except Exception:
                pass

            return jsonify({
                "error": str(e)
            }), 500

        episode["video"] = (
            f"/uploads/videos/{filename}"
        )

        # Delete old uploaded video.
        if old_video.startswith(
            "/uploads/videos/"
        ):

            old_filename = old_video.split(
                "/uploads/videos/",
                1
            )[1]

            old_path = safe_path(
                VIDEOS_DIR,
                old_filename
            )

            if (
                old_path
                and old_path.exists()
            ):

                try:
                    old_path.unlink()
                except Exception:
                    pass

    episode["updated_at"] = (
        datetime.now().isoformat(
            timespec="seconds"
        )
    )

    save_catalog(data)

    drama = find_drama(
        data,
        drama_id
    )

    record_activity(
        "episode_updated",
        (
            f"{drama.get('title', drama_id)}"
            if drama
            else drama_id
        )
        + f" - Episode {ep_number}"
    )

    return jsonify(
        episode
    )


# =========================================================
# EPISODES — DELETE
# =========================================================

@app.route(
    "/api/episodes/<episode_id>",
    methods=["DELETE"]
)
@admin_required
def delete_episode(episode_id):

    data = load_catalog()

    episode = find_episode(
        data,
        episode_id
    )

    if not episode:

        return jsonify({
            "error":
            "Episode not found"
        }), 404

    video_url = episode.get(
        "video",
        ""
    )

    if video_url.startswith(
        "/uploads/videos/"
    ):

        filename = video_url.split(
            "/uploads/videos/",
            1
        )[1]

        path = safe_path(
            VIDEOS_DIR,
            filename
        )

        if path and path.exists():

            try:
                path.unlink()
            except Exception:
                pass

    drama_id = episode.get(
        "drama_id"
    )

    data["episodes"] = [
        e
        for e in data["episodes"]
        if e.get("id") != episode_id
    ]

    update_episode_count(
        data,
        drama_id
    )

    # Remove old episode analytics.
    data["analytics"][
        "episode_views"
    ].pop(
        episode_id,
        None
    )

    save_catalog(data)

    record_activity(
        "episode_deleted",
        f"Episode {episode.get('number', '')}"
    )

    return jsonify({
        "ok": True
    })


# =========================================================

# =========================================================
# DRAMA COVER UPLOAD
# =========================================================

@app.route("/api/dramas/<drama_id>/cover", methods=["POST"])
@admin_required
def upload_drama_cover(drama_id):

    image = request.files.get("cover")

    if not image:
        return jsonify({"error": "No cover image supplied"}), 400

    if not allowed_image(image.filename):
        return jsonify({
            "error": "Only JPG, JPEG, PNG and WEBP images are allowed"
        }), 400

    extension = Path(image.filename).suffix.lower()
    filename = f"{uuid.uuid4().hex}{extension}"
    destination = COVERS_DIR / filename
    image.save(destination)

    data = load_catalog()

    drama = next(
        (d for d in data.get("dramas", [])
         if str(d.get("id")) == str(drama_id)),
        None
    )

    if not drama:
        try:
            destination.unlink()
        except Exception:
            pass
        return jsonify({"error": "Drama not found"}), 404

    url = f"/uploads/covers/{filename}"

    drama["cover"] = url
    drama["cover_url"] = url

    save_catalog(data)

    record_activity("cover_uploaded", f"{drama_id}:{filename}")

    return jsonify({
        "ok": True,
        "url": url,
        "filename": filename,
        "drama": drama
    })


# COVER UPLOAD
# =========================================================

@app.route(
    "/api/media/cover",
    methods=["POST"]
)
@admin_required
def upload_cover():

    image = request.files.get("cover")

    if not image:
        return jsonify({"error": "No cover image supplied"}), 400

    if not allowed_image(image.filename):
        return jsonify({
            "error": "Only JPG, JPEG, PNG and WEBP images are allowed"
        }), 400

    extension = Path(image.filename).suffix.lower()
    filename = f"{uuid.uuid4().hex}{extension}"
    key = f"covers/{filename}"

    try:
        r2.upload_fileobj(
            image,
            R2_BUCKET_NAME,
            key,
            ExtraArgs={
                "ContentType": image.content_type or "application/octet-stream"
            }
        )

        url = f"{R2_PUBLIC_URL}/{key}"

        record_activity("cover_uploaded", filename)

        return jsonify({
            "ok": True,
            "url": url,
            "filename": filename
        })

    except Exception as e:
        return jsonify({
            "error": f"R2 upload failed: {str(e)}"
        }), 500


# =========================================================
# MEDIA LIBRARY
# =========================================================

@app.route("/api/media")
@admin_required
def media_library():

    items = []

    roots = [
        (
            "images",
            BASE / "images"
        ),
        (
            "covers",
            COVERS_DIR
        ),
        (
            "videos",
            VIDEOS_DIR
        )
    ]

    for media_type, root in roots:

        if not root.exists():
            continue

        for path in root.rglob("*"):

            if not path.is_file():
                continue

            try:

                relative = (
                    path
                    .relative_to(BASE)
                    .as_posix()
                )

                items.append({

                    "type":
                    media_type,

                    "name":
                    path.name,

                    "path":
                    "/" + relative,

                    "size":
                    path.stat().st_size,

                    "modified":
                    datetime.fromtimestamp(
                        path.stat().st_mtime
                    ).isoformat(
                        timespec="seconds"
                    )
                })

            except Exception:
                pass

    items.sort(
        key=lambda x:
        x["modified"],
        reverse=True
    )

    return jsonify(
        items
    )


@app.route(
    "/api/media/delete",
    methods=["POST"]
)
@admin_required
def delete_media():

    body = request.get_json(
        silent=True
    ) or {}

    media_path = str(
        body.get(
            "path",
            ""
        )
    )

    allowed_roots = [
        BASE / "images",
        COVERS_DIR,
        VIDEOS_DIR
    ]

    if not media_path.startswith(
        "/"
    ):

        return jsonify({
            "error":
            "Invalid media path"
        }), 400

    relative = (
        media_path.lstrip("/")
    )

    target = (
        BASE / relative
    ).resolve()

    allowed = any(
        root.resolve() in target.parents
        for root in allowed_roots
    )

    if not allowed or not target.is_file():

        return jsonify({
            "error":
            "Media file not found"
        }), 404

    target.unlink()

    record_activity(
        "media_deleted",
        media_path
    )

    return jsonify({
        "ok": True
    })


# =========================================================
# HOMEPAGE PLACEMENTS
# =========================================================

@app.route(
    "/api/homepage",
    methods=["GET"]
)
def homepage_data():

    data = load_catalog()

    published = [
        d
        for d in data["dramas"]
        if d.get(
            "published",
            True
        )
    ]

    result = {}

    for section in [
        "hero",
        "new_releases",
        "trending",
        "for_you",
        "popular"
    ]:

        ids = data[
            "homepage"
        ].get(
            section,
            []
        )

        # Also support existing drama
        # placement values.
        selected = []

        for drama in published:

            if (
                drama.get("id")
                in ids
                or
                section
                in drama.get(
                    "placements",
                    []
                )
            ):

                selected.append(
                    drama
                )

        result[section] = selected

    return jsonify({

        "dramas":
        published,

        "placements":
        result

    })


@app.route(
    "/api/public/dramas",
    methods=["GET"]
)
def public_dramas():

    data = load_catalog()

    result = []

    for d in data["dramas"]:
        if not d.get("published", True):
            continue

        result.append({
            "id": d.get("id"),
            "title": d.get("title", ""),
            "description": d.get("description", ""),
            "cover": d.get("cover", ""),
            "category": d.get("category", ""),
            "tags": d.get("tags", []),
            "published": True,
            "updated_at": d.get("updated_at", "")
        })

    # Newest updated drama first.
    result.sort(
        key=lambda d: d.get("updated_at") or "",
        reverse=True
    )

    return jsonify(result)


@app.route(
    "/api/public/episodes",
    methods=["GET"]
)
def public_episodes():

    data = load_catalog()

    published_ids = {
        d.get("id")
        for d in data["dramas"]
        if d.get("published", True)
    }

    result = [
        {
            "id": e.get("id"),
            "drama_id": e.get("drama_id"),
            "number": e.get("number"),
            "title": e.get("title"),
            "video": e.get("video")
        }
        for e in data["episodes"]
        if e.get("drama_id") in published_ids
    ]

    result.sort(
        key=lambda e: (
            e.get("drama_id", ""),
            int(e.get("number", 0))
        )
    )

    return jsonify(result)


@app.route(
    "/api/admin/homepage",
    methods=["GET"]
)
@admin_required
def admin_homepage():

    data = load_catalog()

    return jsonify(
        data["homepage"]
    )


@app.route(
    "/api/admin/homepage",
    methods=["PUT"]
)
@admin_required
def update_homepage():

    body = request.get_json(
        silent=True
    ) or {}

    data = load_catalog()

    sections = [
        "hero",
        "new_releases",
        "trending",
        "for_you",
        "popular"
    ]

    for section in sections:

        if section not in body:
            continue

        ids = body[section]

        if not isinstance(
            ids,
            list
        ):

            ids = []

        valid_ids = {
            d.get("id")
            for d in data["dramas"]
        }

        data["homepage"][section] = [
            x
            for x in ids
            if x in valid_ids
        ]

    save_catalog(data)

    record_activity(
        "homepage_updated",
        "Homepage placements updated"
    )

    return jsonify(
        data["homepage"]
    )


# =========================================================
# ADVERTISING
# =========================================================

@app.route("/api/admin/advertising", methods=["GET", "PUT"])
@admin_required
def admin_advertising():

    data = load_catalog()

    defaults = {
        "enabled": False,
        "popup_enabled": False,
        "home_banner": {
            "enabled": False,
            "html": "",
            "link_url": ""
        },
        "drama_banner": {
            "enabled": False,
            "html": ""
        },
        "episode_banner": {
            "enabled": False,
            "html": ""
        },
        "in_feed": {
            "enabled": False,
            "html": ""
        },
        "video_preroll": {
            "enabled": False,
            "html": ""
        }
    }

    ads = data.setdefault("advertising", {})

    for key, value in defaults.items():
        if key not in ads:
            ads[key] = value.copy() if isinstance(value, dict) else value

    if request.method == "GET":
        return jsonify(ads)

    body = request.get_json(silent=True) or {}

    ads["enabled"] = bool(
        body.get("enabled", ads["enabled"])
    )

    # Popup advertising is disabled unless explicitly enabled.
    ads["popup_enabled"] = bool(
        body.get("popup_enabled", ads["popup_enabled"])
    )

    for key in [
        "home_banner",
        "drama_banner",
        "episode_banner",
        "in_feed",
        "video_preroll"
    ]:
        incoming = body.get(key)

        if not isinstance(incoming, dict):
            continue

        ads[key]["enabled"] = bool(
            incoming.get(
                "enabled",
                ads[key]["enabled"]
            )
        )

        if "html" in incoming:
            ads[key]["html"] = str(
                incoming["html"]
            )

    save_catalog(data)

    record_activity(
        "advertising_updated",
        "Advertising settings updated"
    )

    return jsonify({
        "ok": True,
        "advertising": ads
    })



# =========================================================
# AD VIDEO UPLOAD
# =========================================================

@app.route("/api/admin/advertising/video-upload", methods=["POST"])
@admin_required
def admin_advertising_video_upload():

    if "file" not in request.files:
        return jsonify({
            "ok": False,
            "error": "No video file supplied"
        }), 400

    file = request.files["file"]

    if not file or not file.filename:
        return jsonify({
            "ok": False,
            "error": "Invalid video file"
        }), 400

    filename = secure_filename(file.filename)

    if not filename:
        return jsonify({
            "ok": False,
            "error": "Invalid filename"
        }), 400

    allowed = {
        ".mp4": "video/mp4",
        ".webm": "video/webm",
        ".mov": "video/quicktime"
    }

    ext = os.path.splitext(filename)[1].lower()

    if ext not in allowed:
        return jsonify({
            "ok": False,
            "error": "Only MP4, WebM and MOV videos are supported"
        }), 400

    import uuid

    key = f"ads/{uuid.uuid4().hex}-{filename}"

    try:
        r2.upload_fileobj(
            file,
            R2_BUCKET_NAME,
            key,
            ExtraArgs={
                "ContentType": allowed[ext]
            }
        )

        url = f"{R2_PUBLIC_URL}/{key}"

        data = load_catalog()

        ads = data.setdefault("advertising", {})

        video_ad = ads.setdefault(
            "video_preroll",
            {
                "enabled": False,
                "html": ""
            }
        )

        video_ad["html"] = (
            f'<video src="{url}" '
            f'playsinline preload="auto"></video>'
        )

        video_ad["enabled"] = True

        save_catalog(data)

        record_activity(
            "advertising_video_uploaded",
            f"Advertising video uploaded: {filename}"
        )

        return jsonify({
            "ok": True,
            "url": url,
            "html": video_ad["html"]
        })

    except Exception as e:

        app.logger.exception(
            "Advertising video upload failed"
        )

        return jsonify({
            "ok": False,
            "error": "Advertising video upload failed"
        }), 500



# =========================================================
# MONETIZATION / PREMIUM
# =========================================================

@app.route("/api/admin/monetization", methods=["GET", "PUT"])
@admin_required
def admin_monetization():

    data = load_catalog()

    defaults = {
        "premium_enabled": False,
        "monthly_price": 0,
        "annual_price": 0,
        "currency": "USD",
        "premium_name": "Premium",
        "premium_description": "Unlock premium content and an ad-free experience.",
        "payments_enabled": False
    }

    monetization = data.setdefault("monetization", {})

    for key, value in defaults.items():
        monetization.setdefault(key, value)

    if request.method == "GET":
        return jsonify(monetization)

    body = request.get_json(silent=True) or {}

    if "premium_enabled" in body:
        monetization["premium_enabled"] = bool(body["premium_enabled"])

    if "payments_enabled" in body:
        monetization["payments_enabled"] = bool(body["payments_enabled"])

    if "monthly_price" in body:
        try:
            monetization["monthly_price"] = max(
                0,
                float(body["monthly_price"])
            )
        except (TypeError, ValueError):
            pass

    if "annual_price" in body:
        try:
            monetization["annual_price"] = max(
                0,
                float(body["annual_price"])
            )
        except (TypeError, ValueError):
            pass

    if "currency" in body:
        monetization["currency"] = str(
            body["currency"]
        ).strip().upper()[:10]

    if "premium_name" in body:
        monetization["premium_name"] = str(
            body["premium_name"]
        ).strip()[:100]

    if "premium_description" in body:
        monetization["premium_description"] = str(
            body["premium_description"]
        ).strip()[:500]

    save_catalog(data)

    record_activity(
        "monetization_updated",
        "Premium and monetization settings updated"
    )

    return jsonify({
        "ok": True,
        "monetization": monetization
    })


# =========================================================

# =========================================================
# PUBLIC ADVERTISING
# =========================================================


AD_ANALYTICS_FILE = DATA_DIR / "ad_analytics.json"
VALID_AD_TYPES = {"home_banner", "drama_banner", "episode_banner"}

def load_ad_analytics():
    if not AD_ANALYTICS_FILE.exists():
        return {"days": {}}
    try:
        data = json.loads(AD_ANALYTICS_FILE.read_text())
        if not isinstance(data, dict):
            return {"days": {}}
        data.setdefault("days", {})
        return data
    except Exception:
        return {"days": {}}

def save_ad_analytics(data):
    AD_ANALYTICS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = AD_ANALYTICS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(AD_ANALYTICS_FILE)

@app.route("/api/public/ad-impression", methods=["POST"])
def public_ad_impression():
    body = request.get_json(silent=True) or {}
    ad_type = str(body.get("ad_type", "")).strip()

    if ad_type not in VALID_AD_TYPES:
        return jsonify({"error": "Invalid ad type"}), 400

    data = load_ad_analytics()
    day = datetime.now().strftime("%Y-%m-%d")

    days = data.setdefault("days", {})
    record = days.setdefault(day, {
        "home_banner": 0,
        "drama_banner": 0,
        "episode_banner": 0,
        "total": 0
    })

    record[ad_type] = int(record.get(ad_type, 0)) + 1
    record["total"] = int(record.get("total", 0)) + 1

    save_ad_analytics(data)

    return jsonify({"ok": True})

@app.route("/api/admin/ad-analytics", methods=["GET"])
@admin_required
def admin_ad_analytics():
    data = load_ad_analytics()
    days = data.get("days", {})

    today = datetime.now().strftime("%Y-%m-%d")

    def total_for(days_count):
        dates = sorted(days.keys())[-days_count:]
        result = {
            "home_banner": 0,
            "drama_banner": 0,
            "episode_banner": 0,
            "total": 0
        }

        for d in dates:
            row = days.get(d, {})
            for key in result:
                result[key] += int(row.get(key, 0))

        return result

    return jsonify({
        "today": days.get(today, {
            "home_banner": 0,
            "drama_banner": 0,
            "episode_banner": 0,
            "total": 0
        }),
        "last_7_days": total_for(7),
        "last_30_days": total_for(30),
        "days": days
    })

@app.route("/api/public/advertising", methods=["GET"])
def public_advertising():
    data = load_catalog()
    ads = data.get("advertising", {})

    # Public endpoint exposes only display settings.
    # Popups and video prerolls remain OFF unless explicitly enabled
    # from the admin dashboard.
    return jsonify({
        "enabled": bool(ads.get("enabled", False)),
        "popup_enabled": bool(ads.get("popup_enabled", False)),
        "home_banner": ads.get("home_banner", {
            "enabled": False,
            "html": "",
            "link_url": ""
        }),
        "drama_banner": ads.get("drama_banner", {
            "enabled": False,
            "html": ""
        }),
        "episode_banner": ads.get("episode_banner", {
            "enabled": False,
            "html": ""
        }),
        "in_feed": ads.get("in_feed", {
            "enabled": False,
            "html": ""
        }),
        "video_preroll": ads.get("video_preroll", {
            "enabled": False,
            "html": ""
        })
    })

# SETTINGS
# =========================================================

@app.route("/api/admin/settings", methods=["GET", "PUT"])
@admin_required
def admin_settings():

    data = load_catalog()

    defaults = {
        "site_name": "SHORT REELS",
        "site_description": "",
        "maintenance_mode": False
    }

    settings = data.setdefault("settings", {})

    for key, value in defaults.items():
        settings.setdefault(key, value)

    if request.method == "GET":
        return jsonify(settings)

    body = request.get_json(silent=True) or {}

    if "site_name" in body:
        settings["site_name"] = str(body["site_name"]).strip()

    if "site_description" in body:
        settings["site_description"] = str(body["site_description"]).strip()

    if "maintenance_mode" in body:
        settings["maintenance_mode"] = bool(body["maintenance_mode"])

    save_catalog(data)

    record_activity(
        "settings_updated",
        "Site settings updated"
    )

    return jsonify({
        "ok": True,
        "settings": settings
    })


# =========================================================
# ANALYTICS
# =========================================================

@app.route("/api/analytics")
@admin_required
def analytics():

    data = load_catalog()

    analytics_data = (
        data["analytics"]
    )

    drama_views = (
        analytics_data[
            "drama_views"
        ]
    )

    episode_views = (
        analytics_data[
            "episode_views"
        ]
    )

    drama_lookup = {
        d["id"]:
        d.get(
            "title",
            d["id"]
        )
        for d in data[
            "dramas"
        ]
    }

    episode_lookup = {
        e["id"]:
        e
        for e in data[
            "episodes"
        ]
    }

    top_dramas = sorted(

        [
            {
                "id":
                drama_id,

                "title":
                drama_lookup.get(
                    drama_id,
                    drama_id
                ),

                "views":
                views
            }

            for drama_id, views
            in drama_views.items()
        ],

        key=lambda x:
        x["views"],

        reverse=True
    )

    top_episodes = sorted(

        [

            {
                "id":
                episode_id,

                "number":
                episode_lookup.get(
                    episode_id,
                    {}
                ).get(
                    "number"
                ),

                "title":
                episode_lookup.get(
                    episode_id,
                    {}
                ).get(
                    "title",
                    episode_id
                ),

                "views":
                views
            }

            for episode_id, views
            in episode_views.items()
        ],

        key=lambda x:
        x["views"],

        reverse=True
    )

    return jsonify({

        "visits":
        analytics_data[
            "visits"
        ],

        "unique_visitors":
        analytics_data[
            "unique_visitors"
        ],

        "drama_views":
        drama_views,

        "episode_views":
        episode_views,

        "daily":
        analytics_data[
            "daily"
        ],

        "top_dramas":
        top_dramas[:20],

        "top_episodes":
        top_episodes[:20],

        "activity":
        analytics_data[
            "activity"
        ][:30]

    })


@app.route(
    "/api/analytics/drama/<drama_id>",
    methods=["POST"]
)
def drama_view(drama_id):

    data = load_catalog()

    if not find_drama(
        data,
        drama_id
    ):

        return jsonify({
            "error":
            "Drama not found"
        }), 404

    views = (
        data["analytics"][
            "drama_views"
        ]
    )

    views[drama_id] = (
        views.get(
            drama_id,
            0
        ) + 1
    )

    save_catalog(data)

    return jsonify({

        "ok": True,

        "views":
        views[drama_id]

    })


@app.route(
    "/api/analytics/episode/<episode_id>",
    methods=["POST"]
)
def episode_view(episode_id):

    data = load_catalog()

    if not find_episode(
        data,
        episode_id
    ):

        return jsonify({
            "error":
            "Episode not found"
        }), 404

    views = (
        data["analytics"][
            "episode_views"
        ]
    )

    views[episode_id] = (
        views.get(
            episode_id,
            0
        ) + 1
    )

    save_catalog(data)

    return jsonify({

        "ok": True,

        "views":
        views[episode_id]

    })


# =========================================================
# TEST
# =========================================================

@app.route("/api/test")
def test():

    return jsonify({

        "status":
        "online",

        "message":
        "SHORT REELS backend is working"

    })


# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=8080,
        debug=True
    )
