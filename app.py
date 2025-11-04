import os
import secrets
from datetime import datetime

from flask import Flask, redirect, render_template, request, session, url_for, jsonify, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, scoped_session
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import requests
from werkzeug.security import generate_password_hash, check_password_hash


# Load environment variables
load_dotenv()


# Basic Flask setup
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(16))


# Three-color theme (used in templates)
THEME = {
    "bg": "#0B0C10",       # background
    "primary": "#66FCF1",  # primary accent
    "muted": "#45A29E",    # secondary
}


# Database setup: prefer DATABASE_URL (e.g., Supabase Postgres), fallback to local SQLite
db_url_env = os.getenv("DATABASE_URL", "").strip()
if db_url_env:
    # Prefer psycopg (v3) driver for Postgres if not explicitly set
    if db_url_env.startswith("postgresql://") and "+" not in db_url_env.split("://", 1)[0]:
        DATABASE_URL = "postgresql+psycopg://" + db_url_env.split("://", 1)[1]
    else:
        DATABASE_URL = db_url_env
else:
    DATABASE_URL = "sqlite:///app.db"

engine = create_engine(DATABASE_URL, pool_pre_ping=True)

SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False))
Base = declarative_base()


class User(Base, UserMixin):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=True)
    picture = Column(Text, nullable=True)
    is_admin = Column(Boolean, default=False, nullable=False)
    credits = Column(Integer, default=0, nullable=False)
    api_key = Column(String(64), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    password_hash = Column(Text, nullable=True)

    logs = relationship("APILog", back_populates="user", cascade="all, delete-orphan")


class APILog(Base):
    __tablename__ = "api_logs"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    endpoint = Column(String(255), nullable=False)
    cost = Column(Integer, default=0, nullable=False)
    status = Column(String(64), default="success", nullable=False)
    details = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="logs")


Base.metadata.create_all(bind=engine)

# Ensure password_hash column exists for SQLite if table was created earlier without it
try:
    with engine.connect() as conn:
        res = conn.exec_driver_sql("PRAGMA table_info('users')")
        cols = [row[1] for row in res]
        if 'password_hash' not in cols:
            conn.exec_driver_sql("ALTER TABLE users ADD COLUMN password_hash TEXT")
except Exception:
    pass


# Login manager
login_manager = LoginManager(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id: str):
    db = SessionLocal()
    try:
        return db.get(User, int(user_id))
    finally:
        db.close()


# OAuth (Google)
oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


def get_or_create_user(email: str, name: str | None, picture: str | None):
    db = SessionLocal()
    try:
        user = db.query(User).filter_by(email=email).first()
        if user:
            # update basic profile fields on login
            user.name = name or user.name
            user.picture = picture or user.picture
        else:
            api_key = secrets.token_hex(24)
            user = User(email=email, name=name, picture=picture, credits=0, is_admin=False, api_key=api_key)
            db.add(user)
        db.commit()
        db.refresh(user)
        return user
    finally:
        db.close()


def current_user_or_api_key():
    """Return (user, db_session) from login session or X-API-Key header/query. Caller must close db.
    """
    db = SessionLocal()
    try:
        if current_user.is_authenticated:
            # refresh from DB to ensure latest credits
            user = db.get(User, current_user.id)
            return user, db

        api_key = request.headers.get("X-API-Key") or request.args.get("api_key")
        if api_key:
            user = db.query(User).filter_by(api_key=api_key).first()
            return user, db
        return None, db
    except Exception:
        db.close()
        raise


@app.context_processor
def inject_theme():
    return {
        "THEME": THEME,
        "RECAPTCHA_SITE_KEY": os.getenv("RECAPTCHA_SITE_KEY", ""),
    }


# Routes
@app.get("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.get("/login")
def login():
    redirect_uri = url_for("auth_callback", _external=True)
    return google.authorize_redirect(redirect_uri)


@app.get("/auth/callback")
def auth_callback():
    token = google.authorize_access_token()
    # Prefer parsing ID Token to avoid separate userinfo HTTP request
    try:
        info = google.parse_id_token(token)
    except Exception:
        # Fallback to userinfo endpoint if parsing fails
        resp = google.get("https://openidconnect.googleapis.com/v1/userinfo")
        info = resp.json()
    email = info.get("email")
    if not email:
        abort(400, "Google login failed: no email")
    user = get_or_create_user(email=email, name=info.get("name"), picture=info.get("picture"))
    login_user(user)
    return redirect(url_for("dashboard"))


@app.post("/login_local")
def login_local():
    email = (request.form.get("email") or request.json.get("email") if request.is_json else "").strip().lower()
    password = (request.form.get("password") or request.json.get("password") if request.is_json else "")
    if not email or not password:
        return redirect(url_for("index"))
    db = SessionLocal()
    try:
        user = db.query(User).filter_by(email=email).first()
        if not user or not user.password_hash or not check_password_hash(user.password_hash, password):
            return render_template("index.html", login_error="Invalid credentials"), 401
        login_user(user)
        return redirect(url_for("dashboard"))
    finally:
        db.close()


@app.post("/register_local")
def register_local():
    email = (request.form.get("email") or request.json.get("email") if request.is_json else "").strip().lower()
    password = (request.form.get("password") or request.json.get("password") if request.is_json else "")
    name = (request.form.get("name") or request.json.get("name") if request.is_json else None)
    if not email or not password:
        return render_template("index.html", register_error="Email and password required"), 400
    db = SessionLocal()
    try:
        existing = db.query(User).filter_by(email=email).first()
        if existing and existing.password_hash:
            return render_template("index.html", register_error="Email already registered"), 400
        if existing and not existing.password_hash:
            existing.password_hash = generate_password_hash(password)
            db.commit()
            login_user(existing)
            return redirect(url_for("dashboard"))
        api_key = secrets.token_hex(24)
        user = User(email=email, name=name, credits=0, is_admin=False, api_key=api_key,
                    password_hash=generate_password_hash(password))
        db.add(user)
        db.commit()
        login_user(user)
        return redirect(url_for("dashboard"))
    finally:
        db.close()


@app.post("/logout")
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.get("/dashboard")
@login_required
def dashboard():
    db = SessionLocal()
    try:
        user = db.get(User, current_user.id)
        recent_logs = (
            db.query(APILog)
            .filter(APILog.user_id == user.id)
            .order_by(APILog.created_at.desc())
            .limit(10)
            .all()
        )
        return render_template("dashboard.html", user=user, logs=recent_logs)
    finally:
        db.close()


@app.get("/admin")
@login_required
def admin():
    if not current_user.is_authenticated:
        return redirect(url_for("index"))
    db = SessionLocal()
    try:
        user = db.get(User, current_user.id)
        if not user.is_admin:
            abort(403)
        return render_template("admin.html")
    finally:
        db.close()


@app.post("/admin/credit")
@login_required
def admin_credit():
    db = SessionLocal()
    try:
        admin_user = db.get(User, current_user.id)
        if not admin_user.is_admin:
            abort(403)
        email = request.form.get("email", "").strip().lower()
        amount = int(request.form.get("amount", "0") or 0)
        if not email or amount == 0:
            return render_template("admin.html", error="Email and amount required")
        user = db.query(User).filter_by(email=email).first()
        if not user:
            return render_template("admin.html", error="User not found")
        user.credits += amount
        db.commit()
        return render_template("admin.html", success=f"Added {amount} credits to {email}")
    finally:
        db.close()


def log_api_usage(db, user_id: int, endpoint: str, cost: int, status: str, details: str | None = None):
    entry = APILog(user_id=user_id, endpoint=endpoint, cost=cost, status=status, details=details)
    db.add(entry)
    db.commit()


ESP32_BASE_URL = os.getenv("ESP32_BASE_URL", "http://192.168.1.200")
SMS_COST = 1


@app.post("/api/send_sms")
def api_send_sms():
    user, db = current_user_or_api_key()
    try:
        if not user:
            return jsonify({"error": "Unauthorized"}), 401

        data = request.get_json(silent=True) or {}
        number = data.get("number")
        message = data.get("message")
        if not number or not message:
            return jsonify({"error": "number and message are required"}), 400

        # Normalize PH numbers to +639XXXXXXXXX
        def normalize_ph_number(raw: str) -> str | None:
            s = (raw or "").strip()
            # keep digits only
            digits = "".join(ch for ch in s if ch.isdigit())
            if digits.startswith("63") and len(digits) == 12 and digits[2] == "9":
                return "+" + digits
            if digits.startswith("09") and len(digits) == 11:
                return "+63" + digits[1:]
            if digits.startswith("9") and len(digits) == 10:
                return "+63" + digits
            if s.startswith("+") and digits.startswith("63") and len(digits) == 12 and digits[2] == "9":
                return "+" + digits
            return None

        normalized = normalize_ph_number(number)
        if not normalized:
            return jsonify({"error": "invalid_number_format", "expected": "+639XXXXXXXXX"}), 400

        # Check credits
        if user.credits < SMS_COST:
            log_api_usage(db, user.id, "/api/send_sms", 0, "failed", "insufficient_credits")
            return jsonify({"error": "Insufficient credits"}), 402

        # Forward to ESP32
        try:
            esp_resp = requests.post(
                f"{ESP32_BASE_URL}/api/sms/send",
                json={"number": normalized, "message": message},
                timeout=10,
            )
            ok = esp_resp.status_code == 200
        except Exception as e:
            ok = False
            esp_resp = None
            err = str(e)

        if not ok:
            details = f"esp_status={getattr(esp_resp, 'status_code', 'n/a')}"
            log_api_usage(db, user.id, "/api/send_sms", 0, "failed", details)
            return jsonify({"error": "ESP32 request failed"}), 502

        # Deduct credits and log
        user.credits -= SMS_COST
        db.add(user)
        db.commit()
        log_api_usage(db, user.id, "/api/send_sms", SMS_COST, "success", None)

        return jsonify({
            "success": True,
            "remaining_credits": user.credits,
        })
    finally:
        db.close()


@app.get("/me")
def me():
    user, db = current_user_or_api_key()
    try:
        if not user:
            return jsonify({"authenticated": False}), 200
        return jsonify({
            "authenticated": True,
            "email": user.email,
            "credits": user.credits,
            "api_key": user.api_key,
            "is_admin": user.is_admin,
        })
    finally:
        db.close()


@app.get("/docs")
def docs():
    return render_template("docs.html")


@app.get("/verify-wall")
@login_required
def verify_wall():
    return render_template("verify_wall.html")


@app.post("/api/claim_credits_wall")
@login_required
def claim_credits_wall():
    db = SessionLocal()
    try:
        user = db.get(User, current_user.id)
        user.credits += 3
        db.commit()
        return jsonify({"ok": True, "credits": user.credits, "added": 3})
    finally:
        db.close()

@app.post("/api/claim_credits")
@login_required
def claim_credits():
    db = SessionLocal()
    try:
        user = db.get(User, current_user.id)
        data = request.get_json(silent=True) or {}
        # Verify Google reCAPTCHA v2
        recaptcha_token = data.get("recaptcha")
        secret = os.getenv("RECAPTCHA_SECRET", "")
        if not recaptcha_token or not secret:
            return jsonify({"ok": False, "error": "captcha_required"}), 400
        try:
            verify_resp = requests.post(
                "https://www.google.com/recaptcha/api/siteverify",
                data={
                    "secret": secret,
                    "response": recaptcha_token,
                    "remoteip": request.remote_addr or "",
                },
                timeout=8,
            )
            g = verify_resp.json()
            if not g.get("success"):
                return jsonify({"ok": False, "error": "captcha_failed"}), 400
        except Exception:
            return jsonify({"ok": False, "error": "captcha_verify_error"}), 400
        user.credits += 3
        db.commit()
        return jsonify({"ok": True, "credits": user.credits, "added": 3})
    finally:
        db.close()


def create_app():
    return app


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)


