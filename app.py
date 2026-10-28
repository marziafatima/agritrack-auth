"""AgriTrack - Sign In / Sign Up module (Flask + MySQL, hashed passwords)."""
import os, re, secrets, ssl
from datetime import datetime
from functools import wraps

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


# ---------------- Database connection (SQLite locally, MySQL when DATABASE_URL is set) ----------------
def build_db():
    url = make_url(os.environ.get("DATABASE_URL", "sqlite:///agritrack.db"))
    options = {"pool_pre_ping": True, "pool_recycle": 280}
    if url.get_backend_name() == "mysql":
        url = url.set(drivername="mysql+pymysql").difference_update_query(["ssl-mode", "ssl_mode"])
        if os.environ.get("DB_SSL", "1") != "0":  # cloud MySQL (Aiven etc.) needs an encrypted connection
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            options["connect_args"] = {"ssl": ctx}
    return url.render_as_string(hide_password=False), options


uri, engine_options = build_db()
app.config["SQLALCHEMY_DATABASE_URI"] = uri
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = engine_options
db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), nullable=False)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum("Farmer", "Buyer", "Supplier", "Admin", name="role_enum"), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    location = db.Column(db.String(30), nullable=False)
    status = db.Column(db.Enum("Pending", "Active", "Blocked", name="status_enum"),
                       nullable=False, default="Pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


DUMMY_HASH = generate_password_hash("not-a-real-password")


def init_db():
    """Create tables and make sure one Admin account exists."""
    db.create_all()
    if not User.query.filter_by(role="Admin").first():
        pw = os.environ.get("ADMIN_PASSWORD")
        if not pw:
            pw = secrets.token_urlsafe(9)
            print(f"[AgriTrack] No ADMIN_PASSWORD set. Generated admin password: {pw}", flush=True)
        db.session.add(User(name="System Admin", username="admin", password_hash=generate_password_hash(pw),
                            role="Admin", phone="0300-0000000", location="Lahore", status="Active"))
        try:
            db.session.commit()
        except IntegrityError:  # another worker created it first
            db.session.rollback()


with app.app_context():
    init_db()


# ---------------- CSRF protection ----------------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        if not secrets.compare_digest(request.form.get("_csrf", ""), session.get("_csrf", "")):
            abort(400)


# ---------------- Validation (same rules as the prototype forms.js) ----------------
def validate_registration(f):
    e = {}
    name, username = f.get("name", "").strip(), f.get("username", "").strip().lower()
    password, role = f.get("password", ""), f.get("role", "")
    phone, location = f.get("phone", "").strip(), f.get("location", "").strip()
    if not 3 <= len(name) <= 40:
        e["name"] = "Full name must be 3 to 40 characters"
    if not re.fullmatch(r"[A-Za-z0-9_]{4,20}", username):
        e["username"] = "4 to 20 letters, numbers or _ only"
    if not 8 <= len(password) <= 30 or not re.search(r"\d", password):
        e["password"] = "8 to 30 characters, with at least one digit"
    if role not in ("Farmer", "Buyer", "Supplier"):  # Admin can never be self-registered
        e["role"] = "Please choose a role"
    if not re.fullmatch(r"[0-9+\-\s]{7,15}", phone):
        e["phone"] = "7 to 15 digits, e.g. 0300-1234567"
    if not 2 <= len(location) <= 30:
        e["location"] = "Location must be 2 to 30 characters"
    return e, dict(name=name, username=username, role=role, phone=phone, location=location)


# ---------------- Access control ----------------
def login_required(role=None):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            uid = session.get("uid")
            user = db.session.get(User, uid) if uid else None
            if not user or user.status != "Active":
                session.clear()
                return redirect(url_for("login"))
            if role and user.role != role:
                abort(403)
            return fn(user, *a, **k)
        return wrapper
    return deco


# ---------------- Routes ----------------
@app.route("/")
def home():
    return redirect(url_for("dashboard") if session.get("uid") else url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    errors, form = {}, {}
    if request.method == "POST":
        errors, form = validate_registration(request.form)
        if not errors and User.query.filter_by(username=form["username"]).first():
            errors["username"] = "This username is already taken"
        if not errors:
            db.session.add(User(password_hash=generate_password_hash(request.form["password"]),
                                status="Pending", **form))
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                errors["username"] = "This username is already taken"
            else:
                flash("Account created. It will work after the Admin verifies it.", "success")
                return redirect(url_for("login"))
    return render_template("register.html", errors=errors, form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        ok = check_password_hash(user.password_hash if user else DUMMY_HASH, password)
        if not user or not ok:
            flash("Wrong username or password", "danger")
        elif user.status == "Pending":
            flash("Your account is waiting for Admin verification", "warning")
        elif user.status == "Blocked":
            flash("Your account is blocked. Contact Admin", "danger")
        else:
            session.clear()
            session["uid"] = user.id
            return redirect(url_for("admin" if user.role == "Admin" else "dashboard"))
    return render_template("login.html")


@app.route("/dashboard")
@login_required()
def dashboard(user):
    return render_template("dashboard.html", user=user)


@app.route("/admin")
@login_required("Admin")
def admin(user):
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin.html", user=user, users=users)


@app.route("/admin/<int:uid>/<action>", methods=["POST"])
@login_required("Admin")
def admin_action(user, uid, action):
    target = db.session.get(User, uid) or abort(404)
    new = {"verify": "Active", "activate": "Active", "block": "Blocked"}.get(action) or abort(404)
    if target.id == user.id:
        flash("You cannot change your own account", "warning")
    else:
        target.status = new
        db.session.commit()
        flash(f"{target.username} is now {new}", "success")
    return redirect(url_for("admin"))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
