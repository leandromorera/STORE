# ecommerce_v2/app.py
import os, json, logging, smtplib, bcrypt, requests, stripe
from email.mime.text import MIMEText
from urllib.parse import urlparse, urljoin

from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session
from dotenv import load_dotenv
from flask_login import (
    LoginManager, login_user, login_required, logout_user, current_user, UserMixin
)

from models import (
    Base, ExternalBase,
    User, Device, UploadProduct,
    CartItem, CartSnapshot, Order, OrderItem
)
from flask import send_from_directory


load_dotenv()
# Main (app) DB
DEFAULT_PRICE_CENTS = int(os.getenv("DEFAULT_PRICE_CENTS", "1000"))
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///ecommerce.db")
# External LOADER DB (uploads)
LOADER_DATABASE_URL = os.getenv("LOADER_DATABASE_URL", "sqlite:///data.db")

SITE_NAME = os.getenv("SITE_NAME", "My Shop")
CURRENCY  = os.getenv("CURRENCY", "USD")
SECRET    = os.getenv("FLASK_SECRET_KEY", "dev-key")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://localhost:3000")

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO")

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = SECRET

# ---------- Engines ----------
engine_main   = create_engine(DATABASE_URL, future=True)       # users/carts/orders
Base.metadata.create_all(engine_main)

engine_loader = create_engine(LOADER_DATABASE_URL, future=True)  # uploads (existing DB)
# DO NOT create_all() on the external DB; we only map it.

def main_session():
    return Session(engine_main)

def loader_session():
    return Session(engine_loader)

# ---------- Auth ----------
login_manager = LoginManager(app)
login_manager.login_view = "login"

class LoginUser(UserMixin):
    def __init__(self, u: User):
        self.id = str(u.id)
        self.email = u.email

@login_manager.user_loader
def load_user(user_id):
    with main_session() as db:
        u = db.get(User, int(user_id))
        return LoginUser(u) if u else None

# ---------- Logging & notify ----------
log = logging.getLogger("shop")
log.setLevel(logging.INFO)
fh = logging.FileHandler("app.log")
fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
log.addHandler(fh); log.addHandler(ch)

def notify(msg: str):
    try:
        if SLACK_WEBHOOK_URL:
            requests.post(SLACK_WEBHOOK_URL, json={"text": msg}, timeout=5)
    except Exception as e:
        log.warning(f"Slack notify failed: {e}")
    try:
        if SMTP_HOST and ALERT_EMAIL_TO:
            m = MIMEText(msg)
            m["Subject"] = f"[{SITE_NAME}] Notification"
            m["From"] = SMTP_USER or "noreply@localhost"
            m["To"] = ALERT_EMAIL_TO
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=5) as s:
                s.starttls()
                if SMTP_USER and SMTP_PASS:
                    s.login(SMTP_USER, SMTP_PASS)
                s.send_message(m)
    except Exception as e:
        log.warning(f"Email notify failed: {e}")

def format_money(cents:int) -> str:
    return f"${cents/100:.2f}" if CURRENCY.upper()=="USD" else f"{cents/100:.2f} {CURRENCY}"

@app.context_processor
def inject_globals():
    qty = 0
    if hasattr(current_user, "is_authenticated") and current_user.is_authenticated:
        with main_session() as db:
            qty = db.scalar(
                select(func.coalesce(func.sum(CartItem.quantity), 0))
                .where(CartItem.user_id == int(current_user.id))
            ) or 0
    return {"SITE_NAME": SITE_NAME, "cart_qty": qty, "format_money": format_money}

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc

# ---------- Optional reverse geocode (cache only if your external DB has `physical_address`) ----------
def reverse_geocode(lat, lng):
    if lat is None or lng is None: return None
    try:
        r = requests.get("https://nominatim.openstreetmap.org/reverse",
                         params={"format":"jsonv2","lat":lat,"lon":lng,"zoom":16},
                         headers={"User-Agent":"ecommerce_v2/1.0"}, timeout=5)
        if r.ok:
            return r.json().get("display_name")
    except Exception as e:
        log.info(f"reverse_geocode failed: {e}")
    return None

# --------------------------- AUTH ROUTES ---------------------------
@app.get("/login")
def login():
    return render_template("login.html")

@app.post("/login")
def login_post():
    email = request.form.get("email","").strip().lower()
    password = request.form.get("password","")
    with main_session() as db:
        u = db.execute(select(User).where(User.email==email)).scalar_one_or_none()
        if not u or not bcrypt.checkpw(password.encode(), u.password_hash.encode()):
            notify(f"Failed login attempt for {email}")
            return (render_template("login.html", error="Invalid credentials"), 401)
        login_user(LoginUser(u))
    return redirect(url_for("index"))

@app.get("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.get("/register")
def register():
    return render_template("register.html")

@app.post("/register")
def register_post():
    email = request.form.get("email","").strip().lower()
    password = request.form.get("password","")
    device_id = request.form.get("device_id","").strip()
    if not email or not password:
        return (render_template("register.html", error="Email and password required"), 400)
    with main_session() as db:
        exists = db.execute(select(User).where(User.email==email)).scalar_one_or_none()
        if exists:
            return (render_template("register.html", error="User already exists"), 409)
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        u = User(email=email, password_hash=pw_hash)
        db.add(u); db.flush()
        if device_id:
            db.add(Device(device_id=device_id, user_id=u.id))
        db.commit()
        login_user(LoginUser(u))
    return redirect(url_for("index"))

# --------------------------- CATALOG ---------------------------
@app.get("/")
@login_required
def index():
    # get user's device_ids from main DB
    with main_session() as db:
        dev_ids = [d.device_id for d in db.execute(
            select(Device).where(Device.user_id == int(current_user.id))
        ).scalars().all()]

    products = []
    if dev_ids:
        # fetch products from external LOADER DB
        with loader_session() as ldb:
            products = ldb.execute(
                select(UploadProduct)
                .where(UploadProduct.device_id.in_(dev_ids))
                .order_by(UploadProduct.uploaded_at.desc())
            ).scalars().all()
            # optional: if your LOADER DB has a physical_address column and you WANT to cache it here,
            # you can populate it, BUT that writes to the external DB. Most people leave it read-only.
    return render_template("index.html", products=products)

@app.get("/product/<int:pid>")
@login_required
def product(pid):
    with loader_session() as ldb:
        p = ldb.get(UploadProduct, pid)
        if not p: abort(404)

    # ownership check in main DB
    with main_session() as db:
        owns = db.execute(
            select(Device).where(Device.user_id == int(current_user.id),
                                 Device.device_id == p.device_id)
        ).scalar_one_or_none()
        if not owns: abort(403)

    return render_template("product.html", p=p)

# --------------------------- CART ---------------------------
@app.post("/cart/add")
@login_required
def cart_add():
    pid = request.form.get("product_id", type=int)
    qty = max(1, request.form.get("quantity", type=int, default=1))
    if not pid: abort(400)

    # fetch product from external DB
    with loader_session() as ldb:
        p = ldb.get(UploadProduct, pid)
        if not p: abort(404)

    with main_session() as db:
        # enforce device ownership
        owns = db.execute(
            select(Device).where(Device.user_id == int(current_user.id),
                                 Device.device_id == p.device_id)
        ).scalar_one_or_none()
        if not owns: abort(403)

        row = db.execute(
            select(CartItem).where(CartItem.user_id == int(current_user.id),
                                   CartItem.product_id == pid)
        ).scalar_one_or_none()
        if row:
            row.quantity += qty
        else:
            db.add(CartItem(user_id=int(current_user.id), product_id=pid, quantity=qty))

        # snapshot
        snap = {"items":[]}
        all_items = db.execute(
            select(CartItem).where(CartItem.user_id == int(current_user.id))
        ).scalars().all()
        for it in all_items:
            snap["items"].append({"product_id": it.product_id, "quantity": it.quantity})
        db.add(CartSnapshot(user_id=int(current_user.id), json_payload=json.dumps(snap)))
        db.commit()

    return redirect(request.form.get("next") or url_for("cart_view"))

@app.get("/cart")
@login_required
def cart_view():
    products = []
    subtotal = 0

    # read cart rows (main DB)
    with main_session() as db:
        items = db.execute(
            select(CartItem).where(CartItem.user_id == int(current_user.id))
        ).scalars().all()

    # enrich with product rows (external DB)
    if items:
        with loader_session() as ldb:
            for it in items:
                p = ldb.get(UploadProduct, it.product_id)
                if not p:
                    continue
                price = DEFAULT_PRICE_CENTS
                line = price * it.quantity
                subtotal += line
                products.append((p, it.quantity, line))

    return render_template("cart.html", items=products, subtotal=subtotal)

@app.post("/cart/update")
@login_required
def cart_update():
    try:
        with main_session() as db:
            for key, val in request.form.items():
                if key.startswith("qty_"):
                    pid = int(key.split("_",1)[1])
                    row = db.execute(
                        select(CartItem).where(CartItem.user_id == int(current_user.id),
                                               CartItem.product_id == pid)
                    ).scalar_one_or_none()
                    if not row: continue
                    q = max(0, int(val or "0"))
                    if q == 0: db.delete(row)
                    else: row.quantity = q

            # snapshot
            snap = {"items":[]}
            all_items = db.execute(
                select(CartItem).where(CartItem.user_id == int(current_user.id))
            ).scalars().all()
            for it in all_items:
                snap["items"].append({"product_id": it.product_id, "quantity": it.quantity})
            db.add(CartSnapshot(user_id=int(current_user.id), json_payload=json.dumps(snap)))
            db.commit()
    except Exception as e:
        log.exception("Cart update failed")
        notify(f"Cart update failed for user {current_user.id}: {e}")
        flash("Update failed. Try recovery.", "danger")
    return redirect(url_for("cart_view"))

# --------------------------- RECOVERY ---------------------------
@app.get("/recover")
@login_required
def recover_get():
    return render_template("recover.html")

@app.post("/recover")
@login_required
def recover_post():
    with main_session() as db:
        snap = db.execute(
            select(CartSnapshot)
            .where(CartSnapshot.user_id == int(current_user.id))
            .order_by(CartSnapshot.created_at.desc())
        ).scalars().first()
        if not snap:
            flash("No snapshot found.", "warning")
            return redirect(url_for("cart_view"))
        data = json.loads(snap.json_payload)
        db.query(CartItem).filter(CartItem.user_id == int(current_user.id)).delete()
        for it in data.get("items", []):
            db.add(CartItem(user_id=int(current_user.id),
                            product_id=int(it["product_id"]),
                            quantity=int(it["quantity"])))
        db.commit()
    flash("Cart recovered.", "success")
    return redirect(url_for("cart_view"))

# --------------------------- CHECKOUT (Stripe) ---------------------------
@app.get("/checkout")
@login_required
def checkout_get():
    with main_session() as db:
        has = db.execute(
            select(CartItem.id).where(CartItem.user_id == int(current_user.id))
        ).first()
        if not has:
            flash("Cart is empty.", "warning")
            return redirect(url_for("index"))
    return render_template("checkout.html")

@app.post("/api/stripe/checkout")
@login_required
def stripe_checkout():
    name = request.form.get("name","").strip()
    email = request.form.get("email","").strip()
    address = request.form.get("address","").strip()
    if not (name and email and address):
        return jsonify({"error":"Missing fields"}), 400

    with main_session() as db:
        items = db.execute(
            select(CartItem).where(CartItem.user_id == int(current_user.id))
        ).scalars().all()

    if not items:
        return jsonify({"error":"Cart empty"}), 400

    line_items = []
    total = 0
    with loader_session() as ldb:
        for it in items:
            p = ldb.get(UploadProduct, it.product_id)
            if not p:
                continue
            price = DEFAULT_PRICE_CENTS
            total += price * it.quantity
            line_items.append({
                "quantity": it.quantity,
                "price_data": {
                    "currency": CURRENCY.lower(),
                    "unit_amount": price,
                    "product_data": {
                        "name": p.original_name or p.filename or f"Item {p.id}",
                        "description": (p.ocr_text or "")[:200],
                        "images": [p.img_url()] if p.img_url() else []
                    }
                }
            })

    with main_session() as db:
        o = Order(user_id=int(current_user.id), email=email, name=name, address=address,
                  total_cents=total, status="pending")
        db.add(o); db.flush()
        try:
            cs = stripe.checkout.Session.create(
                mode="payment",
                customer_email=email,
                line_items=line_items,
                success_url=f"{PUBLIC_BASE_URL}/success?order_id={o.id}",
                cancel_url=f"{PUBLIC_BASE_URL}/cart",
                metadata={"order_id": str(o.id), "user_id": str(current_user.id)}
            )
            o.stripe_session_id = cs.id
            db.commit()
            return redirect(cs.url, code=303)
        except Exception as e:
            db.rollback()
            log.exception("Stripe checkout create failed")
            notify(f"Stripe checkout failed for user {current_user.id}: {e}")
            o.status = "failed"; db.add(o); db.commit()
            flash("Payment init failed. Try again or use recovery.", "danger")
            return redirect(url_for("cart_view"))

@app.get("/success")
@login_required
def success_page():
    order_id = request.args.get("order_id", type=int)
    if not order_id: return redirect(url_for("index"))
    with main_session() as db:
        o = db.get(Order, order_id)
        if not o or o.user_id != int(current_user.id):
            abort(404)
        total = o.total_cents
    return render_template("success.html", order_id=order_id, total_cents=total)

# --------------------------- STRIPE WEBHOOK ---------------------------
@app.post("/webhooks/stripe")
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig = request.headers.get("Stripe-Signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        log.warning(f"Stripe webhook signature failure: {e}")
        return "bad sig", 400
    try:
        if event["type"] == "checkout.session.completed":
            data = event["data"]["object"]
            order_id = int(data["metadata"]["order_id"])
            with main_session() as db:
                o = db.get(Order, order_id)
                if o:
                    o.status = "paid"
                    db.commit()
                    notify(f"Order #{o.id} paid by user {o.user_id}")
        return "ok", 200
    except Exception as e:
        log.exception("Stripe webhook error")
        notify(f"Stripe webhook error: {e}")
        return "error", 500

# --------------------------- 404 ---------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

UPLOAD_DIR = "/var/www/LOADER/uploads"  # your real folder

@app.get("/media/<path:filename>")
def media(filename):
    return send_from_directory(UPLOAD_DIR, filename, conditional=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7000, debug=True)

