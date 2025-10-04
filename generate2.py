#!/usr/bin/env python3
# scaffold_ecommerce_v2.py
# Generates a full Flask + SQLAlchemy + Stripe ecommerce app (no Docker).
# Features:
# - Users, device_id→user mapping
# - Catalog sourced from your `uploads` table (lat/lng, OCR, image, address)
# - Per-user cart (DB-backed), delete/update, recovery via snapshots
# - Stripe Checkout + webhook to mark orders "paid"
# - Logging to file + Slack/email notifications
# - Minimal templates & CSS; ready to run on localhost:3000

import os, textwrap, secrets

APP_DIR = os.path.abspath(os.path.join(os.getcwd(), "ecommerce_v2"))
FILES = {}

def put(path, content):
    path = os.path.join(APP_DIR, path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(textwrap.dedent(content).lstrip("\n"))

def main():
    os.makedirs(APP_DIR, exist_ok=True)

    # ---------- ENV / REQS ----------
    put(".env", f"""
    FLASK_SECRET_KEY={secrets.token_hex(32)}
    DATABASE_URL=sqlite:///ecommerce.db
    SITE_NAME=My Shop
    CURRENCY=USD
    PUBLIC_BASE_URL=http://localhost:3000

    # Optional Slack/email notifications for errors & payments
    SLACK_WEBHOOK_URL=
    SMTP_HOST=
    SMTP_PORT=587
    SMTP_USER=
    SMTP_PASS=
    ALERT_EMAIL_TO=

    # Stripe
    STRIPE_SECRET_KEY=sk_test_xxx
    STRIPE_WEBHOOK_SECRET=whsec_xxx
    """)

    put("requirements.txt", """
    Flask==3.0.3
    SQLAlchemy==2.0.32
    python-dotenv==1.0.1
    Flask-Login==0.6.3
    bcrypt==4.2.0
    stripe==10.5.0
    requests==2.32.3
    """)

    # Optional: conda env file
    put("environment.yml", """
    name: shop
    channels:
      - conda-forge
    dependencies:
      - python=3.11
      - flask
      - sqlalchemy
      - python-dotenv
      - pip
      - pip:
        - Flask-Login==0.6.3
        - bcrypt==4.2.0
        - stripe==10.5.0
        - requests==2.32.3
    """)

    # ---------- MODELS ----------
    put("models.py", """
    from datetime import datetime
    from sqlalchemy import (Column, Integer, String, Text, DateTime, ForeignKey,
                            Float)
    from sqlalchemy.orm import declarative_base, relationship

    Base = declarative_base()

    # Users & device assignment
    class User(Base):
        __tablename__ = "users"
        id = Column(Integer, primary_key=True)
        email = Column(String(200), unique=True, nullable=False)
        password_hash = Column(String(200), nullable=False)
        created_at = Column(DateTime, default=datetime.utcnow)
        devices = relationship("Device", back_populates="user", cascade="all, delete-orphan")
        carts = relationship("CartItem", back_populates="user", cascade="all, delete-orphan")
        orders = relationship("Order", back_populates="user")

    class Device(Base):
        __tablename__ = "devices"
        id = Column(Integer, primary_key=True)
        device_id = Column(String(64), unique=True, nullable=False)  # matches uploads.device_id
        user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
        user = relationship("User", back_populates="devices")

    # Map to your existing uploads table (adjust name if different)
    class UploadProduct(Base):
        __tablename__ = "uploads"
        id = Column(Integer, primary_key=True)
        filename = Column(String(255))
        original_name = Column(String(255))
        stored_path = Column(String(512))
        ocr_text = Column(Text)
        lat = Column(Float)
        lng = Column(Float)
        taken_at_iso = Column(String(64))
        device_id = Column(String(64), index=True)
        uploaded_at = Column(String(64))
        analysis_type = Column(String(64))
        analysis_status = Column(String(64))
        analysis_result = Column(Text)
        analyzed_at = Column(String(64))
        rag_job_id = Column(String(64))
        analysis_error = Column(Text)
        # Add-ons for commerce:
        price_cents = Column(Integer, default=1000)  # Fallback if you don't store price yet
        physical_address = Column(Text)              # Cached reverse geocode

        def img_url(self):
            # Adjust if you serve images differently. For dev you can host from /static/uploads or absolute URL.
            return self.stored_path

    # Cart / Orders
    class CartItem(Base):
        __tablename__ = "cart_items"
        id = Column(Integer, primary_key=True)
        user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
        product_id = Column(Integer, ForeignKey("uploads.id"), nullable=False)
        quantity = Column(Integer, nullable=False, default=1)
        user = relationship("User", back_populates="carts")
        product = relationship("UploadProduct")

    class CartSnapshot(Base):
        __tablename__ = "cart_snapshots"
        id = Column(Integer, primary_key=True)
        user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
        json_payload = Column(Text, nullable=False)
        created_at = Column(DateTime, default=datetime.utcnow)

    class Order(Base):
        __tablename__ = "orders"
        id = Column(Integer, primary_key=True)
        user_id = Column(Integer, ForeignKey("users.id"))
        email = Column(String(200), nullable=False)
        name = Column(String(200), nullable=False)
        address = Column(Text, nullable=False)
        total_cents = Column(Integer, nullable=False, default=0)
        status = Column(String(50), nullable=False, default="pending")  # pending|paid|failed
        stripe_session_id = Column(String(128))
        created_at = Column(DateTime, default=datetime.utcnow)
        user = relationship("User", back_populates="orders")
        items = relationship("OrderItem", back_populates="order", cascade="all, delete-orphan")

    class OrderItem(Base):
        __tablename__ = "order_items"
        id = Column(Integer, primary_key=True)
        order_id = Column(Integer, ForeignKey("orders.id"), nullable=False)
        product_id = Column(Integer, ForeignKey("uploads.id"), nullable=False)
        quantity = Column(Integer, nullable=False, default=1)
        unit_price_cents = Column(Integer, nullable=False, default=0)
        order = relationship("Order", back_populates="items")
        product = relationship("UploadProduct")
    """)

    # ---------- APP ----------
    put("app.py", """
    import os, json, logging, smtplib, bcrypt, requests, stripe
    from email.mime.text import MIMEText
    from urllib.parse import urlparse, urljoin

    from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
    from sqlalchemy import create_engine, select, func
    from sqlalchemy.orm import Session
    from dotenv import load_dotenv
    from flask_login import (LoginManager, login_user, login_required, logout_user,
                             current_user, UserMixin)

    from models import Base, User, Device, UploadProduct, CartItem, CartSnapshot, Order, OrderItem

    load_dotenv()
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///ecommerce.db")
    SITE_NAME = os.getenv("SITE_NAME", "My Shop")
    CURRENCY = os.getenv("CURRENCY", "USD")
    SECRET = os.getenv("FLASK_SECRET_KEY", "dev-key")
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

    # DB & schema
    engine = create_engine(DATABASE_URL, future=True)
    Base.metadata.create_all(engine)

    # Auth
    login_manager = LoginManager(app)
    login_manager.login_view = "login"

    class LoginUser(UserMixin):
        def __init__(self, u: User):
            self.id = str(u.id)
            self.email = u.email

    @login_manager.user_loader
    def load_user(user_id):
        with Session(engine) as db:
            u = db.get(User, int(user_id))
            return LoginUser(u) if u else None

    # Logging
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
            with Session(engine) as db:
                qty = db.scalar(select(func.coalesce(func.sum(CartItem.quantity), 0)).where(CartItem.user_id==int(current_user.id))) or 0
        return {"SITE_NAME": SITE_NAME, "cart_qty": qty, "format_money": format_money}

    def is_safe_url(target):
        ref_url = urlparse(request.host_url)
        test_url = urlparse(urljoin(request.host_url, target))
        return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc

    # Optional reverse geocode (cache to physical_address)
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

    # ---------- AUTH ----------
    @app.get("/login")
    def login():
        return render_template("login.html")

    @app.post("/login")
    def login_post():
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        with Session(engine) as db:
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
        with Session(engine) as db:
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

    # ---------- CATALOG (uploads bound to user's devices) ----------
    @app.get("/")
    @login_required
    def index():
        with Session(engine) as db:
            dev_ids = [d.device_id for d in db.execute(select(Device).where(Device.user_id==int(current_user.id))).scalars().all()]
            items = []
            if dev_ids:
                rows = db.execute(select(UploadProduct).where(UploadProduct.device_id.in_(dev_ids))
                                  .order_by(UploadProduct.uploaded_at.desc())).scalars().all()
                for p in rows:
                    if not p.physical_address and p.lat is not None and p.lng is not None:
                        addr = reverse_geocode(p.lat, p.lng)
                        if addr:
                            p.physical_address = addr
                            db.add(p)
                db.commit()
                items = rows
        return render_template("index.html", products=items)

    @app.get("/product/<int:pid>")
    @login_required
    def product(pid):
        with Session(engine) as db:
            p = db.get(UploadProduct, pid)
            if not p: abort(404)
            # enforce ownership
            owns = db.execute(select(Device).where(Device.user_id==int(current_user.id),
                                                   Device.device_id==p.device_id)).scalar_one_or_none()
            if not owns: abort(403)
        return render_template("product.html", p=p)

    # ---------- CART ----------
    @app.post("/cart/add")
    @login_required
    def cart_add():
        pid = request.form.get("product_id", type=int)
        qty = max(1, request.form.get("quantity", type=int, default=1))
        if not pid: abort(400)
        try:
            with Session(engine) as db:
                p = db.get(UploadProduct, pid)
                if not p: abort(404)
                owns = db.execute(select(Device).where(Device.user_id==int(current_user.id),
                                                       Device.device_id==p.device_id)).scalar_one_or_none()
                if not owns: abort(403)
                row = db.execute(select(CartItem).where(CartItem.user_id==int(current_user.id),
                                                        CartItem.product_id==pid)).scalar_one_or_none()
                if row:
                    row.quantity += qty
                else:
                    db.add(CartItem(user_id=int(current_user.id), product_id=pid, quantity=qty))
                # snapshot
                snap = {"items":[]}
                all_items = db.execute(select(CartItem).where(CartItem.user_id==int(current_user.id))).scalars().all()
                for it in all_items:
                    snap["items"].append({"product_id": it.product_id, "quantity": it.quantity})
                db.add(CartSnapshot(user_id=int(current_user.id), json_payload=json.dumps(snap)))
                db.commit()
            return redirect(request.form.get("next") or url_for("cart_view"))
        except Exception as e:
            logging.exception("cart_add failed")
            notify(f"Cart add failed for user {current_user.id}: {e}")
            return (redirect(url_for("recover_get")), 302)

    @app.get("/cart")
    @login_required
    def cart_view():
        with Session(engine) as db:
            items = db.execute(select(CartItem).where(CartItem.user_id==int(current_user.id))).scalars().all()
            products = []; subtotal = 0
            for it in items:
                p = db.get(UploadProduct, it.product_id)
                if not p: continue
                line = it.quantity * (p.price_cents or 0)
                subtotal += line
                products.append((p, it.quantity, line))
        return render_template("cart.html", items=products, subtotal=subtotal)

    @app.post("/cart/update")
    @login_required
    def cart_update():
        try:
            with Session(engine) as db:
                for key, val in request.form.items():
                    if key.startswith("qty_"):
                        pid = int(key.split("_",1)[1])
                        row = db.execute(select(CartItem).where(CartItem.user_id==int(current_user.id),
                                                                CartItem.product_id==pid)).scalar_one_or_none()
                        if not row: continue
                        q = max(0, int(val or "0"))
                        if q == 0: db.delete(row)
                        else: row.quantity = q
                # snapshot
                snap = {"items":[]}
                all_items = db.execute(select(CartItem).where(CartItem.user_id==int(current_user.id))).scalars().all()
                for it in all_items:
                    snap["items"].append({"product_id": it.product_id, "quantity": it.quantity})
                db.add(CartSnapshot(user_id=int(current_user.id), json_payload=json.dumps(snap)))
                db.commit()
            return redirect(url_for("cart_view"))
        except Exception as e:
            logging.exception("cart_update failed")
            notify(f"Cart update failed for user {current_user.id}: {e}")
            return (redirect(url_for("recover_get")), 302)

    # ---------- RECOVERY ----------
    @app.get("/recover")
    @login_required
    def recover_get():
        return render_template("recover.html")

    @app.post("/recover")
    @login_required
    def recover_post():
        with Session(engine) as db:
            snap = db.execute(
                select(CartSnapshot).where(CartSnapshot.user_id==int(current_user.id)).order_by(CartSnapshot.created_at.desc())
            ).scalars().first()
            if not snap:
                return redirect(url_for("cart_view"))
            data = json.loads(snap.json_payload)
            db.query(CartItem).filter(CartItem.user_id==int(current_user.id)).delete()
            for it in data.get("items", []):
                db.add(CartItem(user_id=int(current_user.id), product_id=it["product_id"], quantity=it["quantity"]))
            db.commit()
        return redirect(url_for("cart_view"))

    # ---------- CHECKOUT (Stripe) ----------
    @app.get("/checkout")
    @login_required
    def checkout_get():
        with Session(engine) as db:
            has = db.execute(select(CartItem.id).where(CartItem.user_id==int(current_user.id))).first()
            if not has:
                return redirect(url_for("cart_view"))
        return render_template("checkout.html")

    @app.post("/api/stripe/checkout")
    @login_required
    def stripe_checkout():
        name = request.form.get("name","").strip()
        email = request.form.get("email","").strip()
        address = request.form.get("address","").strip()
        if not (name and email and address):
            return jsonify({"error":"Missing fields"}), 400
        with Session(engine) as db:
            items = db.execute(select(CartItem).where(CartItem.user_id==int(current_user.id))).scalars().all()
            if not items:
                return jsonify({"error":"Cart empty"}), 400
            line_items = []; total = 0
            for it in items:
                p = db.get(UploadProduct, it.product_id)
                if not p: continue
                price = p.price_cents or 0
                total += price * it.quantity
                line_items.append({
                    "quantity": it.quantity,
                    "price_data": {
                        "currency": CURRENCY.lower(),
                        "unit_amount": price,
                        "product_data": {
                            "name": p.original_name or p.filename or f"Item {p.id}",
                            "description": (p.physical_address or (p.ocr_text or ""))[:200],
                            "images": [p.img_url()] if p.img_url() else []
                        }
                    }
                })
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
                logging.exception("Stripe checkout create failed")
                notify(f"Stripe checkout failed for user {current_user.id}: {e}")
                o.status = "failed"; db.add(o); db.commit()
                return redirect(url_for("cart_view"))

    @app.get("/success")
    @login_required
    def success_page():
        order_id = request.args.get("order_id", type=int)
        if not order_id: return redirect(url_for("index"))
        with Session(engine) as db:
            o = db.get(Order, order_id)
            if not o or o.user_id != int(current_user.id):
                abort(404)
            total = o.total_cents
        return render_template("success.html", order_id=order_id, total_cents=total)

    # Stripe webhook
    @app.post("/webhooks/stripe")
    def stripe_webhook():
        payload = request.get_data(as_text=True)
        sig = request.headers.get("Stripe-Signature", "")
        try:
            event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
        except Exception as e:
            logging.warning(f"Stripe webhook signature failure: {e}")
            return "bad sig", 400
        try:
            if event["type"] == "checkout.session.completed":
                data = event["data"]["object"]
                order_id = int(data["metadata"]["order_id"])
                with Session(engine) as db:
                    o = db.get(Order, order_id)
                    if o:
                        o.status = "paid"
                        db.commit()
                        notify(f"Order #{o.id} paid by user {o.user_id}")
            return "ok", 200
        except Exception as e:
            logging.exception("Stripe webhook error")
            notify(f"Stripe webhook error: {e}")
            return "error", 500

    @app.errorhandler(404)
    def not_found(e):
        return render_template("404.html"), 404

    if __name__ == "__main__":
        app.run(host="0.0.0.0", port=3000, debug=True)
    """)

    # ---------- TEMPLATES ----------
    put("templates/base.html", """
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8"/>
      <meta name="viewport" content="width=device-width, initial-scale=1"/>
      <title>{{ SITE_NAME }}</title>
      <link rel="stylesheet" href="{{ url_for('static', filename='styles.css') }}">
    </head>
    <body>
      <header class="header">
        <a class="brand" href="{{ url_for('index') }}">{{ SITE_NAME }}</a>
        <nav class="nav">
          {% if current_user.is_authenticated %}
            <a href="{{ url_for('cart_view') }}">Cart ({{ cart_qty }})</a>
            <a href="{{ url_for('logout') }}">Logout</a>
          {% else %}
            <a href="{{ url_for('login') }}">Login</a>
            <a href="{{ url_for('register') }}">Register</a>
          {% endif %}
        </nav>
      </header>
      <main class="container">
        {% if error %}<div class="flash-item danger">{{ error }}</div>{% endif %}
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            <div class="flash">
              {% for cat, msg in messages %}
                <div class="flash-item {{ cat }}">{{ msg }}</div>
              {% endfor %}
            </div>
          {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
      </main>
      <footer class="footer">© {{ SITE_NAME }}</footer>
    </body>
    </html>
    """)

    put("templates/login.html", """
    {% extends "base.html" %}
    {% block content %}
    <h1>Login</h1>
    <form method="post" action="{{ url_for('login_post') }}" class="form">
      <label>Email <input name="email" type="email" required></label>
      <label>Password <input name="password" type="password" required></label>
      <button class="btn" type="submit">Login</button>
    </form>
    <p>No account? <a href="{{ url_for('register') }}">Register</a></p>
    {% endblock %}
    """)

    put("templates/register.html", """
    {% extends "base.html" %}
    {% block content %}
    <h1>Register</h1>
    <form method="post" action="{{ url_for('register_post') }}" class="form">
      <label>Email <input name="email" type="email" required></label>
      <label>Password <input name="password" type="password" required></label>
      <label>Device ID (optional) <input name="device_id"></label>
      <button class="btn" type="submit">Create account</button>
    </form>
    {% endblock %}
    """)

    put("templates/index.html", """
    {% extends "base.html" %}
    {% block content %}
      <h1>Products</h1>
      {% if not products %}
        <p>No products yet. Link a device_id with uploads for this user.</p>
      {% else %}
      <div class="grid">
        {% for p in products %}
          <div class="card">
            <a href="{{ url_for('product', pid=p.id) }}">
              <img src="{{ p.img_url() or 'https://picsum.photos/seed/noimg/600/600' }}" alt="{{ p.original_name or p.filename }}">
            </a>
            <div class="pad">
              <div class="title">
                <a href="{{ url_for('product', pid=p.id) }}">{{ p.original_name or p.filename }}</a>
              </div>
              <div class="price">{{ format_money(p.price_cents or 0) }}</div>
              <form method="post" action="{{ url_for('cart_add') }}">
                <input type="hidden" name="product_id" value="{{ p.id }}">
                <button class="btn">Add to cart</button>
              </form>
            </div>
          </div>
        {% endfor %}
      </div>
      {% endif %}
    {% endblock %}
    """)

    put("templates/product.html", """
    {% extends "base.html" %}
    {% block content %}
      <div class="product">
        <img class="product-img" src="{{ p.img_url() or 'https://picsum.photos/seed/noimg/800/800' }}" alt="">
        <div class="product-info">
          <h1>{{ p.original_name or p.filename }}</h1>
          <div class="price">{{ format_money(p.price_cents or 0) }}</div>
          {% if p.physical_address %}<p><b>Address:</b> {{ p.physical_address }}</p>{% endif %}
          {% if p.lat and p.lng %}<p><b>Location:</b> {{ p.lat }}, {{ p.lng }}</p>{% endif %}
          {% if p.ocr_text %}<p><b>OCR:</b> {{ p.ocr_text }}</p>{% endif %}
          <form method="post" action="{{ url_for('cart_add') }}">
            <input type="hidden" name="product_id" value="{{ p.id }}">
            <label>Qty <input type="number" name="quantity" min="1" value="1"></label>
            <button class="btn">Add to cart</button>
          </form>
        </div>
      </div>
    {% endblock %}
    """)

    put("templates/cart.html", """
    {% extends "base.html" %}
    {% block content %}
      <h1>Your Cart</h1>
      {% if not items %}
        <p>Cart is empty.</p>
      {% else %}
        <form method="post" action="{{ url_for('cart_update') }}">
          <table class="table">
            <thead><tr><th>Item</th><th>Qty</th><th>Price</th><th>Total</th></tr></thead>
            <tbody>
              {% for p, q, line in items %}
                <tr>
                  <td class="row">
                    <img src="{{ p.img_url() or 'https://picsum.photos/seed/noimg/80/80' }}" width="48" height="48" alt="">
                    <a href="{{ url_for('product', pid=p.id) }}">{{ p.original_name or p.filename }}</a>
                  </td>
                  <td><input type="number" name="qty_{{ p.id }}" min="0" value="{{ q }}"></td>
                  <td>{{ format_money(p.price_cents or 0) }}</td>
                  <td>{{ format_money(line) }}</td>
                </tr>
              {% endfor %}
            </tbody>
          </table>
          <div class="row space-between" style="margin-top: 12px;">
            <a class="btn secondary" href="{{ url_for('index') }}">Continue shopping</a>
            <a class="btn" href="{{ url_for('checkout_get') }}">Checkout</a>
            <button class="btn" type="submit">Update cart</button>
          </div>
        </form>
      {% endif %}
    {% endblock %}
    """)

    put("templates/checkout.html", """
    {% extends "base.html" %}
    {% block content %}
    <h1>Checkout</h1>
    <form method="post" action="{{ url_for('stripe_checkout') }}" class="form">
      <label>Name <input name="name" required></label>
      <label>Email <input name="email" type="email" required></label>
      <label>Address <textarea name="address" required></textarea></label>
      <button class="btn" type="submit">Proceed to Stripe</button>
    </form>
    {% endblock %}
    """)

    put("templates/success.html", """
    {% extends "base.html" %}
    {% block content %}
    <h1>Thank you!</h1>
    <p>Your order was placed successfully.</p>
    <p>Order ID: <b>#{{ order_id }}</b></p>
    <p>Total: <b>{{ format_money(total_cents) }}</b></p>
    <a class="btn" href="{{ url_for('index') }}">Back to store</a>
    {% endblock %}
    """)

    put("templates/recover.html", """
    {% extends "base.html" %}
    {% block content %}
    <h1>Recover Cart</h1>
    <form method="post" action="{{ url_for('recover_post') }}">
      <button class="btn" type="submit">Restore last snapshot</button>
    </form>
    {% endblock %}
    """)

    put("templates/404.html", """
    {% extends "base.html" %}
    {% block content %}
      <h1>Not found</h1>
      <p>The page you requested could not be found.</p>
      <a class="btn" href="{{ url_for('index') }}">Go home</a>
    {% endblock %}
    """)

    # ---------- STATIC ----------
    put("static/styles.css", """
    :root { --max: 1100px; --border:#e6e6e6; --text:#111; --muted:#666; --bg:#fff; }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial; color: var(--text); background: var(--bg); }
    a { color: inherit; text-decoration: none; }
    img { display:block; }
    .container { max-width: var(--max); margin: 0 auto; padding: 20px; }
    .header { display:flex; align-items:center; justify-content:space-between; padding:14px 20px; border-bottom:1px solid var(--border); }
    .brand { font-weight: 800; font-size: 18px; }
    .nav a { margin-left: 12px; padding: 6px 10px; border:1px solid var(--border); border-radius:10px; }
    .grid { display:grid; gap:16px; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); }
    .card { border:1px solid var(--border); border-radius:12px; overflow:hidden; display:flex; flex-direction:column; }
    .card img { width:100%; height:220px; object-fit:cover; }
    .pad { padding:12px; display:flex; flex-direction:column; gap:8px; }
    .title { font-weight:700; }
    .price { font-weight:700; }
    .btn { display:inline-block; background:#111; color:#fff; border:1px solid #111; border-radius:10px; padding:10px 12px; cursor:pointer; }
    .btn.secondary { background:#fff; color:#111; }
    .row { display:flex; align-items:center; gap:12px; }
    .space-between { justify-content: space-between; align-items: center; }
    .table { width:100%; border-collapse: collapse; }
    .table th, .table td { border-bottom:1px solid var(--border); padding:10px; text-align:left; vertical-align: middle; }
    .product { display:grid; grid-template-columns: 1fr 1fr; gap:24px; align-items:start; }
    .product-img { width:100%; height:auto; border:1px solid var(--border); border-radius:12px; }
    .product-info .price { font-size:20px; margin:10px 0; }
    .form { display:flex; flex-direction:column; gap:12px; max-width:480px; }
    .form input, .form textarea { width:100%; padding:10px; border:1px solid var(--border); border-radius:10px; }
    .flash { margin: 10px 0; display:flex; flex-direction:column; gap:8px; }
    .flash-item { padding:10px 12px; border-radius:8px; border:1px solid var(--border); }
    .flash-item.success { background:#eefcee; border-color:#cce8cc; }
    .flash-item.warning { background:#fff8e6; border-color:#ffecb3; }
    .flash-item.danger { background:#ffecec; border-color:#ffc9c9; }
    .footer { padding: 24px 20px; border-top:1px solid var(--border); text-align:center; color: var(--muted); }
    @media (max-width: 860px){ .product { grid-template-columns: 1fr; } }
    """)

    print(f"✅ New release scaffolded in: {APP_DIR}\n")
    print("How to run (venv):")
    print("  cd ecommerce_v2")
    print("  python3 -m venv venv && source venv/bin/activate")
    print("  pip install -r requirements.txt")
    print("  python app.py   # http://localhost:3000")
    print("\nHow to run (conda):")
    print("  conda env create -f environment.yml && conda activate shop")
    print("  python app.py   # http://localhost:3000")
    print("\nCreate a user (quick):")
    print("  python - <<'PY'\n"
          "import os,bcrypt\n"
          "from sqlalchemy import create_engine,select\n"
          "from sqlalchemy.orm import Session\n"
          "from models import Base,User,Device\n"
          "from dotenv import load_dotenv\n"
          "load_dotenv(); engine=create_engine(os.getenv('DATABASE_URL','sqlite:///ecommerce.db'),future=True)\n"
          "Base.metadata.create_all(engine)\n"
          "email='you@example.com'; pw='changeme'; device='e356c8c1ee8ca937'\n"
          "with Session(engine) as db:\n"
          "  u=db.execute(select(User).where(User.email==email)).scalar_one_or_none()\n"
          "  if not u:\n"
          "    u=User(email=email,password_hash=bcrypt.hashpw(pw.encode(),bcrypt.gensalt()).decode()); db.add(u); db.flush();\n"
          "    db.add(Device(device_id=device,user_id=u.id)); db.commit(); print('created user & device')\n"
          "  else:\n"
          "    print('user exists')\n"
          "PY")
    print("\nStripe:")
    print("  - Set STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET in .env")
    print("  - In Stripe dashboard, create a webhook to http://localhost:3000/webhooks/stripe for event 'checkout.session.completed'")
    print("\nNotes:")
    print("  - We map products to your existing `uploads` table via SQLAlchemy (no schema change unless you add price/address columns).")
    print("  - Ensure each user's device_id is linked in the `devices` table so they only see their own items.")
    print("  - Errors go to app.log and (optionally) Slack/email via .env settings.")
    print("  - Recovery page: /recover to restore last cart snapshot.\n")

if __name__ == "__main__":
    main()
