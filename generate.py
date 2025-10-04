#!/usr/bin/env python3
import os, textwrap, secrets, json

ROOT = os.path.abspath(os.path.join(os.getcwd(), "ecommerce_site"))
APP = os.path.join(ROOT, "app.py")
MODELS = os.path.join(ROOT, "models.py")
REQ = os.path.join(ROOT, "requirements.txt")
SEED = os.path.join(ROOT, "seed.py")
ENV = os.path.join(ROOT, ".env")
TPL = os.path.join(ROOT, "templates")
STC = os.path.join(ROOT, "static")
CSS = os.path.join(STC, "styles.css")
DB = os.path.join(ROOT, "ecommerce.db")

def write(path, content):
  os.makedirs(os.path.dirname(path), exist_ok=True)
  with open(path, "w", encoding="utf-8") as f:
    f.write(textwrap.dedent(content).lstrip("\n"))

def main():
  os.makedirs(ROOT, exist_ok=True)
  os.makedirs(TPL, exist_ok=True)
  os.makedirs(STC, exist_ok=True)

# .env with a random secret key
secret = secrets.token_hex(32)
write(ENV, f"""
FLASK_SECRET_KEY={secret}
DATABASE_URL=sqlite:///{DB}
SITE_NAME=My Shop
CURRENCY=USD
""")

# requirements
write(REQ, """
Flask==3.0.3
SQLAlchemy==2.0.32
python-dotenv==1.0.1
""")

# models.py
write(MODELS, """
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy import Numeric
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class Product(Base):
    __tablename__ = "products"
    id = Column(Integer, primary_key=True)
    title = Column(String(200), nullable=False)
    slug = Column(String(200), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    price_cents = Column(Integer, nullable=False, default=0)
    image_url = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def price_display(self, currency="USD"):
        return f"${self.price_cents/100:.2f}" if currency == "USD" else f"{self.price_cents/100:.2f} {currency}"

class Order(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True)
    email = Column(String(200), nullable=False)
    name = Column(String(200), nullable=False)
    address = Column(Text, nullable=False)
    total_cents = Column(Integer, nullable=False, default=0)
    status = Column(String(50), nullable=False, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    items = relationship("OrderItem", back_populates="order", cascade="all, delete-orphan")

class OrderItem(Base):
    __tablename__ = "order_items"
    id = Column(Integer, primary_key=True)
    order_id = Column(Integer, ForeignKey("orders.id"), nullable=False)
    product_id = Column(Integer, ForeignKey("products.id"), nullable=False)
    quantity = Column(Integer, nullable=False, default=1)
    unit_price_cents = Column(Integer, nullable=False, default=0)
    order = relationship("Order", back_populates="items")
    product = relationship("Product")
""")

# app.py
write(APP, """
import os
from functools import wraps
from urllib.parse import urlparse, urljoin

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from models import Base, Product, Order, OrderItem

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///ecommerce.db")
SITE_NAME = os.getenv("SITE_NAME", "My Shop")
CURRENCY = os.getenv("CURRENCY", "USD")
SECRET = os.getenv("FLASK_SECRET_KEY", "dev-key")

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = SECRET

engine = create_engine(DATABASE_URL, future=True)
Base.metadata.create_all(engine)

def format_money(cents:int) -> str:
    if CURRENCY.upper() == "USD":
        return f"${cents/100:.2f}"
    return f"{cents/100:.2f} {CURRENCY}"

def get_cart():
    return session.get("cart_v1", {})

def save_cart(cart: dict):
    session["cart_v1"] = cart

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc

@app.context_processor
def inject_globals():
    cart = get_cart()
    qty = sum(cart.values()) if isinstance(cart, dict) else 0
    return {"SITE_NAME": SITE_NAME, "cart_qty": qty, "format_money": format_money}

@app.get("/")
def index():
    with Session(engine) as db:
        products = db.execute(select(Product).order_by(Product.created_at.desc())).scalars().all()
    return render_template("index.html", products=products)

@app.get("/product/<slug>")
def product(slug):
    with Session(engine) as db:
        prod = db.execute(select(Product).where(Product.slug == slug)).scalar_one_or_none()
    if not prod:
        abort(404)
    return render_template("product.html", p=prod)

@app.post("/cart/add")
def cart_add():
    product_id = request.form.get("product_id", type=int)
    qty = max(1, request.form.get("quantity", type=int, default=1))
    if not product_id:
        abort(400)
    # verify product exists
    with Session(engine) as db:
        exists = db.get(Product, product_id)
        if not exists:
            abort(404)
    cart = get_cart()
    cart[str(product_id)] = cart.get(str(product_id), 0) + qty
    save_cart(cart)
    flash("Added to cart.", "success")
    next_url = request.form.get("next") or url_for("cart_view")
    return redirect(next_url if is_safe_url(next_url) else url_for("cart_view"))

@app.get("/cart")
def cart_view():
    cart = get_cart()
    ids = [int(k) for k in cart.keys()]
    products = []
    subtotal = 0
    with Session(engine) as db:
        if ids:
            rows = db.execute(select(Product).where(Product.id.in_(ids))).scalars().all()
            for p in rows:
                q = cart.get(str(p.id), 0)
                line = q * p.price_cents
                subtotal += line
                products.append((p, q, line))
    return render_template("cart.html", items=products, subtotal=subtotal)

@app.post("/cart/update")
def cart_update():
    cart = {}
    for key, value in request.form.items():
        if key.startswith("qty_"):
            pid = key.split("_", 1)[1]
            try:
                q = max(0, int(value))
            except:
                q = 0
            if q > 0:
                cart[pid] = q
    save_cart(cart)
    flash("Cart updated.", "success")
    return redirect(url_for("cart_view"))

@app.get("/checkout")
def checkout_get():
    cart = get_cart()
    if not cart:
        flash("Cart is empty.", "warning")
        return redirect(url_for("index"))
    return render_template("checkout.html")

@app.post("/checkout")
def checkout_post():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    address = request.form.get("address", "").strip()
    if not (name and email and address):
        flash("Please fill in all fields.", "danger")
        return redirect(url_for("checkout_get"))

    cart = get_cart()
    if not cart:
        flash("Cart is empty.", "warning")
        return redirect(url_for("index"))

    ids = [int(k) for k in cart.keys()]
    with Session(engine) as db:
        rows = db.execute(select(Product).where(Product.id.in_(ids))).scalars().all()
        # compute total
        total = 0
        for p in rows:
            q = cart.get(str(p.id), 0)
            total += p.price_cents * q

        order = Order(email=email, name=name, address=address, total_cents=total, status="pending")
        db.add(order)
        db.flush()  # get order.id

        for p in rows:
            q = cart.get(str(p.id), 0)
            if q > 0:
                item = OrderItem(order_id=order.id, product_id=p.id, quantity=q, unit_price_cents=p.price_cents)
                db.add(item)

        db.commit()
        order_id = order.id

    # clear cart
    save_cart({})
    return render_template("success.html", order_id=order_id, total_cents=total)

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

if __name__ == "__main__":
    # Dev server
    app.run(host="0.0.0.0", port=3000, debug=True)
""")

# seed.py
write(SEED, """
import os
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from dotenv import load_dotenv
from models import Base, Product

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///ecommerce.db")
engine = create_engine(DATABASE_URL, future=True)
Base.metadata.create_all(engine)

demo = [
    dict(title="T-Shirt", slug="t-shirt", description="Soft cotton tee", price_cents=1999, image_url="https://picsum.photos/seed/tee/600/600"),
    dict(title="Mug", slug="mug", description="Ceramic mug", price_cents=1299, image_url="https://picsum.photos/seed/mug/600/600"),
    dict(title="Cap", slug="cap", description="Adjustable cap", price_cents=1599, image_url="https://picsum.photos/seed/cap/600/600"),
]

with Session(engine) as db:
    for d in demo:
        existing = db.execute(select(Product).where(Product.slug == d["slug"])).scalar_one_or_none()
        if existing:
            for k, v in d.items():
                setattr(existing, k, v)
        else:
            db.add(Product(**d))
    db.commit()
print("Seeded products:", len(demo))
""")

# templates
write(os.path.join(TPL, "base.html"), """
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
        <a href="{{ url_for('index') }}">Home</a>
        <a href="{{ url_for('cart_view') }}">Cart ({{ cart_qty }})</a>
      </nav>
    </header>
    <main class="container">
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

write(os.path.join(TPL, "index.html"), """
{% extends "base.html" %}
{% block content %}
  <h1>Products</h1>
  <div class="grid">
    {% for p in products %}
      <div class="card">
        <a href="{{ url_for('product', slug=p.slug) }}">
          <img src="{{ p.image_url or 'https://picsum.photos/seed/noimg/600/600' }}" alt="{{ p.title }}">
        </a>
        <div class="pad">
          <div class="title"><a href="{{ url_for('product', slug=p.slug) }}">{{ p.title }}</a></div>
          <div class="price">{{ format_money(p.price_cents) }}</div>
          <form method="post" action="{{ url_for('cart_add') }}">
            <input type="hidden" name="product_id" value="{{ p.id }}">
            <input type="hidden" name="next" value="{{ request.full_path }}">
            <button class="btn">Add to cart</button>
          </form>
        </div>
      </div>
    {% endfor %}
  </div>
{% endblock %}
""")

write(os.path.join(TPL, "product.html"), """
{% extends "base.html" %}
{% block content %}
  <div class="product">
    <img class="product-img" src="{{ p.image_url or 'https://picsum.photos/seed/noimg/800/800' }}" alt="{{ p.title }}">
    <div class="product-info">
      <h1>{{ p.title }}</h1>
      <div class="price">{{ format_money(p.price_cents) }}</div>
      <p>{{ p.description or '' }}</p>
      <form method="post" action="{{ url_for('cart_add') }}">
        <input type="hidden" name="product_id" value="{{ p.id }}">
        <label>Qty <input type="number" name="quantity" min="1" value="1"></label>
        <button class="btn">Add to cart</button>
      </form>
    </div>
  </div>
{% endblock %}
""")

write(os.path.join(TPL, "cart.html"), """
{% extends "base.html" %}
{% block content %}
  <h1>Your Cart</h1>
  {% if not items %}
    <p>Cart is empty.</p>
  {% else %}
    <form method="post" action="{{ url_for('cart_update') }}">
      <table class="table">
        <thead>
          <tr><th>Item</th><th>Qty</th><th>Price</th><th>Total</th></tr>
        </thead>
        <tbody>
          {% for p, q, line in items %}
            <tr>
              <td class="row">
                <img src="{{ p.image_url or 'https://picsum.photos/seed/noimg/80/80' }}" width="48" height="48" alt="">
                <a href="{{ url_for('product', slug=p.slug) }}">{{ p.title }}</a>
              </td>
              <td><input type="number" name="qty_{{ p.id }}" min="0" value="{{ q }}"></td>
              <td>{{ format_money(p.price_cents) }}</td>
              <td>{{ format_money(line) }}</td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
      <div class="row space-between">
        <div class="total">Subtotal: <b>{{ format_money(subtotal) }}</b></div>
        <div class="actions">
          <a class="btn secondary" href="{{ url_for('index') }}">Continue shopping</a>
          <button class="btn" type="submit">Update cart</button>
          <a class="btn" href="{{ url_for('checkout_get') }}">Checkout</a>
        </div>
      </div>
    </form>
  {% endif %}
{% endblock %}
""")

write(os.path.join(TPL, "checkout.html"), """
{% extends "base.html" %}
{% block content %}
  <h1>Checkout</h1>
  <form method="post" class="form">
    <label>Name <input name="name" required></label>
    <label>Email <input name="email" type="email" required></label>
    <label>Address <textarea name="address" required></textarea></label>
    <button class="btn" type="submit">Place order</button>
  </form>
{% endblock %}
""")

write(os.path.join(TPL, "success.html"), """
{% extends "base.html" %}
{% block content %}
  <h1>Thank you!</h1>
  <p>Your order was placed successfully.</p>
  <p>Order ID: <b>#{{ order_id }}</b></p>
  <p>Total: <b>{{ format_money(total_cents) }}</b></p>
  <a class="btn" href="{{ url_for('index') }}">Back to store</a>
{% endblock %}
""")

write(os.path.join(TPL, "404.html"), """
{% extends "base.html" %}
{% block content %}
  <h1>Not found</h1>
  <p>The page you requested could not be found.</p>
  <a class="btn" href="{{ url_for('index') }}">Go home</a>
{% endblock %}
""")

# styles
write(CSS, """
:root { --max: 1100px; --border:#e6e6e6; --text:#111; --muted:#666; --bg:#fff; --brand:#111; }
* { box-sizing: border-box; }
body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial; color: var(--text); background: var(--bg); }
a { color: inherit; text-decoration: none; }
img { display: block; }
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

# Final instructions
print(f"Scaffold created in: {ROOT}\n")
print("How to run:")
print("1) python3 -m venv venv && source venv/bin/activate")
print("2) pip install -r requirements.txt")
print("3) python seed.py   (loads 3 demo products)")
print("4) python app.py    (dev server on http://localhost:3000)")
print("\nProduction-ish with gunicorn:")
print("gunicorn -w 2 -b 0.0.0.0:3000 app:app")
print("\nDatabase file: ecommerce_site/ecommerce.db")
print("Env config:    ecommerce_site/.env")