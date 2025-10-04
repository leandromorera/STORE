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
