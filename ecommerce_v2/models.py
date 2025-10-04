# ecommerce_v2/models.py
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import declarative_base, relationship
import os
from urllib.parse import quote
# ----------------- MAIN APP SCHEMA (users, devices, cart, orders) -----------------
Base = declarative_base()

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
    device_id = Column(String(64), unique=True, nullable=False)  # matches uploads.device_id in external DB
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="devices")

# NO FK to uploads (it lives in another DB file)
class CartItem(Base):
    __tablename__ = "cart_items"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    product_id = Column(Integer, nullable=False)  # refers to uploads.id in external DB
    quantity = Column(Integer, nullable=False, default=1)
    user = relationship("User", back_populates="carts")

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
    product_id = Column(Integer, nullable=False)  # refers to uploads.id in external DB
    quantity = Column(Integer, nullable=False, default=1)
    unit_price_cents = Column(Integer, nullable=False, default=0)
    order = relationship("Order", back_populates="items")

# ----------------- EXTERNAL LOADER DB SCHEMA (uploads) -----------------
ExternalBase = declarative_base()

class UploadProduct(ExternalBase):
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

    def img_url(self):
        p = (self.stored_path or "").strip().replace("\\", "/")
        # if already web path, just safe-encode the filename
        if p.startswith(("http://","https://","/media/","/static/")):
            if "/" in p:
                head, tail = p.rsplit("/", 1)
                return f"{head}/{quote(tail)}"
            return p
        # if it's a disk path, serve by basename under /media
        return "/media/" + quote(os.path.basename(p))