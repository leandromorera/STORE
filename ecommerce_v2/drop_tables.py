import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

load_dotenv()
engine = create_engine(os.getenv("DATABASE_URL","sqlite:///ecommerce.db"), future=True)
with engine.begin() as conn:
    conn.execute(text("DROP TABLE IF EXISTS cart_items"))
    conn.execute(text("DROP TABLE IF EXISTS order_items"))
print("Dropped old cart/order tables (if any). They'll be recreated on app start.")