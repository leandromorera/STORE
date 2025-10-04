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
