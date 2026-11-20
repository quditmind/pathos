# Example shop worker (test fixture for pathos-graph; not run).
import os

import redis
from fastapi import FastAPI

from worker.pricing import price_for, Discounts

app = FastAPI()
cache = redis.Redis(host="redis", password=os.environ.get("REDIS_PASSWORD"))


@app.get("/api/prices/{product_id}")
def get_price(product_id: int):
    cached = cache.get(f"price:{product_id}")
    if cached:
        return {"price": float(cached)}
    d = Discounts()
    value = d.apply(price_for(product_id))
    cache.set(f"price:{product_id}", value)
    return {"price": value}
