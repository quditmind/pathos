# Test fixture for the PATHOS graph rules (example code, not executed).
import os
import requests
import psycopg
from fastapi import APIRouter
from celery import Celery

router = APIRouter()
celery_app = Celery("tasks")


# ruleid: pathos-graph-python-route-decorator
@router.get("/orders/{order_id}")
async def get_order(order_id: int):
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        # ruleid: pathos-graph-python-db-sql-read
        conn.execute("SELECT * FROM orders WHERE id = %s", (order_id,))
        # ok: pathos-graph-python-db-sql-read, pathos-graph-python-db-sql-write
        conn.execute(query)
    # ruleid: pathos-graph-python-http-call
    requests.post("https://hooks.partner.example.net/orders", json={})
    # ruleid: pathos-graph-python-queue-celery-send
    send_receipt.delay(order_id)


# ruleid: pathos-graph-python-queue-celery-task
@celery_app.task
def send_receipt(order_id):
    return order_id
