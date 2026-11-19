# Test fixture for workers/rules/pathos-database.yml (Python). Not executed.
import json
import os

from django.db.models.expressions import RawSQL
from flask import request
from sqlalchemy import text

from app.models import User


def dbapi(cursor, name, uid):
    # ruleid: pathos.database.python.sql-string-building
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    # ruleid: pathos.database.python.sql-string-building
    cursor.execute("SELECT * FROM users WHERE id = %s" % uid)
    # ruleid: pathos.database.python.sql-string-building
    cursor.execute(f"DELETE FROM users WHERE id = {uid}")
    query = "UPDATE users SET name = '" + name + "'"
    # ruleid: pathos.database.python.sql-string-building
    cursor.execute(query)
    # ok: pathos.database.python.sql-string-building
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
    # ok: pathos.database.python.sql-string-building
    cursor.execute("SELECT 1")


def django(name, order):
    # ruleid: pathos.database.python.django-raw-sql
    a = User.objects.raw(f"SELECT * FROM app_user WHERE name = '{name}'")
    # ruleid: pathos.database.python.django-raw-sql
    b = User.objects.all().extra(where=["name = '%s'" % name])
    # ruleid: pathos.database.python.django-raw-sql
    c = User.objects.annotate(v=RawSQL("SELECT score FROM s WHERE o = " + order, []))
    # ok: pathos.database.python.django-raw-sql
    d = User.objects.raw("SELECT * FROM app_user WHERE name = %s", [name])
    return a, b, c, d


def sqlalchemy(session, uid):
    # ruleid: pathos.database.python.sqlalchemy-text-formatting
    r1 = session.execute(text(f"SELECT * FROM users WHERE id = {uid}"))
    # ruleid: pathos.database.python.sqlalchemy-text-formatting
    r2 = session.execute(text("SELECT * FROM users WHERE id = " + uid))
    # ok: pathos.database.python.sqlalchemy-text-formatting
    r3 = session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": uid})
    return r1, r2, r3


def mongo(db):
    body = request.get_json()
    # ruleid: pathos.database.python.nosql-injection
    user = db.users.find_one({"name": body["name"], "password": body["password"]})
    # ok: pathos.database.python.nosql-injection
    user2 = db.users.find_one({"name": str(body["name"])})
    # ok: pathos.database.python.nosql-injection
    user3 = db.users.find_one({"name": "admin"})
    return user, user2, user3


# ruleid: pathos.database.connection-string-hardcoded-password
DATABASE_URL = "postgresql://app:fixture-db-pass-not-real@db.internal:5432/app"
# ok: pathos.database.connection-string-hardcoded-password
DATABASE_URL_OK = "postgresql://app:${DB_PASSWORD}@db.internal:5432/app"
# ok: pathos.database.connection-string-hardcoded-password
DATABASE_URL_ENV = os.environ.get("DATABASE_URL", "postgresql://localhost/app")
# ruleid: pathos.database.connection-string-tls-disabled
REPLICA_URL = "postgresql://db-replica.internal/app?sslmode=disable"
# ok: pathos.database.connection-string-tls-disabled
REPLICA_URL_OK = "postgresql://db-replica.internal/app?sslmode=verify-full"
