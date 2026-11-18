import os

# ruleid: pathos.misconfig.django.debug-true
DEBUG = True
# ok: pathos.misconfig.django.debug-true
DEBUG = os.environ.get("DJANGO_DEBUG") == "1"

# ruleid: pathos.misconfig.django.allowed-hosts-wildcard
ALLOWED_HOSTS = ["*"]
# ok: pathos.misconfig.django.allowed-hosts-wildcard
ALLOWED_HOSTS = ["app.example.com"]

# ruleid: pathos.misconfig.django.insecure-secret-key
SECRET_KEY = "django-insecure-test-fixture-not-a-real-key"
# ok: pathos.misconfig.django.insecure-secret-key
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]

# ruleid: pathos.misconfig.django.csrf-middleware-missing, pathos.misconfig.django.security-middleware-missing
MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
]

# ok: pathos.misconfig.django.csrf-middleware-missing
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
]

# ruleid: pathos.misconfig.django.insecure-cookie-settings
SESSION_COOKIE_SECURE = False
# ruleid: pathos.misconfig.django.insecure-cookie-settings
CSRF_COOKIE_SECURE = False
# ok: pathos.misconfig.django.insecure-cookie-settings
SESSION_COOKIE_HTTPONLY = True

# ruleid: pathos.misconfig.django.transport-security-disabled
SECURE_HSTS_SECONDS = 0
# ok: pathos.misconfig.django.transport-security-disabled
SECURE_SSL_REDIRECT = True

# ruleid: pathos.misconfig.django.cors-allow-all
CORS_ALLOW_ALL_ORIGINS = True
