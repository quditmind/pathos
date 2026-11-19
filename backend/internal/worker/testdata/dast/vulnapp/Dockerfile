# Deliberately vulnerable test application for the worker-dast fixtures.
# Test infrastructure only: never published, never deployed.
FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir flask==3.1.3
COPY app.py /app/app.py
EXPOSE 80 443
CMD ["sh", "-c", "openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=b3-vulnapp -keyout /tmp/key.pem -out /tmp/cert.pem 2>/dev/null; exec python /app/app.py"]
