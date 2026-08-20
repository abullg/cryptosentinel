# VAmPI — Vulnerable Modern REST API
# Source: https://github.com/erev0s/VAmPI (Apache 2.0)
# Builds from a small embedded app.py with the vulnerable endpoints inlined
# (avoids needing to git clone during docker build, keeps build self-contained).

FROM python:3.11-slim

WORKDIR /app

# Install Flask + requests (VAmPI deps)
RUN pip install --no-cache-dir flask==3.0.0 requests==2.31.0

# Inline app.py — based on erev0s/VAmPI API.py
# Endpoints (all intentionally vulnerable):
#   GET  /                          → info / healthcheck
#   GET  /api/v1/books               → list books (sensitive data exposure)
#   GET  /api/v1/books/<id>          → IDOR (no authz check)
#   POST /api/v1/user/login          → login (returns JWT)
#   GET  /api/v1/user                → user info (JWT none-alg bypass)
#   GET  /api/v1/resources?cmd=ls    → command injection
#   GET  /api/v1/books?q=' OR 1=1--   → SQLi (regex match against book list)
#   POST /api/v1/user/register       → JSON body injection
COPY app.py .

ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=5000"]
