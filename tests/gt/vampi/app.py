"""
VAmPI — Vulnerable Modern REST API (embedded simplified version).
Based on https://github.com/erev0s/VAmPI (Apache 2.0 license).

This is intentionally vulnerable code. Do NOT deploy in production.
Used by CryptoSentinel GT benchmark to test API vulnerability detection.

Vulnerable endpoints (all per expected.yaml):
  - GET  /                            Healthcheck (returns service info)
  - GET  /api/v1/books                 Sensitive data exposure (returns ALL books
                                       including author+title+intro)
  - GET  /api/v1/books/<int:id>         IDOR (no authz check — any id works)
  - GET  /api/v1/books?q=<query>       SQLi pattern (regex match on payload)
  - POST /api/v1/user/login            Auth (returns weak JWT, none-alg accepted)
  - GET  /api/v1/user                   JWT alg=none bypass (accepts forged JWT)
  - GET  /api/v1/resources?cmd=<cmd>   Command injection (os.popen)
  - POST /api/v1/user/register         JSON injection (returns debug info)

Test credentials (pre-seeded):
  user/user   — normal user
  admin/admin — admin
"""
import os
import re
import json
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

# ─── IN-MEMORY DB (pre-seeded) ──────────────────────────────────────────
BOOKS = [
    {"id": 1, "title": "The Great Gatsby", "author": "F. Scott Fitzgerald", "intro": "A 1925 novel..."},
    {"id": 2, "title": "1984", "author": "George Orwell", "intro": "Dystopian social science fiction..."},
    {"id": 3, "title": "Brave New World", "author": "Aldous Huxley", "intro": "1932 dystopian novel..."},
    {"id": 4, "title": " Fahrenheit 451", "author": "Ray Bradbury", "intro": "1953 dystopian novel..."},
    {"id": 5, "title": "Animal Farm", "author": "George Orwell", "intro": "1945 political satire..."},
]

USERS = {
    "user": {"password": "user", "role": "user"},
    "admin": {"password": "admin", "role": "admin"},
}


@app.route("/", methods=["GET"])
def healthcheck():
    """Root endpoint — service info."""
    return jsonify({
        "service": "VAmPI",
        "version": "1.0-cs-gt",
        "status": "running",
        "endpoints": [
            "/api/v1/books",
            "/api/v1/books/<id>",
            "/api/v1/books?q=<query>",
            "/api/v1/user/login",
            "/api/v1/user",
            "/api/v1/resources?cmd=<cmd>",
            "/api/v1/user/register",
        ],
    })


@app.route("/api/v1/books", methods=["GET"])
def list_books():
    """Sensitive data exposure — returns ALL books including author + intro.

    A real API would paginate + restrict to public fields only.
    """
    q = request.args.get("q", "")
    if q:
        # SQLi-vulnerable regex match — if payload looks like ' OR 1=1--,
        # returns all rows (simulating SQLi bypass)
        if re.search(r"'\s*OR\s*'?\d+'?\s*=\s*'?\d+", q, re.I) or "1=1" in q:
            return jsonify({"books": BOOKS, "query": q, "warning": "SQLi pattern matched"})
        # Filter by title (regex)
        matched = [b for b in BOOKS if re.search(q, b["title"], re.I)]
        return jsonify({"books": matched, "query": q})
    return jsonify({"books": BOOKS})


@app.route("/api/v1/books/<int:book_id>", methods=["GET"])
def get_book(book_id):
    """IDOR — no authz check. Any id returns a book (even other users')."""
    if book_id < 1 or book_id > len(BOOKS):
        return jsonify({"error": "Book not found", "id": book_id}), 404
    return jsonify({"book": BOOKS[book_id - 1]})


@app.route("/api/v1/user/login", methods=["POST"])
def login():
    """Weak auth — returns a 'JWT' that accepts alg=none bypass."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    user = USERS.get(username)
    if user and user["password"] == password:
        # Deliberately weak: header + payload visible, no signature
        # (real attack: forge with alg=none and arbitrary payload)
        import base64
        header = base64.b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
        payload_b = base64.b64encode(
            json.dumps({"username": username, "role": user["role"]}).encode()
        ).decode().rstrip("=")
        sig = "weak-signature"
        token = f"{header}.{payload_b}.{sig}"
        return jsonify({"token": token, "username": username, "role": user["role"]})
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/v1/user", methods=["GET"])
def user_info():
    """JWT alg=none bypass — if Authorization header has alg=none, accept it."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Missing Bearer token"}), 401
    token = auth[7:]
    # Check if alg=none (JWT header decoded)
    try:
        import base64
        parts = token.split(".")
        if len(parts) >= 2:
            header_b64 = parts[0] + "=" * (-len(parts[0]) % 4)
            header_json = base64.urlsafe_b64decode(header_b64).decode()
            header = json.loads(header_json)
            if header.get("alg") == "none":
                # BYPASS — accept forged token
                payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
                return jsonify({
                    "user": payload.get("username", "?"),
                    "role": payload.get("role", "user"),
                    "warning": "JWT alg=none accepted — token forge bypass",
                })
            # Normal token — accept (weak validation, no signature check)
            payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
            return jsonify({
                "user": payload.get("username", "?"),
                "role": payload.get("role", "user"),
            })
    except Exception:
        pass
    return jsonify({"error": "Invalid token"}), 401


@app.route("/api/v1/resources", methods=["GET"])
def resources():
    """Command injection — os.popen on cmd parameter."""
    cmd = request.args.get("cmd", "")
    if not cmd:
        return jsonify({"resources": ["public", "internal"], "usage": "?cmd=<command>"})
    # INTENTIONALLY VULNERABLE — pass user input directly to shell
    try:
        output = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=5
        )
        return jsonify({
            "cmd": cmd,
            "stdout": output.stdout,
            "stderr": output.stderr,
            "returncode": output.returncode,
            "warning": "Command injection — user input passed to shell",
        })
    except Exception as e:
        return jsonify({"cmd": cmd, "error": str(e)}), 500


@app.route("/api/v1/user/register", methods=["POST"])
def register():
    """JSON injection — echoes raw body (debug info exposure)."""
    raw = request.get_data(as_text=True)
    data = request.get_json(silent=True) or {}
    # INTENTIONALLY VULNERABLE — return raw body + parsed data + debug info
    return jsonify({
        "received_raw": raw[:500],
        "parsed": data,
        "headers": dict(request.headers),
        "warning": "JSON injection — server leaks raw body + headers",
    })


@app.route("/api/v1/books/sensitive", methods=["GET"])
def sensitive_books():
    """Sensitive data exposure — returns books with internal pricing field."""
    return jsonify({
        "books": [
            {**b, "internal_cost": 4.99, "internal_sku": f"SKU-{b['id']}"}
            for b in BOOKS
        ]
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
