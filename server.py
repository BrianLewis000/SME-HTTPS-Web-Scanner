"""
Local backend for the SME Header Auditor extension.

Run this alongside the browser extension:
    pip install flask flask-cors --break-system-packages
    python server.py

The extension posts to http://localhost:5000. This writes into the same
SQLite schema you're already using for the dataset, so records added via
the extension land in the same table as your manually-inserted ones.

IMPORTANT: change DB_PATH below to point at your actual .db file.

SCORING METHODOLOGY (kept here for reference so any batch-scanning script
you write later stays consistent with the extension's popup.js):
Severity-tiered weights, sum to 1.0:
    Content-Security-Policy      0.25
    Strict-Transport-Security    0.20
    X-Frame-Options              0.15
    Referrer-Policy              0.15
    Permissions-Policy           0.15
    X-Content-Type-Options       0.10

Quality-graded credit per header (not just presence):
    pass (well-configured)       full weight    x1.0
    weak (present, misconfigured) half weight   x0.5
    fail (absent)                 no weight     x0.0

score = sum(weight_i * credit_i) for i in the 6 headers
Tiers: A >= 0.90, B >= 0.75, C >= 0.60, D >= 0.40, F < 0.40
"""
HEADER_WEIGHTS = {
    "content-security-policy": 0.25,
    "strict-transport-security": 0.20,
    "x-frame-options": 0.15,
    "referrer-policy": 0.15,
    "permissions-policy": 0.15,
    "x-content-type-options": 0.10,
}
QUALITY_CREDIT = {"pass": 1.0, "weak": 0.5, "fail": 0.0}


import sqlite3
from datetime import date

from flask import Flask, request, jsonify
from flask_cors import CORS

DB_PATH = "sme_dataset.db"  # <-- point this at your existing database file

app = Flask(__name__)
CORS(app)  # allows the chrome-extension:// origin to call this backend


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


HEADER_COLUMNS = ["csp", "hsts", "xfo", "referrer_policy", "permissions_policy", "xcto"]

# Extra columns beyond the original schema, added incrementally as the tool
# grew. Listed here (name -> SQL type) so both CREATE TABLE and the
# migration loop in init_db() stay in sync with a single source of truth.
EXTRA_COLUMNS = {"established_year": "INTEGER", "score": "REAL", "tier": "TEXT"}
for col in HEADER_COLUMNS:
    EXTRA_COLUMNS[f"{col}_status"] = "TEXT"
    EXTRA_COLUMNS[f"{col}_detail"] = "TEXT"
EXTRA_COLUMNS.update({
    "cookies_total": "INTEGER",
    "cookies_secure": "INTEGER",
    "cookies_httponly": "INTEGER",
    "cookies_samesite": "INTEGER",
    "server_header": "TEXT",
    "x_powered_by": "TEXT",
})


def init_db():
    conn = get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            business_name TEXT,
            url TEXT UNIQUE NOT NULL,
            sector TEXT,
            category TEXT,
            source TEXT,
            date_added TEXT,
            notes TEXT
        )
        """
    )
    # Migration for a pre-existing sites table (created before these columns
    # existed) - CREATE TABLE IF NOT EXISTS above won't add columns to a
    # table that's already there, so add anything missing explicitly.
    existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(sites)")}
    for col_name, col_type in EXTRA_COLUMNS.items():
        if col_name not in existing_cols:
            conn.execute(f"ALTER TABLE sites ADD COLUMN {col_name} {col_type}")
    conn.commit()
    conn.close()


@app.route("/check_duplicate", methods=["GET"])
def check_duplicate():
    url = request.args.get("url", "")
    conn = get_conn()
    row = conn.execute("SELECT 1 FROM sites WHERE url = ?", (url,)).fetchone()
    conn.close()
    return jsonify({"exists": row is not None})


@app.route("/add_site", methods=["POST"])
def add_site():
    data = request.get_json(force=True)
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"status": "error", "message": "missing url"}), 400

    established_year = data.get("established_year")
    current_year = date.today().year
    try:
        established_year = int(established_year)
        valid_year = 1900 <= established_year <= current_year
    except (TypeError, ValueError):
        valid_year = False

    if not valid_year:
        return jsonify({"status": "error", "message": "missing or invalid established_year"}), 400

    if data.get("score") is None or data.get("tier") is None:
        return jsonify({
            "status": "error",
            "message": "missing header scan data (score/tier) - reload the tab in the extension before saving",
        }), 400

    columns = [
        "business_name", "url", "sector", "category", "established_year",
        "score", "tier",
    ]
    for col in HEADER_COLUMNS:
        columns += [f"{col}_status", f"{col}_detail"]
    columns += [
        "cookies_total", "cookies_secure", "cookies_httponly", "cookies_samesite",
        "server_header", "x_powered_by", "source", "date_added", "notes",
    ]

    values = {
        "business_name": data.get("business_name", ""),
        "url": url,
        "sector": data.get("sector", ""),
        "category": data.get("category", ""),
        "established_year": established_year,
        "score": data.get("score"),
        "tier": data.get("tier"),
        "cookies_total": data.get("cookies_total"),
        "cookies_secure": data.get("cookies_secure"),
        "cookies_httponly": data.get("cookies_httponly"),
        "cookies_samesite": data.get("cookies_samesite"),
        "server_header": data.get("server_header"),
        "x_powered_by": data.get("x_powered_by"),
        "source": "extension",
        "date_added": date.today().isoformat(),
        "notes": data.get("notes", ""),
    }
    for col in HEADER_COLUMNS:
        values[f"{col}_status"] = data.get(f"{col}_status")
        values[f"{col}_detail"] = data.get(f"{col}_detail")

    placeholders = ", ".join("?" for _ in columns)
    column_list = ", ".join(columns)

    conn = get_conn()
    try:
        conn.execute(
            f"INSERT INTO sites ({column_list}) VALUES ({placeholders})",
            tuple(values[c] for c in columns),
        )
        conn.commit()
        status = "added"
    except sqlite3.IntegrityError:
        status = "duplicate"
    finally:
        conn.close()

    return jsonify({"status": status})


if __name__ == "__main__":
    init_db()
    print(f"Using database: {DB_PATH}")
    app.run(port=5000, debug=True)
