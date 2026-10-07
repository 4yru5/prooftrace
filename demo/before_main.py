"""InvoiceFlow — a tiny invoice service.

A deliberately vulnerable (BOLA / IDOR, CWE-639) FastAPI app used as the
ProofTrace demo target. The bug is semantic, not syntactic: the SQL is
parameterized (no SQL injection), authentication is present, yet one endpoint
returns an object by id without checking that the caller owns it.

Structured as a HackBench-style challenge: user B's invoice carries a planted
flag that a successful BOLA attack exfiltrates.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException

DB_PATH = Path(__file__).parent / "invoiceflow.db"

# Static bearer tokens -> user id. Two tenants, one invoice each.
TOKENS = {
    "tok_alice_a1": "user_A",
    "tok_bob_b2": "user_B",
}

SEED = [
    # id, owner_id, customer, amount, note (note on invoice 2 holds the flag)
    (1, "user_A", "Acme Corp", 1200, "Q3 retainer"),
    (2, "user_B", "Globex Inc", 9000, "FLAG{bola_user_b_invoice_pwned}"),
]

app = FastAPI(title="InvoiceFlow", version="1.0.0")


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    with get_db() as db:
        db.execute("DROP TABLE IF EXISTS invoices")
        db.execute(
            """
            CREATE TABLE invoices (
                id INTEGER PRIMARY KEY,
                owner_id TEXT NOT NULL,
                customer TEXT NOT NULL,
                amount INTEGER NOT NULL,
                note TEXT
            )
            """
        )
        db.executemany(
            "INSERT INTO invoices (id, owner_id, customer, amount, note) "
            "VALUES (?, ?, ?, ?, ?)",
            SEED,
        )
        db.commit()


def authenticate(authorization: str = Header(default="")) -> str:
    """Resolve a bearer token to a user id. Real authentication, on purpose."""
    token = authorization.removeprefix("Bearer ").strip()
    user = TOKENS.get(token)
    if not user:
        raise HTTPException(status_code=401, detail="invalid or missing token")
    return user


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.get("/api/invoices/{invoice_id}/secure")
def get_invoice_secure(invoice_id: int, user: str = Depends(authenticate)) -> dict:
    # SAFE endpoint, SAME shape as the vulnerable one (id path param -> DB read),
    # differing only by the ownership filter. This is the precision contrast:
    # the reachability engine must clear this path and flag only the unsafe one.
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM invoices WHERE id = :id AND owner_id = :owner",
            {"id": invoice_id, "owner": user},
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="not found")
    return dict(row)


@app.get("/api/me/invoices")
def list_my_invoices(user: str = Depends(authenticate)) -> list[dict]:
    # SAFE endpoint for contrast: results are scoped to the caller.
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM invoices WHERE owner_id = :owner",
            {"owner": user},
        ).fetchall()
    return [dict(r) for r in rows]


if __name__ == "__main__":
    import uvicorn

    init_db()
    uvicorn.run(app, host="0.0.0.0", port=8000)
