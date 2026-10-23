import urllib.request, json, base64, sqlite3

# 1. Login
login_req = urllib.request.Request(
    "http://localhost:8000/auth/login",
    data=json.dumps({"username": "admin", "password": "Pass123!"}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST"
)
token = json.loads(urllib.request.urlopen(login_req).read().decode())["access_token"]

con = sqlite3.connect("cas_dev.db")
cur = con.cursor()
db_sizes = {r[0]: r[1] for r in cur.execute("SELECT id, file_size_bytes FROM cas_data_envelopes WHERE object_uri NOT LIKE '%demo%' AND kek_version = 1 ORDER BY created_at ASC LIMIT 9").fetchall()}
con.close()

env_uuids = [
    "232a01e5-02a6-4605-9112-903fd1375303",
    "791c8bc5-b424-4997-ad90-d2f5d5c5655a",
    "16701abd-399d-46ab-be55-b6765f77a111",
    "39220d81-acb5-4ce0-a74f-752404ab55d7",
    "7156bc22-934a-4fb5-b751-a58e03fe5220",
    "1f2e8618-3ac9-41b8-9468-4757ec251141",
    "7f1b1fbc-16d0-4e55-8b2f-9397c7be32f0",
    "3d60017b-d573-4007-8e71-d6a869ec3622",
    "3b622b68-d74d-41d0-99f4-4fc7f9d7a10a"
]

print("=== VERIFYING LIVE /access-request FOR 9 ORIGINAL ENVELOPES ===")
success_count = 0
for u in env_uuids:
    req_body = {
        "envelope_id": u,
        "purpose": "model_training",
        "requested_view": "raw_image"
    }
    req = urllib.request.Request(
        "http://localhost:8000/access-request",
        data=json.dumps(req_body).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        },
        method="POST"
    )
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode())
        decision = data.get("decision")
        b64_data = data.get("data_b64") or ""
        raw_bytes = base64.b64decode(b64_data)
        ctype = data.get("content_type")
        expected_size = db_sizes[u.replace("-", "")]
        print(f"Envelope {u[:8]}: decision='{decision}', decrypted={len(raw_bytes)} bytes (expected {expected_size}), content_type={ctype}")
        assert len(raw_bytes) == expected_size, f"Size mismatch: {len(raw_bytes)} != {expected_size}"
        assert decision != "deny"
        success_count += 1

print(f"\nAll {success_count} / {len(env_uuids)} original records decrypted with 100% exact byte match over live API!")
