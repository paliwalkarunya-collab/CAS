import sqlite3, os, sys, base64, uuid
sys.path.insert(0, "backend")
from app.services.crypto import unwrap_dek, decrypt_payload, build_aad
from app.adapters.storage import LocalFileAdapter
from app.core.config import get_settings

settings = get_settings()
storage = LocalFileAdapter(settings.local_storage_path)

kek_v1_b64 = None
with open(".env") as f:
    for line in f:
        if line.startswith("CAS_KEK_V1="):
            kek_v1_b64 = line.strip().split("=", 1)[1]

kek_v1 = base64.b64decode(kek_v1_b64)

con = sqlite3.connect("cas_dev.db")
rows = con.cursor().execute("SELECT id, object_uri, nonce_hex, wrapped_dek, sensitivity_label, encryption_version FROM cas_data_envelopes WHERE object_uri NOT LIKE '%demo%' AND kek_version = 1").fetchall()
con.close()

print(f"Checking {len(rows)} envelopes from cas_dev.db with kek_version = 1:")
decrypted_count = 0
for env_id, obj_uri, nonce_hex, w_dek, sens_label, enc_ver in rows:
    standard_uuid_str = str(uuid.UUID(hex=env_id)) if len(env_id) == 32 else str(uuid.UUID(env_id))
    try:
        dek = unwrap_dek(w_dek, kek_v1)
        ciphertext = storage.get_object(obj_uri)
        aad = build_aad(standard_uuid_str, None, sens_label, enc_ver)
        pt = decrypt_payload(ciphertext, bytes.fromhex(nonce_hex), dek, aad)
        decrypted_count += 1
        print(f"  [DECRYPTED] {env_id[:8]} (UUID: {standard_uuid_str}) -> {len(pt)} bytes plaintext")
    except Exception as e:
        print(f"  [FAILED] {env_id[:8]}: {e}")

print(f"\nSummary: {decrypted_count} / {len(rows)} envelopes decrypted successfully with CAS_KEK_V1 in cas_dev.db!")
