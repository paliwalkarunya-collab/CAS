import sqlite3
import sys
sys.path.insert(0, "backend")
from app.services.crypto import unwrap_dek, decrypt_payload, build_aad
from app.adapters.storage import LocalFileAdapter
from app.core.config import get_settings

settings = get_settings()
storage = LocalFileAdapter(settings.local_storage_path)

con = sqlite3.connect("cas_dev.db.bak")
rows = con.cursor().execute("SELECT id, object_uri, nonce_hex, wrapped_dek, sensitivity_label FROM cas_data_envelopes").fetchall()
con.close()

seed_kek = b"k" * 32
matched = 0
for env_id, obj_uri, nonce_hex, w_dek, sens_label in rows:
    try:
        dek = unwrap_dek(w_dek, seed_kek)
        ciphertext = storage.get_object(obj_uri)
        aad = build_aad(env_id, None, sens_label, 1)
        pt = decrypt_payload(ciphertext, bytes.fromhex(nonce_hex), dek, aad)
        matched += 1
        print(f"Envelope {env_id[:8]} DECRYPTED with b'k'*32: {pt.decode(errors='replace')}")
    except Exception as e:
        pass

print(f"Total decrypted with seed KEK b'k'*32: {matched} / {len(rows)}")
