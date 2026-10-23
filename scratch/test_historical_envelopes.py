import sqlite3
import base64
import traceback
from app.adapters.key_service import EnvVarKeyService
from app.services.crypto import unwrap_dek, decrypt_payload, build_aad
from app.core.config import get_settings
from app.adapters.storage import LocalFileAdapter

settings = get_settings()
env_key_service = EnvVarKeyService()
storage = LocalFileAdapter(settings.local_storage_path)

con = sqlite3.connect("cas_dev.db.bak")
cur = con.cursor()
rows = cur.execute("SELECT id, object_uri, nonce_hex, wrapped_dek, kek_version, sensitivity_label, ciphertext_hash FROM cas_data_envelopes").fetchall()
con.close()

print(f"=== TESTING ORIGINAL {len(rows)} ENVELOPES FROM cas_dev.db.bak ===")
env_kek_v1 = env_key_service.get_kek_by_version(1)

for row in rows[:2]:
    env_id, obj_uri, nonce_hex, wrapped_dek, kek_ver, sens_label, c_hash = row
    try:
        dek = unwrap_dek(wrapped_dek, env_kek_v1)
        print("  DEK unwrap succeeded!")
    except Exception as e:
        print(f"  [DEK UNWRAP FAILED] Envelope {env_id[:8]}: {type(e).__name__}: {e!r}")
        continue
    try:
        ciphertext = storage.get_object(obj_uri)
        print(f"  Got ciphertext of len {len(ciphertext)}")
    except Exception as e:
        print(f"  [GET OBJECT FAILED] Envelope {env_id[:8]}: {type(e).__name__}: {e!r}")
        continue
