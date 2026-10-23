import sqlite3
import os
import sys
import base64
sys.path.insert(0, "backend")
from app.services.crypto import unwrap_dek

val = None
with open(".env.example") as f:
    for line in f:
        if line.startswith("CAS_KEK_V1="):
            val = line.strip().split("=", 1)[1]

if val:
    kek = base64.b64decode(val)
    con = sqlite3.connect("cas_dev.db.bak")
    rows = con.cursor().execute("SELECT id, wrapped_dek FROM cas_data_envelopes WHERE id LIKE '8a5e%'").fetchall()
    con.close()
    for env_id, w in rows:
        try:
            unwrap_dek(w, kek)
            print("8a5e matched .env.example CAS_KEK_V1!")
        except Exception as e:
            print(f"8a5e did not match .env.example: {e}")
