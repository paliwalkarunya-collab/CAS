import urllib.request
import json
import uuid
import base64
import sqlite3

# 1. Login as uploader
login_req = urllib.request.Request(
    "http://localhost:8000/auth/login",
    data=json.dumps({"username": "uploader", "password": "Pass123!"}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST"
)
token = json.loads(urllib.request.urlopen(login_req).read().decode())["access_token"]

# 2. Create a test payload (PDF header and random body)
test_data = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" + b"X" * 500 + b"\n%%EOF\n"
test_filename = "roundtrip_test.pdf"

boundary = "----WebKitFormBoundary" + uuid.uuid4().hex
body = []
body.append(f'--{boundary}\r\nContent-Disposition: form-data; name="dataset_id"\r\n\r\nclinical_reports\r\n'.encode())
body.append(f'--{boundary}\r\nContent-Disposition: form-data; name="subject_id"\r\n\r\nsubj-roundtrip-999\r\n'.encode())
body.append(f'--{boundary}\r\nContent-Disposition: form-data; name="sensitivity_label"\r\n\r\nrestricted\r\n'.encode())
body.append(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{test_filename}"\r\nContent-Type: application/pdf\r\n\r\n'.encode() + test_data + b"\r\n")
body.append(f"--{boundary}--\r\n".encode())
multipart_body = b"".join(body)

# 3. Upload envelope
upload_req = urllib.request.Request(
    "http://localhost:8000/envelopes",
    data=multipart_body,
    headers={
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Authorization": f"Bearer {token}"
    },
    method="POST"
)
upload_res = json.loads(urllib.request.urlopen(upload_req).read().decode())
env_id = upload_res["envelope_id"]
print(f"Uploaded successfully! Envelope ID: {env_id}")

# 4. Check database record for kek_version
con = sqlite3.connect("cas_dev.db")
row = con.execute("SELECT kek_version, file_size_bytes, content_type FROM cas_data_envelopes WHERE id = ?", (env_id.replace("-", ""),)).fetchone()
con.close()
print(f"Database envelope record: kek_version={row[0]}, size={row[1]}, content_type={row[2]}")
assert row[0] == 1, f"Expected kek_version=1, got {row[0]}"
assert row[1] == len(test_data), f"Expected size {len(test_data)}, got {row[1]}"

# 5. Access Request & Decryption as admin
admin_login = urllib.request.Request(
    "http://localhost:8000/auth/login",
    data=json.dumps({"username": "admin", "password": "Pass123!"}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST"
)
admin_token = json.loads(urllib.request.urlopen(admin_login).read().decode())["access_token"]

access_req = urllib.request.Request(
    "http://localhost:8000/access-request",
    data=json.dumps({
        "envelope_id": env_id,
        "purpose": "model_training",
        "requested_view": "raw_image"
    }).encode(),
    headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {admin_token}"
    },
    method="POST"
)
access_res = json.loads(urllib.request.urlopen(access_req).read().decode())
print(f"Access request decision: {access_res.get('decision')}")
retrieved_b64 = access_res.get("data_b64")
assert retrieved_b64 is not None, "data_b64 is missing"
retrieved_bytes = base64.b64decode(retrieved_b64)

# 6. Verify bit-for-bit roundtrip integrity
assert retrieved_bytes == test_data, "Decrypted bytes do not match original uploaded bytes!"
print(f"ROUNDTRIP VERIFICATION SUCCESS: {len(retrieved_bytes)} bytes decrypted bit-for-bit identical to uploaded payload!")
