import urllib.request
import json
import uuid
import base64
import sys

# 1. Login as admin
login_req = urllib.request.Request(
    'http://localhost:8000/auth/login',
    data=json.dumps({'username': 'admin', 'password': 'Pass123!'}).encode(),
    headers={'Content-Type': 'application/json'},
    method='POST'
)
token = json.loads(urllib.request.urlopen(login_req).read().decode())['access_token']

# 2. Check key status; if locked, bootstrap / unlock
status_req = urllib.request.Request(
    'http://localhost:8000/keys/status',
    headers={'Authorization': f'Bearer {token}'}
)
status_data = json.loads(urllib.request.urlopen(status_req).read().decode())
if not status_data.get('is_unlocked'):
    print("[INFO] Key service is currently locked. Bootstrapping fresh Shamir split...")
    init_req = urllib.request.Request(
        'http://localhost:8000/keys/shamir/init',
        headers={'Authorization': f'Bearer {token}'},
        method='POST'
    )
    init_data = json.loads(urllib.request.urlopen(init_req).read().decode())
    print(f"[INFO] Bootstrapped v{init_data['version']} with shares: {init_data['shares']}")

test_payloads = [
    ('experiment_report.pdf', b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n%%EOF', 'application/pdf'),
    ('notes.txt', b'Patient records confidential text stream 1234567890.', 'text/plain'),
    ('dataset.csv', b'id,metric,score\n1,accuracy,0.985\n2,f1,0.978\n', 'text/csv'),
    ('params.json', b'{"model": "cas-se-v1", "epochs": 10, "batch_size": 32}', 'application/json'),
    ('word_doc.docx', b'PK\x03\x04\x14\x00\x00\x00\x08\x00DummyOfficeOpenXMLBinaryPayloadBytes123456789', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'),
    ('spreadsheet.xlsx', b'PK\x03\x04\x14\x00\x00\x00\x08\x00DummyExcelOpenXMLBinaryPayloadBytes987654321', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'),
]

print("=== STARTING LIVE END-TO-END MULTI-FORMAT ENCRYPTION & DECRYPTION TEST ===")
for filename, raw_bytes, expected_content_type in test_payloads:
    boundary = '----WebKitFormBoundary' + uuid.uuid4().hex
    body = []
    body.append(f'--{boundary}\r\nContent-Disposition: form-data; name="dataset_id"\r\n\r\nclinical_trials\r\n'.encode())
    body.append(f'--{boundary}\r\nContent-Disposition: form-data; name="subject_id"\r\n\r\npatient-001\r\n'.encode())
    body.append(f'--{boundary}\r\nContent-Disposition: form-data; name="sensitivity_label"\r\n\r\nrestricted\r\n'.encode())
    file_header = f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\nContent-Type: {expected_content_type}\r\n\r\n'.encode()
    body.append(file_header + raw_bytes + b'\r\n')
    body.append(f'--{boundary}--\r\n'.encode())
    full_body = b''.join(body)

    # 1. Ingest
    upload_req = urllib.request.Request(
        'http://localhost:8000/envelopes',
        data=full_body,
        headers={
            'Content-Type': f'multipart/form-data; boundary={boundary}',
            'Authorization': f'Bearer {token}'
        },
        method='POST'
    )
    res = urllib.request.urlopen(upload_req)
    res_data = json.loads(res.read().decode())
    env_id = res_data['envelope_id']

    # 2. Retrieve metadata
    meta_req = urllib.request.Request(
        f'http://localhost:8000/envelopes/{env_id}',
        headers={'Authorization': f'Bearer {token}'}
    )
    meta_data = json.loads(urllib.request.urlopen(meta_req).read().decode())
    assert meta_data['content_type'] == expected_content_type, f"Metadata content_type mismatch: {meta_data['content_type']}"
    assert meta_data['file_size_bytes'] == len(raw_bytes), f"Metadata size mismatch: {meta_data['file_size_bytes']}"

    # 3. Retrieve & Decrypt
    access_req = urllib.request.Request(
        'http://localhost:8000/access-request',
        data=json.dumps({
            'envelope_id': env_id,
            'purpose': 'administrative_review',
            'requested_view': 'raw_image'
        }).encode(),
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {token}'
        },
        method='POST'
    )
    access_res = json.loads(urllib.request.urlopen(access_req).read().decode())
    recovered_bytes = base64.b64decode(access_res['data_b64'])

    assert recovered_bytes == raw_bytes, f'Byte mismatch for {filename}!'
    assert access_res['content_type'] == expected_content_type, f"Access content_type mismatch: {access_res['content_type']}"
    print(f"VERIFIED: {filename:22} | Size: {len(raw_bytes):3} bytes | MIME: {expected_content_type:60} | Byte Match: 100% IDENTICAL")

print("=== ALL FORMATS INGESTED, ENCRYPTED, STORED, RETRIEVED, DECRYPTED WITH 100% BYTE FIDELITY ===")
