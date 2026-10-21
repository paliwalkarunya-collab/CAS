import React, { useState } from 'react'
import type { UploadResponse, UserRole } from '../types'
import { uploadEnvelope } from '../api'
import { UploadCloud, CheckCircle2, AlertCircle, Lock, ShieldAlert } from 'lucide-react'

interface UploadViewProps {
  currentRole: UserRole
}

export const UploadView: React.FC<UploadViewProps> = ({ currentRole }) => {
  const [file, setFile] = useState<File | null>(null)
  const [datasetId, setDatasetId] = useState('fashion_mnist')
  const [subjectId, setSubjectId] = useState('item-042')
  const [sensitivity, setSensitivity] = useState('restricted')
  const [uploading, setUploading] = useState(false)
  const [result, setResult] = useState<UploadResponse | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0])
      setError(null)
    }
  }

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!file) {
      setError('Please select an image file to ingest.')
      return
    }

    setUploading(true)
    setError(null)
    setResult(null)

    try {
      const res = await uploadEnvelope(file, datasetId, subjectId, sensitivity)
      setResult(res)
    } catch (err: any) {
      setError(err.message || 'Envelope upload failed')
    } finally {
      setUploading(false)
    }
  }

  return (
    <div className="app-container fade-in">
      <div style={{ marginBottom: '28px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
          <span className="section-label">ENVELOPE INGESTION</span>
        </div>
        <h1 className="page-title">Ingest Encrypted Data Envelope</h1>
        <p className="page-desc">
          Payloadds are encrypted with a fresh random 32-byte DEK (AES-256-GCM) before reaching object storage. Plaintext payloads are <strong>never stored in the database</strong>.
        </p>
      </div>

      {/* Role permission check notice */}
      {!['admin', 'uploader'].includes(currentRole) && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            padding: '12px 16px',
            background: 'var(--danger-bg)',
            border: '1px solid var(--danger-border)',
            borderRadius: '8px',
            marginBottom: '20px',
            color: '#f87171',
            fontSize: '13px',
          }}
        >
          <ShieldAlert size={18} />
          <span>Notice: Current role ({currentRole.toUpperCase()}) cannot ingest envelopes. Switch to ADMIN or UPLOADER.</span>
        </div>
      )}

      <div className="double-bezel" style={{ marginBottom: '28px' }}>
        <div className="double-bezel-inner">
          <form onSubmit={handleUpload}>
            {/* File Drop Area */}
            <div
              style={{
                border: '2px dashed var(--border-outer)',
                borderRadius: '10px',
                padding: '36px 20px',
                textAlign: 'center',
                background: 'var(--bg-canvas)',
                marginBottom: '22px',
                cursor: 'pointer',
                transition: 'border-color 0.2s ease, background 0.2s ease',
              }}
              onClick={() => document.getElementById('file-upload-input')?.click()}
            >
              <input
                id="file-upload-input"
                type="file"
                accept="image/png,image/jpeg,image/tiff"
                style={{ display: 'none' }}
                onChange={handleFileChange}
              />
              <UploadCloud size={38} color="var(--primary)" style={{ margin: '0 auto 12px' }} />
              <div style={{ fontSize: '14.5px', fontWeight: 600, color: '#fff', marginBottom: '4px' }}>
                {file ? file.name : 'Click or drop image file to encrypt & ingest'}
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-dim)' }}>
                Supported formats: PNG, JPEG, TIFF (Max size: 10 MB)
              </div>
              {file && (
                <div style={{ marginTop: '10px', fontSize: '12px', color: 'var(--primary)', fontFamily: 'var(--font-mono)' }}>
                  Selected file: {(file.size / 1024).toFixed(1)} KB
                </div>
              )}
            </div>

            {/* Metadata Fields */}
            <div className="grid-3" style={{ marginBottom: '22px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px', fontFamily: 'var(--font-mono)' }}>
                  DATASET ID (INDEXED)
                </label>
                <input
                  type="text"
                  className="input-field"
                  value={datasetId}
                  onChange={(e) => setDatasetId(e.target.value)}
                  placeholder="e.g. fashion_mnist"
                  required
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px', fontFamily: 'var(--font-mono)' }}>
                  SUBJECT ID (INDEXED)
                </label>
                <input
                  type="text"
                  className="input-field"
                  value={subjectId}
                  onChange={(e) => setSubjectId(e.target.value)}
                  placeholder="e.g. subject-042"
                  required
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px', fontFamily: 'var(--font-mono)' }}>
                  SENSITIVITY LABEL
                </label>
                <select
                  className="select-field"
                  value={sensitivity}
                  onChange={(e) => setSensitivity(e.target.value)}
                >
                  <option value="restricted">Restricted (Highest)</option>
                  <option value="confidential">Confidential</option>
                  <option value="internal">Internal</option>
                  <option value="public">Public</option>
                </select>
              </div>
            </div>

            {error && (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '12px 16px',
                  background: 'var(--danger-bg)',
                  border: '1px solid var(--danger-border)',
                  borderRadius: '8px',
                  color: '#f87171',
                  fontSize: '13px',
                  marginBottom: '20px',
                }}
              >
                <AlertCircle size={16} />
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              className="btn-primary"
              disabled={uploading || !['admin', 'uploader'].includes(currentRole)}
              style={{ width: '100%', justifyContent: 'center' }}
            >
              <Lock size={15} />
              <span>{uploading ? 'Encrypting & Uploading...' : 'Encrypt & Ingest Envelope'}</span>
            </button>
          </form>
        </div>
      </div>

      {/* Success Result Modal / Card */}
      {result && (
        <div className="double-bezel">
          <div className="double-bezel-inner" style={{ borderLeft: '4px solid var(--success)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '18px', color: '#4ade80' }}>
              <CheckCircle2 size={22} />
              <h3 style={{ fontSize: '15px', fontWeight: 700 }}>Envelope Ingested &amp; Encrypted Successfully</h3>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '13px' }}>
              <div>
                <span style={{ color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>ENVELOPE UUID: </span>
                <span style={{ color: '#fff', fontFamily: 'var(--font-mono)' }}>{result.envelope_id}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>OBJECT STORAGE URI: </span>
                <span style={{ color: 'var(--primary)', fontFamily: 'var(--font-mono)' }}>{result.object_uri}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>CIPHERTEXT SHA-256: </span>
                <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '11.5px' }}>
                  {result.ciphertext_sha256}
                </span>
              </div>
              <div style={{ display: 'flex', gap: '20px' }}>
                <div>
                  <span style={{ color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>KEK VERSION: </span>
                  <span style={{ color: '#fff', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>v{result.kek_version}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>SENSITIVITY: </span>
                  <span style={{ color: '#fbbf24', textTransform: 'uppercase', fontWeight: 700, fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                    {result.sensitivity_label}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
