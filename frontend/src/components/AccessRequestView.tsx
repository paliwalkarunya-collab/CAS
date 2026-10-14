import React, { useState } from 'react'
import type { AccessDecisionResponse, UserRole } from '../types'
import { requestAccess } from '../api'
import { KeyRound, CheckCircle2, XCircle, Eye, Binary } from 'lucide-react'

interface AccessRequestViewProps {
  currentRole: UserRole
  initialEnvelopeId?: string
}

export const AccessRequestView: React.FC<AccessRequestViewProps> = ({ currentRole, initialEnvelopeId = '' }) => {
  const [envelopeId, setEnvelopeId] = useState(initialEnvelopeId)
  const [purpose, setPurpose] = useState('Train classification model on scoped dataset')
  const [requestedView, setRequestedView] = useState<'feature_only' | 'masked_image' | 'raw_image' | 'metadata_only'>(
    currentRole === 'trainer' ? 'feature_only' : 'raw_image'
  )
  const [jobId, setJobId] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [decision, setDecision] = useState<AccessDecisionResponse | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!envelopeId.trim()) return

    setSubmitting(true)
    setError(null)
    setDecision(null)

    try {
      const res = await requestAccess({
        envelope_id: envelopeId.trim(),
        purpose: purpose.trim(),
        requested_view: requestedView,
        job_id: jobId.trim() || undefined,
      })
      setDecision(res)
    } catch (err: any) {
      setError(err.message || 'Access request rejected by policy')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div style={{ maxWidth: '960px', margin: '0 auto', padding: '32px 24px' }}>
      <h1 className="page-title">Context-Aware Access &amp; Data Minimization</h1>
      <p className="page-desc">
        Access decisions pass through Open Policy Agent (OPA) ABAC evaluation. Based on role, purpose, job state, and policy,
        CAS-SE returns the <strong>most minimized data view</strong> (e.g. CNN feature vector) rather than exposing raw pixels.
      </p>

      {/* Access Request Form */}
      <div className="double-bezel" style={{ marginBottom: '28px' }}>
        <div className="double-bezel-inner">
          <form onSubmit={handleSubmit}>
            <div style={{ marginBottom: '18px' }}>
              <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px' }}>
                TARGET ENVELOPE ID (UUID)
              </label>
              <input
                type="text"
                className="input-field"
                value={envelopeId}
                onChange={(e) => setEnvelopeId(e.target.value)}
                placeholder="e.g. 550e8400-e29b-41d4-a716-446655440000"
                required
              />
            </div>

            <div className="grid-2" style={{ marginBottom: '18px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px' }}>
                  PURPOSE SPECIFICATION
                </label>
                <input
                  type="text"
                  className="input-field"
                  value={purpose}
                  onChange={(e) => setPurpose(e.target.value)}
                  placeholder="e.g. Train classification model"
                  required
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px' }}>
                  REQUESTED DATA VIEW
                </label>
                <select
                  className="select-field"
                  value={requestedView}
                  onChange={(e) => setRequestedView(e.target.value as any)}
                >
                  <option value="feature_only">feature_only (64-dim CNN Embedding — Minimization)</option>
                  <option value="masked_image">masked_image (Obfuscated Pixel Representation)</option>
                  <option value="raw_image">raw_image (Unmodified Image — Restricted)</option>
                  <option value="metadata_only">metadata_only (Header details only)</option>
                </select>
              </div>
            </div>

            <div style={{ marginBottom: '20px' }}>
              <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px' }}>
                SCOPED ML JOB ID (OPTIONAL / REQUIRED FOR TRAINERS)
              </label>
              <input
                type="text"
                className="input-field"
                value={jobId}
                onChange={(e) => setJobId(e.target.value)}
                placeholder="Leave blank or paste active approved Job ID"
              />
            </div>

            <button type="submit" className="btn-primary" disabled={submitting} style={{ width: '100%', justifyContent: 'center' }}>
              <KeyRound size={16} />
              <span>{submitting ? 'Evaluating OPA Policy...' : 'Submit Access Request for Policy Evaluation'}</span>
            </button>
          </form>
        </div>
      </div>

      {error && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            padding: '16px 20px',
            background: 'rgba(244, 63, 94, 0.12)',
            border: '1px solid rgba(244, 63, 94, 0.3)',
            borderRadius: '8px',
            color: '#fb7185',
            fontSize: '14px',
            marginBottom: '24px',
          }}
        >
          <XCircle size={20} style={{ flexShrink: 0 }} />
          <div>
            <div style={{ fontWeight: 700 }}>Access Denied by Policy (Fail-Closed)</div>
            <div style={{ fontSize: '12px', marginTop: '4px' }}>{error}</div>
          </div>
        </div>
      )}

      {/* Decision Output Card */}
      {decision && (
        <div className="double-bezel">
          <div
            className="double-bezel-inner"
            style={{
              borderLeft: decision.decision === 'allow' ? '4px solid #10b981' : '4px solid #f43f5e',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                {decision.decision === 'allow' ? (
                  <CheckCircle2 size={24} color="#34d399" />
                ) : (
                  <XCircle size={24} color="#fb7185" />
                )}
                <div>
                  <div style={{ fontSize: '16px', fontWeight: 800, color: '#fff' }}>
                    Access Decision: {decision.decision.toUpperCase()}
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    Permitted View: <strong>{decision.permitted_view || 'None'}</strong>
                  </div>
                </div>
              </div>

              <span className={`decision-pill ${decision.decision}`}>{decision.decision}</span>
            </div>

            <div style={{ padding: '12px 14px', background: 'rgba(0,0,0,0.3)', borderRadius: '6px', marginBottom: '18px', fontSize: '13px' }}>
              <span style={{ color: 'var(--text-dim)', fontWeight: 600 }}>POLICY REASON: </span>
              <span style={{ color: '#fff' }}>{decision.reason}</span>
            </div>

            {/* Released Data Viewer */}
            {decision.data && (
              <div>
                <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '8px' }}>
                  RELEASED DATA PAYLOAD:
                </div>

                {decision.data.feature_vector && (
                  <div style={{ background: 'var(--bg-canvas)', border: '1px solid var(--border-inner)', borderRadius: '6px', padding: '12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px', color: '#60a5fa', fontSize: '12px', fontWeight: 600 }}>
                      <Binary size={14} />
                      <span>Minimized 64-Dimensional CNN Feature Vector (Raw pixels withheld)</span>
                    </div>
                    <pre style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', overflowX: 'auto', maxHeight: '120px' }}>
                      {JSON.stringify(decision.data.feature_vector.slice(0, 16), null, 2)}
                      {'\n// ... 48 more embedding dimensions'}
                    </pre>
                  </div>
                )}

                {decision.data.masked_image_b64 && (
                  <div style={{ background: 'var(--bg-canvas)', border: '1px solid var(--border-inner)', borderRadius: '6px', padding: '12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px', color: '#fbbf24', fontSize: '12px', fontWeight: 600 }}>
                      <Eye size={14} />
                      <span>Masked / Obfuscated Low-Resolution Representation</span>
                    </div>
                    <img
                      src={`data:image/png;base64,${decision.data.masked_image_b64}`}
                      alt="Masked view"
                      style={{ maxHeight: '150px', borderRadius: '4px' }}
                    />
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
