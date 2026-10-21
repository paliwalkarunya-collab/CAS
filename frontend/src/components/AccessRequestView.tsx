import React, { useEffect, useState } from 'react'
import type { AccessDecisionResponse, UserRole, MLJob } from '../types'
import { requestAccess, listMLJobs } from '../api'
import { KeyRound, CheckCircle2, XCircle, Eye, Binary, Info, Sparkles } from 'lucide-react'

interface AccessRequestViewProps {
  currentRole: UserRole
  initialEnvelopeId?: string
}

export const AccessRequestView: React.FC<AccessRequestViewProps> = ({ currentRole, initialEnvelopeId = '' }) => {
  const [envelopeId, setEnvelopeId] = useState(initialEnvelopeId)

  const getDefaultPurpose = (role: UserRole) => {
    switch (role) {
      case 'admin':
        return 'administrative_access'
      case 'trainer':
        return 'model_training'
      case 'researcher':
        return 'research'
      case 'auditor':
      case 'uploader':
      default:
        return 'metadata_verification'
    }
  }

  const getDefaultView = (role: UserRole): 'feature_only' | 'masked_image' | 'raw_image' | 'metadata_only' => {
    switch (role) {
      case 'admin':
        return 'raw_image'
      case 'trainer':
        return 'raw_image'
      case 'researcher':
        return 'raw_image'
      case 'auditor':
      case 'uploader':
      default:
        return 'metadata_only'
    }
  }

  const [purpose, setPurpose] = useState(() => getDefaultPurpose(currentRole))
  const [requestedView, setRequestedView] = useState<'feature_only' | 'masked_image' | 'raw_image' | 'metadata_only'>(
    () => getDefaultView(currentRole)
  )
  const [jobId, setJobId] = useState('')
  const [jobs, setJobs] = useState<MLJob[]>([])
  const [submitting, setSubmitting] = useState(false)
  const [decision, setDecision] = useState<AccessDecisionResponse | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    listMLJobs()
      .then((data) => setJobs(data || []))
      .catch(() => setJobs([]))
  }, [])

  useEffect(() => {
    if (initialEnvelopeId) {
      setEnvelopeId(initialEnvelopeId)
    }
  }, [initialEnvelopeId])

  useEffect(() => {
    setPurpose(getDefaultPurpose(currentRole))
    setRequestedView(getDefaultView(currentRole))
    setError(null)
    setDecision(null)
  }, [currentRole])

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
    <div className="app-container fade-in">
      <div style={{ marginBottom: '28px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
          <span className="section-label">ABAC POLICY ENFORCEMENT</span>
        </div>
        <h1 className="page-title">Context-Aware Access &amp; Data Minimization</h1>
        <p className="page-desc">
          Decisions are governed by Open Policy Agent (OPA) evaluations. CAS-SE automatically returns the <strong>most minimized data view</strong> (e.g. 64-dim CNN embeddings or masked images) rather than exposing raw plaintext.
        </p>
      </div>

      {/* Role Policy Guidance Note */}
      <div
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          gap: '12px',
          padding: '14px 18px',
          background: currentRole === 'admin' ? 'rgba(59, 130, 246, 0.08)' : 'var(--bg-card)',
          border: `1px solid ${currentRole === 'admin' ? 'rgba(59, 130, 246, 0.3)' : 'var(--border-inner)'}`,
          borderRadius: '10px',
          marginBottom: '22px',
          fontSize: '13px',
          color: 'var(--text-main)',
          lineHeight: '1.5',
        }}
      >
        {currentRole === 'admin' ? (
          <Sparkles size={20} color="var(--primary)" style={{ flexShrink: 0, marginTop: '2px' }} />
        ) : (
          <Info size={18} color="var(--primary)" style={{ flexShrink: 0, marginTop: '2px' }} />
        )}
        <div>
          {currentRole === 'admin' && (
            <span>
              <strong style={{ color: 'var(--primary)', letterSpacing: '0.02em' }}>ADMIN SUPERUSER ACTIVE:</strong> You have comprehensive authority across all roles (auditor, trainer, researcher, uploader). You can request any data view (<code>raw_image</code>, <code>masked_image</code>, <code>feature_only</code>, <code>metadata_only</code>) with full override access. No job ID required.
            </span>
          )}
          {currentRole === 'trainer' && (
            <span>
              <strong style={{ color: '#fff' }}>TRAINER ACCESS POLICY:</strong> Trainers have full authority to retrieve visual images (<code>raw_image</code> for full-precision decrypted pixels, <code>masked_image</code> for de-identified inspection) as well as <code>feature_only</code> embeddings. Scoped ML Job ID is optional.
            </span>
          )}
          {currentRole === 'researcher' && (
            <span>
              <strong style={{ color: '#fff' }}>RESEARCHER POLICY:</strong> Researchers can request <code>raw_image</code> or <code>feature_only</code> with an approved research Job ID, or <code>masked_image</code> for dataset debugging.
            </span>
          )}
          {['uploader', 'auditor'].includes(currentRole) && (
            <span>
              <strong style={{ color: '#fff' }}>{currentRole.toUpperCase()} POLICY:</strong>{' '}
              {currentRole === 'uploader'
                ? 'Uploaders can inspect metadata for envelopes they uploaded.'
                : 'Auditors can inspect metadata for audit verification.'}
            </span>
          )}
        </div>
      </div>

      {/* Access Request Form */}
      <div className="double-bezel" style={{ marginBottom: '28px' }}>
        <div className="double-bezel-inner">
          <form onSubmit={handleSubmit}>
            <div style={{ marginBottom: '18px' }}>
              <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px', fontFamily: 'var(--font-mono)' }}>
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
                <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px', fontFamily: 'var(--font-mono)' }}>
                  DECLARED PURPOSE SPECIFICATION
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
                <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px', fontFamily: 'var(--font-mono)' }}>
                  REQUESTED DATA VIEW
                </label>
                <select
                  className="select-field"
                  value={requestedView}
                  onChange={(e) => setRequestedView(e.target.value as any)}
                >
                  <option value="raw_image">raw_image (Visual Image — Full Decrypted Precision Pixels)</option>
                  <option value="masked_image">masked_image (Visual Image — Obfuscated Low-Res Pixels)</option>
                  <option value="feature_only">feature_only (64-dim CNN Embedding — Minimization)</option>
                  <option value="metadata_only">metadata_only (Header details only)</option>
                </select>
              </div>
            </div>

            <div style={{ marginBottom: '22px' }}>
              <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px', fontFamily: 'var(--font-mono)' }}>
                SCOPED ML JOB ID (OPTIONAL / SELECT ACTIVE JOB)
              </label>
              {jobs.length > 0 && (
                <div style={{ marginBottom: '8px' }}>
                  <select
                    className="select-field"
                    style={{ fontSize: '12px' }}
                    onChange={(e) => setJobId(e.target.value)}
                    value={jobId}
                  >
                    <option value="">-- Or choose from existing jobs --</option>
                    {jobs.map((j) => (
                      <option key={j.job_id} value={j.job_id}>
                        {j.purpose} ({j.status.toUpperCase()} - {j.job_id.slice(0, 8)}...)
                      </option>
                    ))}
                  </select>
                </div>
              )}
              <input
                type="text"
                className="input-field"
                value={jobId}
                onChange={(e) => setJobId(e.target.value)}
                placeholder="Leave blank, or select/paste job identifier"
              />
            </div>

            <button type="submit" className="btn-primary" disabled={submitting} style={{ width: '100%', justifyContent: 'center' }}>
              <KeyRound size={15} />
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
            background: 'var(--danger-bg)',
            border: '1px solid var(--danger-border)',
            borderRadius: '10px',
            color: '#f87171',
            fontSize: '13.5px',
            marginBottom: '24px',
          }}
        >
          <XCircle size={20} style={{ flexShrink: 0 }} />
          <div>
            <div style={{ fontWeight: 700 }}>Access Denied by Policy (Fail-Closed)</div>
            <div style={{ fontSize: '12px', marginTop: '3px', color: 'var(--text-muted)' }}>{error}</div>
          </div>
        </div>
      )}

      {/* Decision Output Card */}
      {decision && (() => {
        const isAllowed = decision.decision !== 'deny' && decision.decision !== 'denied'
        const activeView = decision.allowed_view || decision.permitted_view || decision.decision
        const imageB64 = decision.data_b64 || decision.data?.masked_image_b64 || decision.data?.raw_payload_b64
        const hasImageData = Boolean(imageB64)

        return (
          <div className="double-bezel">
            <div
              className="double-bezel-inner"
              style={{
                borderLeft: `4px solid ${isAllowed ? 'var(--success)' : 'var(--danger)'}`,
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div
                    style={{
                      width: '40px',
                      height: '40px',
                      borderRadius: '10px',
                      background: isAllowed ? 'var(--success-bg)' : 'var(--danger-bg)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      color: isAllowed ? 'var(--success)' : 'var(--danger)',
                    }}
                  >
                    {isAllowed ? <CheckCircle2 size={22} /> : <XCircle size={22} />}
                  </div>
                  <div>
                    <div style={{ fontSize: '16px', fontWeight: 800, color: '#fff' }}>
                      Access Decision: {isAllowed ? 'ACCESS GRANTED' : 'ACCESS DENIED'}
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      Released Representation: <strong style={{ color: isAllowed ? 'var(--success)' : 'var(--danger)' }}>{activeView.toUpperCase()}</strong>
                    </div>
                  </div>
                </div>

                <span className={`decision-pill ${isAllowed ? 'allow' : 'deny'}`}>
                  {isAllowed ? activeView.toUpperCase() : 'DENIED'}
                </span>
              </div>

              <div style={{ padding: '12px 16px', background: 'var(--bg-canvas)', borderRadius: '8px', border: '1px solid var(--border-inner)', marginBottom: '20px', fontSize: '13px' }}>
                <span style={{ color: 'var(--text-dim)', fontWeight: 600, fontFamily: 'var(--font-mono)', fontSize: '11px' }}>POLICY REASON: </span>
                <span style={{ color: '#fff' }}>{decision.reason}</span>
              </div>

              {/* Released Data Viewer */}
              {isAllowed && (
                <div>
                  <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '12px' }}>
                    RELEASED DATA REPRESENTATION:
                  </div>

                  {/* Render Visual Image */}
                  {hasImageData && (
                    <div style={{ background: 'var(--bg-canvas)', border: '1px solid var(--border-inner)', borderRadius: '10px', padding: '18px', textAlign: 'center', marginBottom: '16px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', marginBottom: '14px', color: activeView === 'raw_image' ? 'var(--success)' : 'var(--warning)', fontSize: '13px', fontWeight: 600 }}>
                        <Eye size={16} />
                        <span>
                          {activeView === 'raw_image'
                            ? 'Decrypted Raw Image (Full Precision Pixels)'
                            : 'Masked / Obfuscated Image (Low-Resolution / Blurred Pixels)'}
                        </span>
                      </div>
                      <img
                        src={`data:image/png;base64,${imageB64}`}
                        alt={activeView}
                        style={{ maxWidth: '100%', maxHeight: '340px', borderRadius: '8px', border: '1px solid var(--border-outer)', boxShadow: '0 4px 20px rgba(0,0,0,0.5)' }}
                      />
                    </div>
                  )}

                  {/* Render Feature Vector */}
                  {activeView === 'feature_only' && (
                    <div style={{ background: 'var(--bg-canvas)', border: '1px solid var(--border-inner)', borderRadius: '10px', padding: '16px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px', color: 'var(--primary)', fontSize: '13px', fontWeight: 600 }}>
                        <Binary size={16} />
                        <span>Minimized 64-Dimensional CNN Feature Vector</span>
                      </div>
                      <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '12px' }}>
                        Raw pixels are withheld per minimization policy. The embedding is released for model training. To inspect visual pixels, request <strong>raw_image</strong> or <strong>masked_image</strong>:
                      </p>
                      <div style={{ display: 'flex', gap: '10px', marginBottom: '14px', flexWrap: 'wrap' }}>
                        <button
                          type="button"
                          className="btn-primary"
                          style={{ fontSize: '12px', padding: '6px 12px' }}
                          onClick={async () => {
                            setRequestedView('raw_image')
                            setSubmitting(true)
                            try {
                              const res = await requestAccess({
                                envelope_id: envelopeId.trim(),
                                purpose: purpose.trim(),
                                requested_view: 'raw_image',
                                job_id: jobId.trim() || undefined,
                              })
                              setDecision(res)
                            } catch (err: any) {
                              setError(err.message)
                            } finally {
                              setSubmitting(false)
                            }
                          }}
                        >
                          <Eye size={14} />
                          <span>Retrieve Full Image (raw_image)</span>
                        </button>
                        <button
                          type="button"
                          className="btn-secondary"
                          style={{ fontSize: '12px', padding: '6px 12px' }}
                          onClick={async () => {
                            setRequestedView('masked_image')
                            setSubmitting(true)
                            try {
                              const res = await requestAccess({
                                envelope_id: envelopeId.trim(),
                                purpose: purpose.trim(),
                                requested_view: 'masked_image',
                                job_id: jobId.trim() || undefined,
                              })
                              setDecision(res)
                            } catch (err: any) {
                              setError(err.message)
                            } finally {
                              setSubmitting(false)
                            }
                          }}
                        >
                          <Eye size={14} />
                          <span>Retrieve Masked Image (masked_image)</span>
                        </button>
                      </div>
                      {decision.data?.feature_vector ? (
                        <pre style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', overflowX: 'auto', maxHeight: '130px', lineHeight: 1.6 }}>
                          {JSON.stringify(decision.data.feature_vector.slice(0, 16), null, 2)}
                          {'\n// ... 48 additional vector dimensions withheld from preview'}
                        </pre>
                      ) : (
                        <div style={{ fontSize: '11.5px', fontFamily: 'var(--font-mono)', color: 'var(--success)' }}>
                          ✓ Feature extraction access authorized for active ML pipeline.
                        </div>
                      )}
                    </div>
                  )}

                  {/* Metadata Only Notification */}
                  {activeView === 'metadata_only' && (
                    <div style={{ background: 'var(--bg-canvas)', border: '1px solid var(--border-inner)', borderRadius: '10px', padding: '16px', display: 'flex', alignItems: 'center', gap: '10px', color: 'var(--text-main)', fontSize: '13px' }}>
                      <Info size={18} color="var(--primary)" />
                      <span>Metadata access approved. Envelope payload is preserved encrypted in storage.</span>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )
      })()}
    </div>
  )
}
