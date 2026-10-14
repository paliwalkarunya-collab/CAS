import React, { useEffect, useState } from 'react'
import type { AuditEvent, ChainVerifyResult, CheckpointResult, UserRole } from '../types'
import { verifyAuditChain, getAuditCheckpoint, queryAudit } from '../api'
import {
  ShieldCheck,
  Download,
  AlertTriangle,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Link as LinkIcon,
  Layers,
  FileCode2,
  Cpu,
  Lock,
} from 'lucide-react'

interface AuditVerificationViewProps {
  currentRole: UserRole
}

export const AuditVerificationView: React.FC<AuditVerificationViewProps> = ({ currentRole }) => {
  const [verifying, setVerifying] = useState(false)
  const [verifyResult, setVerifyResult] = useState<ChainVerifyResult | null>(null)
  const [checkpoint, setCheckpoint] = useState<CheckpointResult | null>(null)
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [loadingEvents, setLoadingEvents] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null)

  const isAuthorized = ['admin', 'auditor'].includes(currentRole)

  const loadChainSample = async () => {
    if (!isAuthorized) return
    setLoadingEvents(true)
    try {
      const data = await queryAudit({ limit: 12 })
      // Display chronological order (oldest to newest) for chain flow visualization
      setEvents(data.slice().reverse())
      if (data.length > 0) {
        setSelectedEvent(data[0])
      }
    } catch (err: any) {
      console.error('Failed to load audit sample for verification', err)
    } finally {
      setLoadingEvents(false)
    }
  }

  const handleRunVerification = async () => {
    setVerifying(true)
    setError(null)
    try {
      const res = await verifyAuditChain()
      setVerifyResult(res)
      await loadChainSample()
    } catch (err: any) {
      setError(err.message || 'Cryptographic chain verification failed.')
    } finally {
      setVerifying(false)
    }
  }

  const handleGenerateCheckpoint = async () => {
    setError(null)
    try {
      const cp = await getAuditCheckpoint()
      setCheckpoint(cp)
    } catch (err: any) {
      setError(err.message || 'Failed to export signed checkpoint.')
    }
  }

  const handleDownloadCheckpointJSON = () => {
    if (!checkpoint) return
    const blob = new Blob([JSON.stringify(checkpoint, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `cas_se_audit_checkpoint_${new Date().toISOString().replace(/[:.]/g, '-')}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  useEffect(() => {
    if (isAuthorized) {
      handleRunVerification()
    }
  }, [currentRole])

  if (!isAuthorized) {
    return (
      <div style={{ maxWidth: '800px', margin: '40px auto', padding: '32px 24px', textAlign: 'center' }}>
        <div className="double-bezel">
          <div className="double-bezel-inner" style={{ padding: '40px 20px' }}>
            <AlertTriangle size={40} color="#fbbf24" style={{ margin: '0 auto 16px' }} />
            <h2 style={{ fontSize: '18px', fontWeight: 800, marginBottom: '8px' }}>Auditor Privileges Required</h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '14px', lineHeight: 1.6 }}>
              The cryptographic audit-chain verifier executes strict HMAC-SHA-256 chain integrity audits over the entire database.
              Only users with <strong>AUDITOR</strong> or <strong>ADMIN</strong> roles can trigger verification or export signed checkpoints.
            </p>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '32px 24px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '28px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div
              style={{
                width: '32px',
                height: '32px',
                borderRadius: '8px',
                background: 'rgba(16, 185, 129, 0.15)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <ShieldCheck size={18} color="#34d399" />
            </div>
            <h1 className="page-title" style={{ margin: 0 }}>Audit-Chain Verification</h1>
          </div>
          <p className="page-desc" style={{ marginTop: '6px' }}>
            Cryptographic proof of non-repudiation and append-only immutability. Every access decision and administrative action is bound into an HMAC-SHA-256 hash chain.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button className="btn-secondary" onClick={handleGenerateCheckpoint}>
            <Download size={14} />
            <span>Generate Checkpoint</span>
          </button>
          <button className="btn-primary" onClick={handleRunVerification} disabled={verifying}>
            <RefreshCw size={14} className={verifying ? 'animate-spin' : ''} />
            <span>{verifying ? 'Verifying Chain...' : 'Run Full Verification'}</span>
          </button>
        </div>
      </div>

      {error && (
        <div
          style={{
            padding: '12px 16px',
            background: 'rgba(244, 63, 94, 0.15)',
            border: '1px solid rgba(244, 63, 94, 0.3)',
            borderRadius: '8px',
            color: '#fb7185',
            fontSize: '13px',
            marginBottom: '20px',
            fontWeight: 600,
          }}
        >
          {error}
        </div>
      )}

      {/* Primary Verification Result Banner */}
      {verifyResult && (
        <div className="double-bezel" style={{ marginBottom: '28px' }}>
          <div
            className="double-bezel-inner"
            style={{
              padding: '24px',
              borderLeft: `4px solid ${verifyResult.is_valid ? '#10b981' : '#f43f5e'}`,
              background: verifyResult.is_valid
                ? 'linear-gradient(90deg, rgba(16, 185, 129, 0.08) 0%, rgba(15, 23, 42, 0) 100%)'
                : 'linear-gradient(90deg, rgba(244, 63, 94, 0.08) 0%, rgba(15, 23, 42, 0) 100%)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
                {verifyResult.is_valid ? (
                  <div
                    style={{
                      width: '48px',
                      height: '48px',
                      borderRadius: '50%',
                      background: 'rgba(16, 185, 129, 0.2)',
                      border: '1px solid #10b981',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    <CheckCircle2 size={26} color="#34d399" />
                  </div>
                ) : (
                  <div
                    style={{
                      width: '48px',
                      height: '48px',
                      borderRadius: '50%',
                      background: 'rgba(244, 63, 94, 0.2)',
                      border: '1px solid #f43f5e',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    <XCircle size={26} color="#fb7185" />
                  </div>
                )}

                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <h2 style={{ fontSize: '18px', fontWeight: 800, margin: 0, color: verifyResult.is_valid ? '#34d399' : '#fb7185' }}>
                      {verifyResult.is_valid ? 'Audit Hash Chain Verified Intact' : 'CRITICAL: Audit Chain Tampering Detected'}
                    </h2>
                    <span
                      style={{
                        padding: '2px 8px',
                        borderRadius: '4px',
                        fontSize: '11px',
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                        background: verifyResult.is_valid ? 'rgba(16, 185, 129, 0.2)' : 'rgba(244, 63, 94, 0.2)',
                        color: verifyResult.is_valid ? '#34d399' : '#fb7185',
                        border: `1px solid ${verifyResult.is_valid ? 'rgba(16, 185, 129, 0.4)' : 'rgba(244, 63, 94, 0.4)'}`,
                      }}
                    >
                      {verifyResult.is_valid ? 'FAIL-CLOSED VERIFIED' : 'TAMPER ALERT'}
                    </span>
                  </div>
                  <p style={{ margin: '6px 0 0', fontSize: '13px', color: 'var(--text-muted)' }}>
                    {verifyResult.message}
                  </p>
                </div>
              </div>

              <div
                style={{
                  textAlign: 'right',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '12px',
                  color: 'var(--text-dim)',
                }}
              >
                <div>TOTAL EVENTS VERIFIED</div>
                <div style={{ fontSize: '22px', fontWeight: 800, color: 'var(--text-main)', marginTop: '2px' }}>
                  {verifyResult.events_verified}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Cryptographic Architecture Card & Signed Checkpoint Card Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '28px' }}>
        {/* Architecture Mechanics Card */}
        <div className="double-bezel">
          <div className="double-bezel-inner" style={{ padding: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
              <Lock size={16} color="#60a5fa" />
              <h3 style={{ fontSize: '14px', fontWeight: 700, margin: 0 }}>Cryptographic Chain Formula</h3>
            </div>
            <div
              style={{
                background: 'rgba(0, 0, 0, 0.35)',
                padding: '12px 14px',
                borderRadius: '6px',
                border: '1px solid var(--border-inner)',
                fontFamily: 'var(--font-mono)',
                fontSize: '12px',
                color: '#93c5fd',
                marginBottom: '12px',
              }}
            >
              H[i] = HMAC-SHA-256( K_audit, Canonical(Fields[i]) || H[i-1] )
            </div>
            <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '12px', color: 'var(--text-muted)', lineHeight: 1.6 }}>
              <li><strong>Zero Secrets in Chain:</strong> Keys, raw DEKs, and images are never stored in audit logs.</li>
              <li><strong>Canonical JSON:</strong> Deterministic key-sorting prevents formatting ambiguity attacks.</li>
              <li><strong>Strict Sequentiality:</strong> Changing a single bit in past records breaks all downstream hashes.</li>
              <li><strong>Genesis Link:</strong> The first audit event anchors to an empty predecessor string (H[0] = None).</li>
            </ul>
          </div>
        </div>

        {/* Signed Checkpoint Card */}
        <div className="double-bezel">
          <div className="double-bezel-inner" style={{ padding: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Cpu size={16} color="#a78bfa" />
                <h3 style={{ fontSize: '14px', fontWeight: 700, margin: 0 }}>WORM / External Ledger Checkpoint</h3>
              </div>
              {checkpoint && (
                <button
                  onClick={handleDownloadCheckpointJSON}
                  style={{
                    background: 'transparent',
                    border: '1px solid var(--border-inner)',
                    color: '#60a5fa',
                    padding: '3px 8px',
                    borderRadius: '4px',
                    fontSize: '11px',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                  }}
                >
                  <Download size={11} />
                  <span>Export JSON</span>
                </button>
              )}
            </div>

            {checkpoint ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)' }}>
                  <span>Total Events Sealed:</span>
                  <strong style={{ color: 'var(--text-main)' }}>{checkpoint.total_events}</strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)' }}>
                  <span>Checkpoint Timestamp:</span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-main)' }}>
                    {new Date(checkpoint.checkpoint_timestamp).toLocaleString()}
                  </span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', color: 'var(--text-muted)' }}>
                  <span>Last Event ID:</span>
                  <code style={{ fontSize: '11px', color: '#93c5fd', wordBreak: 'break-all' }}>
                    {checkpoint.last_event_id || '(Genesis state)'}
                  </code>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', color: 'var(--text-muted)' }}>
                  <span>HMAC-SHA-256 Checkpoint Signature:</span>
                  <code style={{ fontSize: '10px', color: '#34d399', wordBreak: 'break-all', background: 'rgba(0,0,0,0.3)', padding: '6px', borderRadius: '4px' }}>
                    {checkpoint.checkpoint_signature}
                  </code>
                </div>
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '24px 0', color: 'var(--text-dim)', fontSize: '13px' }}>
                No active checkpoint generated yet. Click "Generate Checkpoint" to seal the current chain state.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Sequential Hash Chain Block Visualizer */}
      <div className="double-bezel" style={{ marginBottom: '28px' }}>
        <div className="double-bezel-inner" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Layers size={18} color="#38bdf8" />
              <h2 style={{ fontSize: '16px', fontWeight: 800, margin: 0 }}>Sequential Chain Link Inspector</h2>
            </div>
            <span style={{ fontSize: '12px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
              Showing {events.length} sequential blocks
            </span>
          </div>

          {loadingEvents ? (
            <div style={{ padding: '30px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
              <RefreshCw size={20} className="animate-spin" style={{ margin: '0 auto 10px' }} />
              Loading sequential chain blocks...
            </div>
          ) : events.length === 0 ? (
            <div style={{ padding: '30px', textAlign: 'center', color: 'var(--text-dim)', fontSize: '13px' }}>
              Audit chain is currently empty. Ingest envelopes or trigger actions to build the chain.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              {events.map((ev, idx) => {
                const isSelected = selectedEvent?.event_id === ev.event_id
                return (
                  <div
                    key={ev.event_id}
                    onClick={() => setSelectedEvent(ev)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '14px',
                      padding: '12px 16px',
                      borderRadius: '8px',
                      background: isSelected ? 'rgba(56, 189, 248, 0.08)' : 'rgba(255, 255, 255, 0.02)',
                      border: isSelected ? '1px solid rgba(56, 189, 248, 0.4)' : '1px solid var(--border-inner)',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                    }}
                  >
                    {/* Block Index Badge */}
                    <div
                      style={{
                        padding: '4px 10px',
                        background: 'rgba(255, 255, 255, 0.05)',
                        border: '1px solid var(--border-inner)',
                        borderRadius: '6px',
                        fontFamily: 'var(--font-mono)',
                        fontSize: '11px',
                        fontWeight: 700,
                        color: '#38bdf8',
                        minWidth: '70px',
                        textAlign: 'center',
                      }}
                    >
                      LINK #{idx + 1}
                    </div>

                    {/* Chain Link Icon */}
                    <LinkIcon size={14} color="#64748b" />

                    {/* Event Type & Role */}
                    <div style={{ flex: '1 1 200px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontWeight: 700, fontSize: '13px', color: '#fff' }}>{ev.event_type}</span>
                        {ev.decision && (
                          <span className={`decision-pill ${ev.decision}`}>{ev.decision.toUpperCase()}</span>
                        )}
                        <span className={`badge-role ${ev.actor_role || 'auditor'}`}>
                          {ev.actor_role || 'SYSTEM'}
                        </span>
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
                        UUID: {ev.event_id.slice(0, 18)}...
                      </div>
                    </div>

                    {/* Timestamp */}
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textAlign: 'right' }}>
                      {new Date(ev.occurred_at).toLocaleTimeString()}
                    </div>

                    {/* Cryptographic Link Status */}
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px',
                        fontSize: '11px',
                        fontFamily: 'var(--font-mono)',
                        color: '#34d399',
                        fontWeight: 700,
                        background: 'rgba(16, 185, 129, 0.1)',
                        padding: '4px 8px',
                        borderRadius: '4px',
                        border: '1px solid rgba(16, 185, 129, 0.25)',
                      }}
                    >
                      <CheckCircle2 size={13} color="#34d399" />
                      <span>CRYPTOGRAPHIC LINK VALID</span>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>

      {/* Selected Event Canonical Payload Inspector */}
      {selectedEvent && (
        <div className="double-bezel">
          <div className="double-bezel-inner" style={{ padding: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
              <FileCode2 size={16} color="#38bdf8" />
              <h3 style={{ fontSize: '14px', fontWeight: 700, margin: 0 }}>
                Canonical Hash Input Inspection (Event {selectedEvent.event_id.slice(0, 8)})
              </h3>
            </div>
            <pre
              style={{
                background: '#090d16',
                padding: '14px',
                borderRadius: '6px',
                border: '1px solid var(--border-inner)',
                color: '#e2e8f0',
                fontSize: '12px',
                fontFamily: 'var(--font-mono)',
                overflowX: 'auto',
                margin: 0,
                lineHeight: 1.5,
              }}
            >
              {JSON.stringify(
                {
                  event_id: selectedEvent.event_id,
                  event_type: selectedEvent.event_type,
                  actor_id: selectedEvent.actor_id || null,
                  actor_role: selectedEvent.actor_role || null,
                  envelope_id: selectedEvent.envelope_id || null,
                  decision: selectedEvent.decision || null,
                  reason: selectedEvent.reason || null,
                  job_id: selectedEvent.job_id || null,
                  occurred_at: selectedEvent.occurred_at,
                  chain_integrity: 'TAMPER_EVIDENT_HMAC_SHA256',
                },
                null,
                2
              )}
            </pre>
          </div>
        </div>
      )}
    </div>
  )
}
