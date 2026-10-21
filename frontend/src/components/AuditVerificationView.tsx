import React, { useEffect, useState } from 'react'
import type { AuditEvent, ChainVerifyResult, CheckpointResult, UserRole } from '../types'
import { verifyAuditChain, getAuditCheckpoint, queryAudit } from '../api'
import {
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
  ShieldAlert,
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
      <div className="app-container fade-in" style={{ maxWidth: '640px', margin: '40px auto', textAlign: 'center' }}>
        <div className="double-bezel">
          <div className="double-bezel-inner" style={{ padding: '48px 24px' }}>
            <div style={{ width: '48px', height: '48px', borderRadius: '12px', background: 'var(--warning-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px', color: 'var(--warning)' }}>
              <ShieldAlert size={24} />
            </div>
            <h2 style={{ fontSize: '18px', fontWeight: 800, color: '#fff', marginBottom: '8px' }}>Auditor Authorization Required</h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '13.5px', lineHeight: 1.6, maxWidth: '440px', margin: '0 auto' }}>
              The cryptographic audit-chain verifier executes strict HMAC-SHA-256 chain integrity audits over the database. Switch your active role to <strong>AUDITOR</strong> or <strong>ADMIN</strong>.
            </p>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="app-container fade-in">
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '28px', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
            <span className="section-label">CRYPTOGRAPHIC INTEGRITY</span>
          </div>
          <h1 className="page-title">Audit-Chain Verification</h1>
          <p className="page-desc">
            Cryptographic proof of non-repudiation and append-only immutability. Every access decision and administrative action is bound into an HMAC-SHA-256 hash chain.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button className="btn-secondary" onClick={handleGenerateCheckpoint}>
            <Download size={13} />
            <span>Generate Checkpoint</span>
          </button>
          <button className="btn-primary" onClick={handleRunVerification} disabled={verifying}>
            <RefreshCw size={13} className={verifying ? 'animate-spin' : ''} />
            <span>{verifying ? 'Verifying Chain...' : 'Run Full Verification'}</span>
          </button>
        </div>
      </div>

      {error && (
        <div
          style={{
            padding: '12px 16px',
            background: 'var(--danger-bg)',
            border: '1px solid var(--danger-border)',
            borderRadius: '8px',
            color: '#f87171',
            fontSize: '13px',
            marginBottom: '20px',
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <AlertTriangle size={16} />
          <span>{error}</span>
        </div>
      )}

      {/* Primary Verification Result Banner */}
      {verifyResult && (
        <div className="double-bezel" style={{ marginBottom: '28px' }}>
          <div
            className="double-bezel-inner"
            style={{
              padding: '24px',
              borderLeft: `4px solid ${verifyResult.is_valid ? 'var(--success)' : 'var(--danger)'}`,
              background: verifyResult.is_valid
                ? 'linear-gradient(90deg, rgba(34, 197, 94, 0.08) 0%, transparent 100%)'
                : 'linear-gradient(90deg, rgba(239, 68, 68, 0.08) 0%, transparent 100%)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
              <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
                <div
                  style={{
                    width: '48px',
                    height: '48px',
                    borderRadius: '12px',
                    background: verifyResult.is_valid ? 'var(--success-bg)' : 'var(--danger-bg)',
                    border: `1px solid ${verifyResult.is_valid ? 'var(--success-border)' : 'var(--danger-border)'}`,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: verifyResult.is_valid ? 'var(--success)' : 'var(--danger)',
                  }}
                >
                  {verifyResult.is_valid ? <CheckCircle2 size={26} /> : <XCircle size={26} />}
                </div>

                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <h2 style={{ fontSize: '17px', fontWeight: 800, margin: 0, color: verifyResult.is_valid ? '#4ade80' : '#f87171' }}>
                      {verifyResult.is_valid ? 'Audit Hash Chain Verified Intact' : 'CRITICAL: Audit Chain Tampering Detected'}
                    </h2>
                    <span
                      style={{
                        padding: '2px 8px',
                        borderRadius: '4px',
                        fontSize: '10.5px',
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                        background: verifyResult.is_valid ? 'var(--success-bg)' : 'var(--danger-bg)',
                        color: verifyResult.is_valid ? '#4ade80' : '#f87171',
                        border: `1px solid ${verifyResult.is_valid ? 'var(--success-border)' : 'var(--danger-border)'}`,
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
                  fontSize: '11px',
                  color: 'var(--text-dim)',
                }}
              >
                <div>TOTAL EVENTS VERIFIED</div>
                <div style={{ fontSize: '26px', fontWeight: 800, color: 'var(--text-main)', marginTop: '2px' }}>
                  {verifyResult.events_verified}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Cryptographic Architecture Card & Signed Checkpoint Card Grid */}
      <div className="grid-2" style={{ marginBottom: '28px' }}>
        {/* Architecture Mechanics Card */}
        <div className="double-bezel">
          <div className="double-bezel-inner">
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
              <Lock size={16} color="var(--primary)" />
              <h3 style={{ fontSize: '14px', fontWeight: 700, margin: 0, color: '#fff' }}>Cryptographic Chain Formula</h3>
            </div>
            <div
              style={{
                background: 'var(--bg-canvas)',
                padding: '12px 14px',
                borderRadius: '7px',
                border: '1px solid var(--border-inner)',
                fontFamily: 'var(--font-mono)',
                fontSize: '12px',
                color: 'var(--primary)',
                marginBottom: '14px',
              }}
            >
              H[i] = HMAC-SHA-256( K_audit, Canonical(Fields[i]) || H[i-1] )
            </div>
            <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '12px', color: 'var(--text-muted)', lineHeight: 1.7 }}>
              <li><strong>Zero Secrets in Chain:</strong> Keys, raw DEKs, and images are never logged.</li>
              <li><strong>Canonical JSON:</strong> Deterministic key-sorting prevents formatting ambiguity attacks.</li>
              <li><strong>Strict Sequentiality:</strong> Altering any historical bit invalidates all subsequent hashes.</li>
              <li><strong>Genesis Anchor:</strong> The initial audit event links to an empty predecessor anchor.</li>
            </ul>
          </div>
        </div>

        {/* Signed Checkpoint Card */}
        <div className="double-bezel">
          <div className="double-bezel-inner">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Cpu size={16} color="var(--primary)" />
                <h3 style={{ fontSize: '14px', fontWeight: 700, margin: 0, color: '#fff' }}>External Ledger Checkpoint</h3>
              </div>
              {checkpoint && (
                <button
                  className="btn-secondary"
                  onClick={handleDownloadCheckpointJSON}
                  style={{ padding: '3px 8px', fontSize: '11px' }}
                >
                  <Download size={11} />
                  <span>Export JSON</span>
                </button>
              )}
            </div>

            {checkpoint ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)' }}>
                  <span>Total Events Sealed:</span>
                  <strong style={{ color: 'var(--text-main)', fontFamily: 'var(--font-mono)' }}>{checkpoint.total_events}</strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)' }}>
                  <span>Checkpoint Timestamp:</span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-main)' }}>
                    {new Date(checkpoint.checkpoint_timestamp).toLocaleString()}
                  </span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', color: 'var(--text-muted)' }}>
                  <span>Last Sealed Event ID:</span>
                  <code style={{ fontSize: '11px', color: 'var(--primary)', wordBreak: 'break-all', fontFamily: 'var(--font-mono)' }}>
                    {checkpoint.last_event_id || '(Genesis state)'}
                  </code>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', color: 'var(--text-muted)' }}>
                  <span>HMAC-SHA-256 Checkpoint Signature:</span>
                  <code style={{ fontSize: '10.5px', color: '#4ade80', wordBreak: 'break-all', background: 'var(--bg-canvas)', padding: '6px 10px', borderRadius: '5px', border: '1px solid var(--border-inner)', fontFamily: 'var(--font-mono)' }}>
                    {checkpoint.checkpoint_signature}
                  </code>
                </div>
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '28px 0', color: 'var(--text-dim)', fontSize: '13px' }}>
                No active checkpoint generated yet. Click "Generate Checkpoint" to seal the current chain state.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Sequential Hash Chain Block Visualizer */}
      <div className="double-bezel" style={{ marginBottom: '28px' }}>
        <div className="double-bezel-inner">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Layers size={17} color="var(--primary)" />
              <h2 style={{ fontSize: '15px', fontWeight: 700, margin: 0, color: '#fff' }}>Sequential Chain Link Inspector</h2>
            </div>
            <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
              SHOWING {events.length} BLOCKS
            </span>
          </div>

          {loadingEvents ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', padding: '12px 0' }}>
              <div className="skeleton" style={{ height: '48px', width: '100%' }} />
              <div className="skeleton" style={{ height: '48px', width: '100%' }} />
              <div className="skeleton" style={{ height: '48px', width: '100%' }} />
            </div>
          ) : events.length === 0 ? (
            <div style={{ padding: '30px', textAlign: 'center', color: 'var(--text-dim)', fontSize: '13px' }}>
              Audit chain is currently empty. Ingest envelopes or trigger access actions to build the chain.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
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
                      background: isSelected ? 'var(--primary-bg)' : 'var(--bg-canvas)',
                      border: isSelected ? '1px solid var(--primary-border)' : '1px solid var(--border-inner)',
                      cursor: 'pointer',
                      transition: 'all 0.16s ease',
                    }}
                  >
                    {/* Block Index Badge */}
                    <div
                      style={{
                        padding: '4px 10px',
                        background: 'rgba(255, 255, 255, 0.04)',
                        border: '1px solid var(--border-inner)',
                        borderRadius: '6px',
                        fontFamily: 'var(--font-mono)',
                        fontSize: '11px',
                        fontWeight: 700,
                        color: 'var(--primary)',
                        minWidth: '70px',
                        textAlign: 'center',
                      }}
                    >
                      LINK #{idx + 1}
                    </div>

                    {/* Chain Link Icon */}
                    <LinkIcon size={14} color="var(--text-dim)" />

                    {/* Event Type & Role */}
                    <div style={{ flex: '1 1 200px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontWeight: 600, fontSize: '13px', color: '#fff' }}>{ev.event_type}</span>
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
                        fontSize: '10.5px',
                        fontFamily: 'var(--font-mono)',
                        color: '#4ade80',
                        fontWeight: 700,
                        background: 'var(--success-bg)',
                        padding: '4px 8px',
                        borderRadius: '5px',
                        border: '1px solid var(--success-border)',
                      }}
                    >
                      <CheckCircle2 size={13} color="#4ade80" />
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
          <div className="double-bezel-inner">
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
              <FileCode2 size={16} color="var(--primary)" />
              <h3 style={{ fontSize: '14px', fontWeight: 700, margin: 0, color: '#fff' }}>
                Canonical Hash Input Inspection (Event {selectedEvent.event_id.slice(0, 8)})
              </h3>
            </div>
            <pre
              style={{
                background: 'var(--bg-canvas)',
                padding: '16px',
                borderRadius: '8px',
                border: '1px solid var(--border-inner)',
                color: '#e2e8f0',
                fontSize: '12px',
                fontFamily: 'var(--font-mono)',
                overflowX: 'auto',
                margin: 0,
                lineHeight: 1.6,
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
