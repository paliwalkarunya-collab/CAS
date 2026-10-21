import React, { useEffect, useState } from 'react'
import type { AuditEvent, ChainVerifyResult, CheckpointResult, UserRole } from '../types'
import { queryAudit, verifyAuditChain, getAuditCheckpoint } from '../api'
import { ShieldCheck, Download, AlertTriangle, RefreshCw, CheckCircle2, XCircle, ShieldAlert, FileText, Check } from 'lucide-react'

interface AuditViewProps {
  currentRole: UserRole
}

export const AuditView: React.FC<AuditViewProps> = ({ currentRole }) => {
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [eventTypeFilter, setEventTypeFilter] = useState('')
  const [decisionFilter, setDecisionFilter] = useState('')
  const [loading, setLoading] = useState(true)
  const [verifyResult, setVerifyResult] = useState<ChainVerifyResult | null>(null)
  const [checkpoint, setCheckpoint] = useState<CheckpointResult | null>(null)
  const [verifying, setVerifying] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadEvents = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await queryAudit({
        eventType: eventTypeFilter || undefined,
        decision: decisionFilter || undefined,
        limit: 50,
      })
      setEvents(data)
    } catch (err: any) {
      setError(err.message || 'Failed to load audit events')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (['admin', 'auditor'].includes(currentRole)) {
      loadEvents()
    }
  }, [currentRole, eventTypeFilter, decisionFilter])

  const handleVerifyChain = async () => {
    setVerifying(true)
    setError(null)
    try {
      const res = await verifyAuditChain()
      setVerifyResult(res)
    } catch (err: any) {
      setError(err.message || 'Verification call failed')
    } finally {
      setVerifying(false)
    }
  }

  const handleExportCheckpoint = async () => {
    setError(null)
    try {
      const cp = await getAuditCheckpoint()
      setCheckpoint(cp)
    } catch (err: any) {
      setError(err.message || 'Failed to generate checkpoint')
    }
  }

  if (!['admin', 'auditor'].includes(currentRole)) {
    return (
      <div className="app-container fade-in" style={{ maxWidth: '640px', margin: '40px auto', textAlign: 'center' }}>
        <div className="double-bezel">
          <div className="double-bezel-inner" style={{ padding: '48px 24px' }}>
            <div style={{ width: '48px', height: '48px', borderRadius: '12px', background: 'var(--warning-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px', color: 'var(--warning)' }}>
              <ShieldAlert size={24} />
            </div>
            <h2 style={{ fontSize: '18px', fontWeight: 800, color: '#fff', marginBottom: '8px' }}>Auditor Authorization Required</h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '13.5px', lineHeight: 1.6, maxWidth: '440px', margin: '0 auto' }}>
              Only auditors and administrators can access the tamper-evident audit trail. Switch your active role to <strong>AUDITOR</strong> in the navigation bar.
            </p>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="app-container fade-in">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '28px', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
            <span className="section-label">AUDIT &amp; COMPLIANCE LOGS</span>
          </div>
          <h1 className="page-title">Tamper-Evident Audit Trail</h1>
          <p className="page-desc">
            Append-only, HMAC-SHA-256 chained audit logs. Every access attempt, decision, and administrative action links strictly to its predecessor's cryptographic hash.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button className="btn-secondary" onClick={loadEvents} disabled={loading}>
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
          <button className="btn-secondary" onClick={handleExportCheckpoint}>
            <Download size={13} />
            <span>Signed Checkpoint</span>
          </button>
          <button className="btn-primary" onClick={handleVerifyChain} disabled={verifying}>
            <ShieldCheck size={14} className={verifying ? 'animate-spin' : ''} />
            <span>{verifying ? 'Verifying...' : 'Verify Chain Integrity'}</span>
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

      {/* Chain Verification Result Alert */}
      {verifyResult && (
        <div
          style={{
            padding: '16px 20px',
            background: verifyResult.is_valid ? 'var(--success-bg)' : 'var(--danger-bg)',
            border: `1px solid ${verifyResult.is_valid ? 'var(--success-border)' : 'var(--danger-border)'}`,
            borderRadius: '10px',
            marginBottom: '24px',
            display: 'flex',
            alignItems: 'center',
            gap: '14px',
          }}
        >
          {verifyResult.is_valid ? (
            <CheckCircle2 size={24} color="#4ade80" />
          ) : (
            <XCircle size={24} color="#f87171" />
          )}
          <div>
            <div style={{ fontWeight: 800, fontSize: '14px', color: verifyResult.is_valid ? '#4ade80' : '#f87171' }}>
              {verifyResult.is_valid ? 'Audit Chain Verification Succeeded' : 'Audit Chain Tampering Detected!'}
            </div>
            <div style={{ fontSize: '12.5px', color: 'var(--text-muted)', marginTop: '2px' }}>
              {verifyResult.message} ({verifyResult.events_verified} sequential events checked)
            </div>
          </div>
        </div>
      )}

      {/* Checkpoint Card */}
      {checkpoint && (
        <div className="double-bezel" style={{ marginBottom: '24px' }}>
          <div className="double-bezel-inner" style={{ borderLeft: '3px solid var(--primary)' }}>
            <div style={{ fontSize: '14px', fontWeight: 700, color: '#fff', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Check size={15} color="var(--primary)" />
              <span>Cryptographically Signed Audit Checkpoint Generated</span>
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <div>Total Events: <strong style={{ color: '#fff', fontFamily: 'var(--font-mono)' }}>{checkpoint.total_events}</strong></div>
              <div>Last Event ID: <code style={{ color: 'var(--primary)', fontFamily: 'var(--font-mono)' }}>{checkpoint.last_event_id}</code></div>
              <div>Timestamp: <span style={{ fontFamily: 'var(--font-mono)' }}>{checkpoint.checkpoint_timestamp}</span></div>
              <div>
                HMAC Signature: <code style={{ color: '#4ade80', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>{checkpoint.checkpoint_signature}</code>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Filter Bar */}
      <div className="double-bezel" style={{ marginBottom: '24px' }}>
        <div className="double-bezel-inner" style={{ padding: '14px 20px' }}>
          <div style={{ display: 'flex', gap: '20px', alignItems: 'center', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className="section-label">EVENT TYPE:</span>
              <select
                className="select-field"
                style={{ width: 'auto', padding: '6px 12px', fontSize: '12.5px' }}
                value={eventTypeFilter}
                onChange={(e) => setEventTypeFilter(e.target.value)}
              >
                <option value="">All Events</option>
                <option value="upload">Upload</option>
                <option value="search">Search</option>
                <option value="access_allow">Access Allow</option>
                <option value="access_deny">Access Deny</option>
                <option value="key_rotate">Key Rotate</option>
                <option value="anomaly_alert">Anomaly Alert</option>
              </select>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className="section-label">DECISION:</span>
              <select
                className="select-field"
                style={{ width: 'auto', padding: '6px 12px', fontSize: '12.5px' }}
                value={decisionFilter}
                onChange={(e) => setDecisionFilter(e.target.value)}
              >
                <option value="">All Decisions</option>
                <option value="allow">Allow</option>
                <option value="deny">Deny</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="double-bezel">
        <div className="double-bezel-inner">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <span style={{ fontSize: '14px', fontWeight: 700, color: '#fff' }}>Chained Audit Log Records</span>
            <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
              {events.length} EVENTS LOADED
            </span>
          </div>

          {loading ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', padding: '12px 0' }}>
              <div className="skeleton" style={{ height: '42px', width: '100%' }} />
              <div className="skeleton" style={{ height: '42px', width: '100%' }} />
              <div className="skeleton" style={{ height: '42px', width: '100%' }} />
            </div>
          ) : events.length === 0 ? (
            <div style={{ padding: '36px 20px', textAlign: 'center', color: 'var(--text-dim)' }}>
              <FileText size={32} style={{ margin: '0 auto 10px', opacity: 0.6 }} />
              <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-main)', marginBottom: '4px' }}>No audit events match filters</div>
              <p style={{ fontSize: '12px' }}>Try resetting the filters or executing actions across the dashboard.</p>
            </div>
          ) : (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>TIMESTAMP (UTC)</th>
                    <th>EVENT TYPE</th>
                    <th>ACTOR ROLE</th>
                    <th>DECISION</th>
                    <th>REASON / DETAILS</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((ev) => (
                    <tr key={ev.event_id}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11.5px', color: 'var(--text-muted)' }}>
                        {new Date(ev.occurred_at).toLocaleTimeString()}
                      </td>
                      <td style={{ fontWeight: 600, color: '#fff' }}>{ev.event_type}</td>
                      <td>
                        <span className={`badge-role ${ev.actor_role || 'auditor'}`}>
                          {ev.actor_role || 'SYSTEM'}
                        </span>
                      </td>
                      <td>
                        {ev.decision ? (
                          <span className={`decision-pill ${ev.decision}`}>{ev.decision}</span>
                        ) : (
                          <span style={{ color: 'var(--text-dim)', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>--</span>
                        )}
                      </td>
                      <td style={{ fontSize: '12px', color: 'var(--text-muted)', maxWidth: '380px' }}>
                        {ev.reason || '--'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
