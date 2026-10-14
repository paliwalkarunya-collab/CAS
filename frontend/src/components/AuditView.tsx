import React, { useEffect, useState } from 'react'
import type { AuditEvent, ChainVerifyResult, CheckpointResult, UserRole } from '../types'
import { queryAudit, verifyAuditChain, getAuditCheckpoint } from '../api'
import { ShieldCheck, Download, AlertTriangle, RefreshCw, CheckCircle2, XCircle } from 'lucide-react'

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
      <div style={{ maxWidth: '800px', margin: '40px auto', padding: '32px 24px', textAlign: 'center' }}>
        <div className="double-bezel">
          <div className="double-bezel-inner" style={{ padding: '40px 20px' }}>
            <AlertTriangle size={36} color="#fbbf24" style={{ margin: '0 auto 16px' }} />
            <h2 style={{ fontSize: '18px', fontWeight: 800, marginBottom: '8px' }}>Auditor Privileges Required</h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '14px' }}>
              Only auditors and administrators can view the audit trail and verify cryptographic chain integrity. Switch your active role to AUDITOR.
            </p>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '32px 24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '24px' }}>
        <div>
          <h1 className="page-title">Tamper-Evident Audit Trail</h1>
          <p className="page-desc">
            Append-only, HMAC-SHA-256 chained audit log. Every event links to the previous event's cryptographic hash.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button className="btn-secondary" onClick={loadEvents} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
          <button className="btn-secondary" onClick={handleExportCheckpoint}>
            <Download size={14} />
            <span>Signed Checkpoint</span>
          </button>
          <button className="btn-primary" onClick={handleVerifyChain} disabled={verifying}>
            <ShieldCheck size={14} />
            <span>{verifying ? 'Verifying Chain...' : 'Verify Chain Integrity'}</span>
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

      {/* Chain Verification Result Alert */}
      {verifyResult && (
        <div
          style={{
            padding: '16px 20px',
            background: verifyResult.is_valid ? 'rgba(16, 185, 129, 0.12)' : 'rgba(244, 63, 94, 0.12)',
            border: `1px solid ${verifyResult.is_valid ? 'rgba(16, 185, 129, 0.3)' : 'rgba(244, 63, 94, 0.3)'}`,
            borderRadius: '8px',
            marginBottom: '20px',
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
          }}
        >
          {verifyResult.is_valid ? (
            <CheckCircle2 size={24} color="#34d399" />
          ) : (
            <XCircle size={24} color="#fb7185" />
          )}
          <div>
            <div style={{ fontWeight: 800, color: verifyResult.is_valid ? '#34d399' : '#fb7185' }}>
              {verifyResult.is_valid ? 'Audit Chain Verification Succeeded' : 'Audit Chain Tampering Detected!'}
            </div>
            <div style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '2px' }}>
              {verifyResult.message} ({verifyResult.events_verified} events checked)
            </div>
          </div>
        </div>
      )}

      {/* Checkpoint Modal / Card */}
      {checkpoint && (
        <div className="double-bezel" style={{ marginBottom: '24px' }}>
          <div className="double-bezel-inner" style={{ borderLeft: '4px solid var(--primary)' }}>
            <div style={{ fontSize: '14px', fontWeight: 700, color: '#fff', marginBottom: '8px' }}>
              Cryptographically Signed Audit Checkpoint
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <div>Total Events: <strong>{checkpoint.total_events}</strong></div>
              <div>Last Event ID: <code>{checkpoint.last_event_id}</code></div>
              <div>Timestamp: {checkpoint.checkpoint_timestamp}</div>
              <div>
                HMAC Signature: <code style={{ color: '#60a5fa' }}>{checkpoint.checkpoint_signature}</code>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Filter Bar */}
      <div className="double-bezel" style={{ marginBottom: '24px' }}>
        <div className="double-bezel-inner" style={{ padding: '14px 20px' }}>
          <div style={{ display: 'flex', gap: '16px', alignItems: 'center', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-dim)' }}>EVENT TYPE:</span>
              <select
                className="select-field"
                style={{ width: 'auto', padding: '6px 12px' }}
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
              <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-dim)' }}>DECISION:</span>
              <select
                className="select-field"
                style={{ width: 'auto', padding: '6px 12px' }}
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
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-muted)' }}>
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
                        <span style={{ color: 'var(--text-dim)', fontSize: '12px' }}>--</span>
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
        </div>
      </div>
    </div>
  )
}
