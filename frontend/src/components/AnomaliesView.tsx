import React, { useEffect, useState } from 'react'
import type { AnomalyAlert, UserRole } from '../types'
import { listAnomalies, runAnomalyScan, reviewAnomaly } from '../api'
import { AlertTriangle, CheckCircle2, Play, RefreshCw, ShieldAlert, Check } from 'lucide-react'

interface AnomaliesViewProps {
  currentRole: UserRole
}

export const AnomaliesView: React.FC<AnomaliesViewProps> = ({ currentRole }) => {
  const [alerts, setAlerts] = useState<AnomalyAlert[]>([])
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)
  const [filterReviewed, setFilterReviewed] = useState<'all' | 'unreviewed' | 'reviewed'>('unreviewed')
  const [actionMsg, setActionMsg] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const loadAlerts = async () => {
    setLoading(true)
    setError(null)
    try {
      const reviewedParam = filterReviewed === 'all' ? undefined : filterReviewed === 'reviewed'
      const data = await listAnomalies(reviewedParam)
      setAlerts(data)
    } catch (err: any) {
      setError(err.message || 'Failed to load anomaly alerts')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (['admin', 'auditor'].includes(currentRole)) {
      loadAlerts()
    }
  }, [currentRole, filterReviewed])

  const handleRunScan = async () => {
    setScanning(true)
    setError(null)
    setActionMsg(null)
    try {
      const res = await runAnomalyScan(72)
      setActionMsg(`IsolationForest scan completed: ${res.alerts_created} new alert(s) filed.`)
      await loadAlerts()
    } catch (err: any) {
      setError(err.message || 'Anomaly scan execution failed')
    } finally {
      setScanning(false)
    }
  }

  const handleReview = async (alertId: string) => {
    try {
      await reviewAnomaly(alertId)
      await loadAlerts()
    } catch (err: any) {
      setError(err.message || 'Failed to review alert')
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
              Only auditors and administrators can view anomaly alerts and execute IsolationForest scans. Switch your active role to <strong>AUDITOR</strong> in the navigation bar.
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
            <span className="section-label">UNSUPERVISED BEHAVIORAL HEURISTICS</span>
          </div>
          <h1 className="page-title">Audit Anomaly Alerts (IsolationForest)</h1>
          <p className="page-desc">
            Unsupervised machine learning scans audit behavior for suspicious access volume, denied request bursts, and bulk exfiltration patterns. Alerts are <strong>advisory</strong>.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button className="btn-secondary" onClick={loadAlerts} disabled={loading}>
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
          <button className="btn-primary" onClick={handleRunScan} disabled={scanning}>
            <Play size={13} className={scanning ? 'animate-spin' : ''} />
            <span>{scanning ? 'Executing Scan...' : 'Run Detection Scan'}</span>
          </button>
        </div>
      </div>

      {actionMsg && (
        <div
          style={{
            padding: '12px 16px',
            background: 'var(--success-bg)',
            border: '1px solid var(--success-border)',
            borderRadius: '8px',
            color: '#4ade80',
            fontSize: '13px',
            marginBottom: '20px',
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <Check size={16} />
          <span>{actionMsg}</span>
        </div>
      )}

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

      {/* Filter Tabs */}
      <div style={{ display: 'flex', gap: '6px', marginBottom: '20px' }}>
        <button
          className={`tab-btn ${filterReviewed === 'unreviewed' ? 'active' : ''}`}
          onClick={() => setFilterReviewed('unreviewed')}
        >
          Unreviewed Alerts
        </button>
        <button
          className={`tab-btn ${filterReviewed === 'reviewed' ? 'active' : ''}`}
          onClick={() => setFilterReviewed('reviewed')}
        >
          Reviewed
        </button>
        <button
          className={`tab-btn ${filterReviewed === 'all' ? 'active' : ''}`}
          onClick={() => setFilterReviewed('all')}
        >
          All Alerts
        </button>
      </div>

      {/* Alerts Table */}
      <div className="double-bezel">
        <div className="double-bezel-inner">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <span style={{ fontSize: '14px', fontWeight: 700, color: '#fff' }}>Detected Anomaly Records</span>
            <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
              {alerts.length} ALERTS
            </span>
          </div>

          {loading ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', padding: '12px 0' }}>
              <div className="skeleton" style={{ height: '42px', width: '100%' }} />
              <div className="skeleton" style={{ height: '42px', width: '100%' }} />
            </div>
          ) : alerts.length === 0 ? (
            <div style={{ padding: '36px 0', textAlign: 'center', color: 'var(--text-dim)' }}>
              <CheckCircle2 size={32} color="#4ade80" style={{ margin: '0 auto 10px', opacity: 0.8 }} />
              <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-main)', marginBottom: '4px' }}>
                No anomaly alerts found
              </div>
              <p style={{ fontSize: '12px' }}>All behavioral access metrics are conforming to standard baseline heuristics.</p>
            </div>
          ) : (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>DETECTED AT</th>
                    <th>ALERT TYPE</th>
                    <th>ANOMALY SCORE</th>
                    <th>DESCRIPTION</th>
                    <th>STATUS</th>
                    <th>ACTION</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.map((a) => (
                    <tr key={a.alert_id}>
                      <td style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        {new Date(a.detected_at).toLocaleString()}
                      </td>
                      <td>
                        <span
                          style={{
                            fontSize: '10.5px',
                            fontWeight: 700,
                            fontFamily: 'var(--font-mono)',
                            padding: '3px 8px',
                            borderRadius: '5px',
                            background: 'var(--warning-bg)',
                            color: '#fbbf24',
                            border: '1px solid var(--warning-border)',
                          }}
                        >
                          {a.alert_type}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 700, color: '#f87171' }}>
                        {a.anomaly_score ? a.anomaly_score.toFixed(2) : '--'}
                      </td>
                      <td style={{ fontSize: '13px', color: '#fff', maxWidth: '380px' }}>
                        {a.description}
                      </td>
                      <td>
                        {a.is_reviewed ? (
                          <span style={{ fontSize: '10.5px', fontFamily: 'var(--font-mono)', color: '#4ade80', fontWeight: 700 }}>REVIEWED</span>
                        ) : (
                          <span style={{ fontSize: '10.5px', fontFamily: 'var(--font-mono)', color: '#f87171', fontWeight: 700 }}>OPEN</span>
                        )}
                      </td>
                      <td>
                        {!a.is_reviewed && (
                          <button
                            className="btn-secondary"
                            style={{ padding: '4px 10px', fontSize: '11px' }}
                            onClick={() => handleReview(a.alert_id)}
                          >
                            Mark Reviewed
                          </button>
                        )}
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
