import React, { useEffect, useState } from 'react'
import type { AnomalyAlert, UserRole } from '../types'
import { listAnomalies, runAnomalyScan, reviewAnomaly } from '../api'
import { AlertTriangle, CheckCircle2, Play, RefreshCw } from 'lucide-react'

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
      <div style={{ maxWidth: '800px', margin: '40px auto', padding: '32px 24px', textAlign: 'center' }}>
        <div className="double-bezel">
          <div className="double-bezel-inner" style={{ padding: '40px 20px' }}>
            <AlertTriangle size={36} color="#fbbf24" style={{ margin: '0 auto 16px' }} />
            <h2 style={{ fontSize: '18px', fontWeight: 800, marginBottom: '8px' }}>Auditor Privileges Required</h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '14px' }}>
              Only auditors and administrators can view anomaly alerts and execute IsolationForest scans. Switch your active role to AUDITOR.
            </p>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div style={{ maxWidth: '1100px', margin: '0 auto', padding: '32px 24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '24px' }}>
        <div>
          <h1 className="page-title">Audit Anomaly Alerts (IsolationForest)</h1>
          <p className="page-desc">
            Unsupervised anomaly detection scans audit behavior for suspicious access volume, denied request bursts, and bulk exfiltration.
            Alerts are <strong>advisory</strong> and never automatically revoke credentials.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button className="btn-secondary" onClick={loadAlerts} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
          <button className="btn-primary" onClick={handleRunScan} disabled={scanning}>
            <Play size={14} className={scanning ? 'animate-spin' : ''} />
            <span>{scanning ? 'Executing Scan...' : 'Run Detection Scan'}</span>
          </button>
        </div>
      </div>

      {actionMsg && (
        <div
          style={{
            padding: '12px 16px',
            background: 'rgba(16, 185, 129, 0.15)',
            border: '1px solid rgba(16, 185, 129, 0.3)',
            borderRadius: '8px',
            color: '#34d399',
            fontSize: '13px',
            marginBottom: '20px',
            fontWeight: 600,
          }}
        >
          {actionMsg}
        </div>
      )}

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

      {/* Filter Tabs */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '20px' }}>
        <button
          className={`tab-btn ${filterReviewed === 'unreviewed' ? 'active' : ''}`}
          onClick={() => setFilterReviewed('unreviewed')}
        >
          Unreviewed
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
          {alerts.length === 0 ? (
            <div style={{ padding: '32px 0', textAlign: 'center', color: 'var(--text-dim)' }}>
              <CheckCircle2 size={32} color="#34d399" style={{ margin: '0 auto 10px', opacity: 0.7 }} />
              <div>No anomaly alerts found for the selected filter.</div>
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
                      <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                        {new Date(a.detected_at).toLocaleString()}
                      </td>
                      <td>
                        <span
                          style={{
                            fontSize: '11px',
                            fontWeight: 700,
                            fontFamily: 'var(--font-mono)',
                            padding: '3px 8px',
                            borderRadius: '4px',
                            background: 'rgba(245, 158, 11, 0.15)',
                            color: '#fbbf24',
                          }}
                        >
                          {a.alert_type}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 700, color: '#f43f5e' }}>
                        {a.anomaly_score ? a.anomaly_score.toFixed(2) : '--'}
                      </td>
                      <td style={{ fontSize: '13px', color: '#fff', maxWidth: '380px' }}>
                        {a.description}
                      </td>
                      <td>
                        {a.is_reviewed ? (
                          <span style={{ fontSize: '11px', color: '#34d399', fontWeight: 700 }}>REVIEWED</span>
                        ) : (
                          <span style={{ fontSize: '11px', color: '#fb7185', fontWeight: 700 }}>OPEN</span>
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
