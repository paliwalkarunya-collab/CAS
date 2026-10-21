import React, { useEffect, useState } from 'react'
import type { KeyVersionItem, MLJob, UserRole } from '../types'
import { approveMLJob, rejectMLJob, listMLJobs, listKeyVersions, rotateKey } from '../api'
import { CheckCircle2, XCircle, RotateCcw, KeyRound, AlertTriangle, RefreshCw, ShieldAlert, Check } from 'lucide-react'

interface AdminApprovalViewProps {
  currentRole: UserRole
}

export const AdminApprovalView: React.FC<AdminApprovalViewProps> = ({ currentRole }) => {
  const [pendingJobs, setPendingJobs] = useState<MLJob[]>([])
  const [keyVersions, setKeyVersions] = useState<KeyVersionItem[]>([])
  const [loading, setLoading] = useState(true)
  const [rotating, setRotating] = useState(false)
  const [actionSuccess, setActionSuccess] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const loadData = async () => {
    setLoading(true)
    setError(null)
    try {
      const allJobs = await listMLJobs()
      setPendingJobs(allJobs.filter((j) => j.status === 'pending'))

      if (currentRole === 'admin') {
        const keys = await listKeyVersions()
        setKeyVersions(keys)
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load admin queue data')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [currentRole])

  const handleApprove = async (jobId: string) => {
    setError(null)
    try {
      await approveMLJob(jobId)
      setActionSuccess(`Job ${jobId.slice(0, 8)} approved. Cryptographic signed manifest token issued.`)
      await loadData()
    } catch (err: any) {
      setError(err.message || 'Failed to approve job')
    }
  }

  const handleReject = async (jobId: string) => {
    const reason = prompt('Enter rejection reason:')
    if (!reason) return
    setError(null)
    try {
      await rejectMLJob(jobId, reason)
      setActionSuccess(`Job ${jobId.slice(0, 8)} rejected.`)
      await loadData()
    } catch (err: any) {
      setError(err.message || 'Failed to reject job')
    }
  }

  const handleRotateKey = async () => {
    if (!confirm('Rotate Master Wrapping Key (KEK)? This will rewrap all envelope DEKs under a new key version.')) {
      return
    }
    setRotating(true)
    setError(null)
    try {
      const res = await rotateKey()
      setActionSuccess(
        `KEK rotated from v${res.old_kek_version} to v${res.new_kek_version}. ${res.envelopes_rewrapped} envelopes rewrapped in-place.`
      )
      await loadData()
    } catch (err: any) {
      setError(err.message || 'Key rotation failed')
    } finally {
      setRotating(false)
    }
  }

  if (currentRole !== 'admin') {
    return (
      <div className="app-container fade-in" style={{ maxWidth: '640px', margin: '40px auto', textAlign: 'center' }}>
        <div className="double-bezel">
          <div className="double-bezel-inner" style={{ padding: '48px 24px' }}>
            <div style={{ width: '48px', height: '48px', borderRadius: '12px', background: 'var(--warning-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px', color: 'var(--warning)' }}>
              <ShieldAlert size={24} />
            </div>
            <h2 style={{ fontSize: '18px', fontWeight: 800, color: '#fff', marginBottom: '8px' }}>Admin Authorization Required</h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '13.5px', lineHeight: 1.6, maxWidth: '440px', margin: '0 auto 20px' }}>
              Only security administrators can approve scoped ML job manifests and rotate master wrapping keys. Switch your active role to <strong>ADMIN</strong> in the top navigation.
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
            <span className="section-label">GOVERNANCE &amp; KEY CONTROL</span>
          </div>
          <h1 className="page-title">Admin Governance &amp; Key Lifecycle</h1>
          <p className="page-desc">
            Review pending ML training job manifests and execute zero-downtime envelope wrapping key rotations.
          </p>
        </div>
        <button className="btn-secondary" onClick={loadData} disabled={loading}>
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          <span>Refresh Queue</span>
        </button>
      </div>

      {actionSuccess && (
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
          <span>{actionSuccess}</span>
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

      {/* Pending Job Queue */}
      <div className="double-bezel" style={{ marginBottom: '28px' }}>
        <div className="double-bezel-inner">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px' }}>
            <h2 style={{ fontSize: '15px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px', color: '#fff' }}>
              <CheckCircle2 size={17} color="var(--primary)" />
              <span>Pending ML Job Approval Queue</span>
            </h2>
            <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
              {pendingJobs.length} PENDING
            </span>
          </div>

          {pendingJobs.length === 0 ? (
            <div style={{ padding: '36px 20px', textAlign: 'center', color: 'var(--text-dim)', fontSize: '13px' }}>
              No pending ML jobs requiring approval at this time.
            </div>
          ) : (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>JOB ID</th>
                    <th>PURPOSE</th>
                    <th>SCOPE</th>
                    <th>VIEW REQUESTED</th>
                    <th>ACTIONS</th>
                  </tr>
                </thead>
                <tbody>
                  {pendingJobs.map((j) => (
                    <tr key={j.job_id}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11.5px', color: '#fff' }}>
                        {j.job_id.slice(0, 8)}...
                      </td>
                      <td style={{ fontWeight: 600 }}>{j.purpose}</td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--primary)' }}>
                        {j.dataset_scope.join(', ') || '—'}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{j.requested_view}</td>
                      <td>
                        <div style={{ display: 'flex', gap: '8px' }}>
                          <button
                            className="btn-primary"
                            style={{ padding: '6px 12px', fontSize: '12px' }}
                            onClick={() => handleApprove(j.job_id)}
                          >
                            <CheckCircle2 size={13} />
                            <span>Approve &amp; Sign</span>
                          </button>
                          <button
                            className="btn-danger"
                            style={{ padding: '6px 12px', fontSize: '12px' }}
                            onClick={() => handleReject(j.job_id)}
                          >
                            <XCircle size={13} />
                            <span>Reject</span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Wrapping Key (KEK) Rotation Panel */}
      <div className="double-bezel">
        <div className="double-bezel-inner">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap', gap: '16px' }}>
            <div>
              <h2 style={{ fontSize: '15px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px', color: '#fff' }}>
                <KeyRound size={17} color="var(--primary)" />
                <span>Wrapping Key (KEK) Lifecycle</span>
              </h2>
              <p style={{ fontSize: '12.5px', color: 'var(--text-muted)', marginTop: '4px' }}>
                Rewraps envelope DEKs under a new KEK version. <strong style={{ color: 'var(--text-main)' }}>Payload ciphertext in storage remains untouched.</strong>
              </p>
            </div>
            <button className="btn-primary" onClick={handleRotateKey} disabled={rotating}>
              <RotateCcw size={13} className={rotating ? 'animate-spin' : ''} />
              <span>{rotating ? 'Rewrapping DEKs...' : 'Rotate Wrapping Key (KEK)'}</span>
            </button>
          </div>

          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>KEK VERSION</th>
                  <th>STATUS</th>
                  <th>ACTIVATED AT</th>
                </tr>
              </thead>
              <tbody>
                {keyVersions.map((kv) => (
                  <tr key={kv.version_number}>
                    <td style={{ fontWeight: 700, fontFamily: 'var(--font-mono)', fontSize: '13px' }}>
                      v{kv.version_number}
                    </td>
                    <td>
                      {kv.is_current ? (
                        <span
                          style={{
                            fontSize: '10.5px',
                            fontFamily: 'var(--font-mono)',
                            fontWeight: 700,
                            padding: '3px 8px',
                            borderRadius: '5px',
                            background: 'var(--success-bg)',
                            color: '#4ade80',
                            border: '1px solid var(--success-border)',
                          }}
                        >
                          ACTIVE CURRENT
                        </span>
                      ) : (
                        <span style={{ fontSize: '10.5px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
                          RETIRED (READ-ONLY)
                        </span>
                      )}
                    </td>
                    <td style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      {new Date(kv.created_at).toLocaleString()}
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
