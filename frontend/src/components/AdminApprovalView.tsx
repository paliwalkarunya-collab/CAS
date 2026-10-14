import React, { useEffect, useState } from 'react'
import type { KeyVersionItem, MLJob, UserRole } from '../types'
import { approveMLJob, rejectMLJob, listMLJobs, listKeyVersions, rotateKey } from '../api'
import { CheckCircle2, XCircle, RotateCcw, KeyRound, AlertTriangle, RefreshCw } from 'lucide-react'

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
      setActionSuccess(`Job ${jobId.slice(0, 8)} approved! Signed manifest token generated.`)
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
    if (!confirm('Rotate Wrapping Key (KEK)? This will rewrap all envelope DEKs to a new key version.')) {
      return
    }
    setRotating(true)
    setError(null)
    try {
      const res = await rotateKey()
      setActionSuccess(
        `KEK rotated from v${res.old_kek_version} to v${res.new_kek_version}! ${res.envelopes_rewrapped} envelopes rewrapped.`
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
      <div style={{ maxWidth: '800px', margin: '40px auto', padding: '32px 24px', textAlign: 'center' }}>
        <div className="double-bezel">
          <div className="double-bezel-inner" style={{ padding: '40px 20px' }}>
            <AlertTriangle size={36} color="#fbbf24" style={{ margin: '0 auto 16px' }} />
            <h2 style={{ fontSize: '18px', fontWeight: 800, marginBottom: '8px' }}>Admin Privileges Required</h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '14px' }}>
              Only administrators can approve scoped ML job manifests and rotate master wrapping keys. Switch your active role to ADMIN in the top bar.
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
          <h1 className="page-title">Admin Governance &amp; Key Lifecycle</h1>
          <p className="page-desc">
            Review pending ML training job manifests and manage envelope wrapping key rotations.
          </p>
        </div>
        <button className="btn-secondary" onClick={loadData} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          <span>Refresh Queue</span>
        </button>
      </div>

      {actionSuccess && (
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
          {actionSuccess}
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

      {/* Pending Job Queue */}
      <div className="double-bezel" style={{ marginBottom: '28px' }}>
        <div className="double-bezel-inner">
          <h2 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <CheckCircle2 size={18} color="#34d399" />
            <span>Pending ML Job Approval Queue ({pendingJobs.length})</span>
          </h2>

          {pendingJobs.length === 0 ? (
            <div style={{ padding: '24px 0', textAlign: 'center', color: 'var(--text-dim)', fontSize: '13px' }}>
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
                    <tr key={j.id}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: '#fff' }}>
                        {j.id.slice(0, 8)}...
                      </td>
                      <td style={{ fontWeight: 600 }}>{j.purpose}</td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: '#60a5fa' }}>
                        {j.dataset_scope}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{j.requested_view}</td>
                      <td>
                        <div style={{ display: 'flex', gap: '8px' }}>
                          <button
                            className="btn-primary"
                            style={{ padding: '6px 12px', fontSize: '12px' }}
                            onClick={() => handleApprove(j.id)}
                          >
                            <CheckCircle2 size={13} />
                            <span>Approve &amp; Sign</span>
                          </button>
                          <button
                            className="btn-secondary"
                            style={{ padding: '6px 12px', fontSize: '12px', color: '#fb7185' }}
                            onClick={() => handleReject(j.id)}
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
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <div>
              <h2 style={{ fontSize: '16px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
                <KeyRound size={18} color="#f59e0b" />
                <span>Wrapping Key (KEK) Lifecycle</span>
              </h2>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                Rewraps envelope DEKs under a new KEK version. <strong>Payload ciphertext in S3/MinIO remains untouched.</strong>
              </p>
            </div>
            <button className="btn-primary" onClick={handleRotateKey} disabled={rotating}>
              <RotateCcw size={14} className={rotating ? 'animate-spin' : ''} />
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
                    <td style={{ fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                      v{kv.version_number}
                    </td>
                    <td>
                      {kv.is_current ? (
                        <span
                          style={{
                            fontSize: '11px',
                            fontWeight: 700,
                            padding: '2px 8px',
                            borderRadius: '4px',
                            background: 'rgba(16, 185, 129, 0.15)',
                            color: '#34d399',
                          }}
                        >
                          ACTIVE CURRENT
                        </span>
                      ) : (
                        <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>RETIRED (READ-ONLY)</span>
                      )}
                    </td>
                    <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
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
