import React, { useEffect, useState } from 'react'
import type { KeyStatusInfo, KeyVersionItem, MLJob, ShamirInitResult, UserRole } from '../types'
import {
  approveMLJob,
  rejectMLJob,
  listMLJobs,
  listKeyVersions,
  rotateKey,
  getKeyStatus,
  unlockShamir,
  lockShamir,
  initShamir,
} from '../api'
import {
  CheckCircle2,
  XCircle,
  RotateCcw,
  KeyRound,
  AlertTriangle,
  RefreshCw,
  ShieldAlert,
  Check,
  Lock,
  Unlock,
  Key,
} from 'lucide-react'

interface AdminApprovalViewProps {
  currentRole: UserRole
}

export const AdminApprovalView: React.FC<AdminApprovalViewProps> = ({ currentRole }) => {
  const [pendingJobs, setPendingJobs] = useState<MLJob[]>([])
  const [keyVersions, setKeyVersions] = useState<KeyVersionItem[]>([])
  const [keyStatus, setKeyStatus] = useState<KeyStatusInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [rotating, setRotating] = useState(false)
  const [actionSuccess, setActionSuccess] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  // Shamir form states
  const [shareInput1, setShareInput1] = useState('')
  const [shareInput2, setShareInput2] = useState('')
  const [unlocking, setUnlocking] = useState(false)
  const [initResult, setInitResult] = useState<ShamirInitResult | null>(null)
  const [provisionedShares, setProvisionedShares] = useState<string[] | null>(null)

  const loadData = async () => {
    setLoading(true)
    setError(null)
    try {
      const allJobs = await listMLJobs()
      setPendingJobs(allJobs.filter((j) => j.status === 'pending'))

      if (currentRole === 'admin') {
        const [keys, status] = await Promise.all([
          listKeyVersions(),
          getKeyStatus().catch(() => null),
        ])
        setKeyVersions(keys)
        setKeyStatus(status)
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
    setProvisionedShares(null)
    try {
      const res = await rotateKey()
      const rewrapMsg = typeof res.envelopes_rewrapped === 'number'
        ? `${res.envelopes_rewrapped} envelopes rewrapped in-place.`
        : `${res.envelopes_rewrapped}.`
      setActionSuccess(
        `KEK rotated from v${res.old_kek_version} to v${res.new_kek_version}. ${rewrapMsg}`
      )
      if (res.provisioned_shares && res.provisioned_shares.length > 0) {
        setProvisionedShares(res.provisioned_shares)
      }
      await loadData()
    } catch (err: any) {
      setError(err.message || 'Key rotation failed')
    } finally {
      setRotating(false)
    }
  }

  const handleShamirUnlock = async (e: React.FormEvent) => {
    e.preventDefault()
    const shares = [shareInput1.trim(), shareInput2.trim()].filter(Boolean)
    if (shares.length < 2) {
      setError('Please provide at least 2 distinct Shamir shares in "x-hex" format to reconstruct the KEK.')
      return
    }
    setUnlocking(true)
    setError(null)
    try {
      const res = await unlockShamir(shares)
      setActionSuccess(res.message)
      setShareInput1('')
      setShareInput2('')
      await loadData()
    } catch (err: any) {
      setError(err.message || 'Failed to unlock Shamir key')
    } finally {
      setUnlocking(false)
    }
  }

  const handleShamirLock = async () => {
    if (!confirm('Lock Shamir Key Service? This wipes the reconstructed KEK from memory until threshold shares are re-supplied.')) {
      return
    }
    setError(null)
    try {
      const res = await lockShamir()
      setActionSuccess(res.message)
      await loadData()
    } catch (err: any) {
      setError(err.message || 'Failed to lock key service')
    }
  }

  const handleShamirInit = async () => {
    if (!confirm('Initialize a fresh 2-of-3 Shamir key split? This will generate a new KEK and return 3 shares to distribute to custodians.')) {
      return
    }
    setError(null)
    setInitResult(null)
    try {
      const res = await initShamir()
      setInitResult(res)
      setActionSuccess(`Fresh Shamir KEK v${res.version} initialized and unlocked in memory.`)
      await loadData()
    } catch (err: any) {
      setError(err.message || 'Failed to initialize Shamir keys')
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

      {/* Shamir Key Provisioning / Initialization Alert */}
      {(initResult || provisionedShares) && (
        <div className="double-bezel" style={{ marginBottom: '24px' }}>
          <div className="double-bezel-inner" style={{ borderLeft: '4px solid #f59e0b', background: 'rgba(245, 158, 11, 0.05)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px', color: '#f59e0b' }}>
              <AlertTriangle size={20} />
              <h3 style={{ fontSize: '15px', fontWeight: 700 }}>
                {initResult ? `Fresh Shamir KEK v${initResult.version} Provisioned (2-of-3)` : 'New KEK Rotation Shares Provisioned'}
              </h3>
            </div>
            <p style={{ fontSize: '13px', color: 'var(--text-main)', marginBottom: '16px', lineHeight: 1.6 }}>
              {initResult?.warning || 'Distribute these threshold shares to separate custodians immediately. Shares are not stored on disk and will not be displayed again.'}
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '16px' }}>
              {(initResult ? initResult.shares : provisionedShares || []).map((s, idx) => (
                <div
                  key={idx}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '8px 14px',
                    background: 'var(--bg-canvas)',
                    border: '1px solid var(--border-inner)',
                    borderRadius: '6px',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '12px',
                  }}
                >
                  <span style={{ color: 'var(--primary)', fontWeight: 700 }}>SHARE #{idx + 1}:</span>
                  <span style={{ color: '#fff', userSelect: 'all' }}>{s}</span>
                </div>
              ))}
            </div>
            <button
              className="btn-secondary"
              onClick={() => {
                setInitResult(null)
                setProvisionedShares(null)
              }}
            >
              <span>Dismiss &amp; Clear Displayed Shares</span>
            </button>
          </div>
        </div>
      )}

      {/* Shamir Secret Sharing Custodian Controls */}
      <div className="double-bezel" style={{ marginBottom: '24px' }}>
        <div className="double-bezel-inner">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                <Key size={17} color="var(--primary)" />
                <h2 style={{ fontSize: '15px', fontWeight: 700, color: '#fff' }}>
                  Shamir Secret Sharing (2-of-3) Custodian State
                </h2>
                <span
                  style={{
                    fontSize: '10.5px',
                    fontFamily: 'var(--font-mono)',
                    fontWeight: 700,
                    padding: '2px 8px',
                    borderRadius: '4px',
                    background: keyStatus?.adapter === 'split' ? 'var(--primary-bg)' : 'rgba(255, 255, 255, 0.05)',
                    color: keyStatus?.adapter === 'split' ? 'var(--primary)' : 'var(--text-dim)',
                    border: '1px solid var(--border-inner)',
                  }}
                >
                  ADAPTER: {keyStatus?.adapter?.toUpperCase() || 'UNKNOWN'}
                </span>
              </div>
              <p style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>
                {keyStatus?.adapter === 'split'
                  ? 'Active KEK is split into 3 mathematical shares. Any 2 shares reconstruct the KEK in memory.'
                  : 'Currently running under EnvVarKeyService. Set KEY_SERVICE_ADAPTER=split in .env to activate Shamir mode.'}
              </p>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              {keyStatus?.adapter === 'split' && (
                <>
                  <span
                    style={{
                      fontSize: '11px',
                      fontFamily: 'var(--font-mono)',
                      fontWeight: 700,
                      padding: '4px 10px',
                      borderRadius: '5px',
                      background: keyStatus.is_unlocked ? 'var(--success-bg)' : 'var(--danger-bg)',
                      color: keyStatus.is_unlocked ? '#4ade80' : '#f87171',
                      border: `1px solid ${keyStatus.is_unlocked ? 'var(--success-border)' : 'var(--danger-border)'}`,
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                    }}
                  >
                    {keyStatus.is_unlocked ? <Unlock size={13} /> : <Lock size={13} />}
                    <span>{keyStatus.is_unlocked ? 'UNLOCKED (IN MEMORY)' : 'LOCKED (FAIL-CLOSED)'}</span>
                  </span>

                  {keyStatus.is_unlocked ? (
                    <button className="btn-secondary" onClick={handleShamirLock} title="Wipe KEK from memory">
                      <Lock size={13} />
                      <span>Lock Key</span>
                    </button>
                  ) : null}

                  <button className="btn-secondary" onClick={handleShamirInit} title="Generate fresh 2-of-3 Shamir key set">
                    <RefreshCw size={13} />
                    <span>Bootstrap Fresh Split</span>
                  </button>
                </>
              )}
            </div>
          </div>

          {keyStatus?.adapter === 'split' && !keyStatus.is_unlocked && (
            <div
              style={{
                marginTop: '16px',
                padding: '18px',
                background: 'var(--bg-canvas)',
                border: '1px solid var(--danger-border)',
                borderRadius: '8px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#f87171', marginBottom: '12px', fontSize: '13px', fontWeight: 600 }}>
                <ShieldAlert size={16} />
                <span>KEK is locked. Ingestion and decryption operations are blocked until unlocked.</span>
              </div>
              <form onSubmit={handleShamirUnlock}>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px', marginBottom: '14px' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', marginBottom: '4px' }}>
                      CUSTODIAN SHARE A (e.g. 1-...)
                    </label>
                    <input
                      type="text"
                      className="input-field"
                      placeholder="1-abcd..."
                      value={shareInput1}
                      onChange={(e) => setShareInput1(e.target.value)}
                      required
                    />
                  </div>
                  <div>
                    <label style={{ display: 'block', fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', marginBottom: '4px' }}>
                      CUSTODIAN SHARE B (e.g. 2-...)
                    </label>
                    <input
                      type="text"
                      className="input-field"
                      placeholder="2-ef01..."
                      value={shareInput2}
                      onChange={(e) => setShareInput2(e.target.value)}
                      required
                    />
                  </div>
                </div>
                <button type="submit" className="btn-primary" disabled={unlocking}>
                  <Unlock size={14} />
                  <span>{unlocking ? 'Reconstructing KEK...' : 'Reconstruct & Unlock KEK'}</span>
                </button>
              </form>
            </div>
          )}

          <div
            style={{
              display: 'flex',
              gap: '16px',
              fontSize: '12px',
              color: 'var(--text-muted)',
              fontFamily: 'var(--font-mono)',
              marginTop: '12px',
              flexWrap: 'wrap',
            }}
          >
            <div>THRESHOLD: <strong style={{ color: '#fff' }}>{keyStatus?.threshold || 2}-of-{keyStatus?.total_shares || 3}</strong></div>
            <div>CURRENT VERSION: <strong style={{ color: 'var(--primary)' }}>v{keyStatus?.current_version || 1}</strong></div>
            <div>STATUS MSG: <span style={{ color: 'var(--text-dim)' }}>{keyStatus?.message || 'Ready'}</span></div>
          </div>
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
