import React, { useEffect, useState } from 'react'
import type { MLJob, UserRole } from '../types'
import { createMLJob, listMLJobs, cancelMLJob } from '../api'
import { Cpu, PlusCircle, AlertCircle, RefreshCw, FolderSearch, Clock, ShieldCheck } from 'lucide-react'

interface MLJobsViewProps {
  currentRole: UserRole
}

export const MLJobsView: React.FC<MLJobsViewProps> = ({ currentRole }) => {
  const [jobs, setJobs] = useState<MLJob[]>([])
  const [loading, setLoading] = useState(true)
  const [purpose, setPurpose] = useState('Train Fashion-MNIST classifier')
  const [datasetScope, setDatasetScope] = useState('fashion_mnist')
  const [requestedView, setRequestedView] = useState('feature_only')
  const [durationHours, setDurationHours] = useState(24)
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadJobs = async () => {
    setLoading(true)
    try {
      const data = await listMLJobs()
      setJobs(data)
    } catch (err: any) {
      setError(err.message || 'Failed to load ML jobs')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadJobs()
  }, [])

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    setCreating(true)
    setError(null)

    try {
      await createMLJob({
        purpose,
        dataset_scope: datasetScope.split(',').map(s => s.trim()).filter(Boolean),
        requested_view: requestedView,
        duration_hours: durationHours,
      })
      await loadJobs()
      setPurpose('')
    } catch (err: any) {
      setError(err.message || 'Failed to create ML job')
    } finally {
      setCreating(false)
    }
  }

  const handleCancel = async (jobId: string) => {
    try {
      await cancelMLJob(jobId)
      await loadJobs()
    } catch (err: any) {
      setError(err.message || 'Failed to cancel ML job')
    }
  }

  return (
    <div className="app-container fade-in">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '28px', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
            <span className="section-label">WORKFLOW ACCESS CONTROL</span>
          </div>
          <h1 className="page-title">ML Job Workflows &amp; Scoping</h1>
          <p className="page-desc">
            Trainers must bind data access to an active, approved, time-bound ML job. Approved jobs receive cryptographically signed manifests.
          </p>
        </div>
        <button className="btn-secondary" onClick={loadJobs} disabled={loading}>
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Job Creation Form (Available to trainer, researcher, and admin) */}
      {['admin', 'trainer', 'researcher'].includes(currentRole) && (
        <div className="double-bezel" style={{ marginBottom: '28px' }}>
          <div className="double-bezel-inner">
            <h2 style={{ fontSize: '15px', fontWeight: 700, marginBottom: '18px', display: 'flex', alignItems: 'center', gap: '8px', color: '#fff' }}>
              <PlusCircle size={16} color="var(--primary)" />
              <span>Create New Scoped ML Job</span>
            </h2>

            <form onSubmit={handleCreate}>
              <div className="grid-2" style={{ marginBottom: '16px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px', fontFamily: 'var(--font-mono)' }}>
                    JOB PURPOSE / OBJECTIVE
                  </label>
                  <input
                    type="text"
                    className="input-field"
                    value={purpose}
                    onChange={(e) => setPurpose(e.target.value)}
                    placeholder="e.g. Train Fashion-MNIST classifier"
                    required
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px', fontFamily: 'var(--font-mono)' }}>
                    DATASET SCOPE (TAG)
                  </label>
                  <input
                    type="text"
                    className="input-field"
                    value={datasetScope}
                    onChange={(e) => setDatasetScope(e.target.value)}
                    placeholder="e.g. fashion_mnist, cifar10"
                    required
                  />
                </div>
              </div>

              <div className="grid-2" style={{ marginBottom: '20px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px', fontFamily: 'var(--font-mono)' }}>
                    REQUESTED DATA VIEW
                  </label>
                  <select
                    className="select-field"
                    value={requestedView}
                    onChange={(e) => setRequestedView(e.target.value)}
                  >
                    <option value="feature_only">feature_only (CNN Embeddings — Recommended)</option>
                    <option value="masked_image">masked_image (Low-Res Pixels)</option>
                    <option value="raw_image">raw_image (Requires explicit justification)</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px', fontFamily: 'var(--font-mono)' }}>
                    EXPIRATION DURATION (HOURS)
                  </label>
                  <input
                    type="number"
                    className="input-field"
                    min={1}
                    max={720}
                    value={durationHours}
                    onChange={(e) => setDurationHours(parseInt(e.target.value) || 24)}
                  />
                </div>
              </div>

              <button type="submit" className="btn-primary" disabled={creating}>
                <Cpu size={15} />
                <span>{creating ? 'Submitting Job...' : 'Submit Job Request'}</span>
              </button>
            </form>
          </div>
        </div>
      )}

      {error && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '12px 16px',
            background: 'var(--danger-bg)',
            border: '1px solid var(--danger-border)',
            borderRadius: '8px',
            color: '#f87171',
            fontSize: '13px',
            marginBottom: '20px',
          }}
        >
          <AlertCircle size={16} />
          <span>{error}</span>
        </div>
      )}

      {/* Jobs Table */}
      <div className="double-bezel">
        <div className="double-bezel-inner">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <div style={{ fontSize: '15px', fontWeight: 700, color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ShieldCheck size={16} color="var(--primary)" />
              <span>Job Registry</span>
            </div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
              {jobs.length} REGISTERED
            </span>
          </div>

          {loading ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', padding: '12px 0' }}>
              <div className="skeleton" style={{ height: '42px', width: '100%' }} />
              <div className="skeleton" style={{ height: '42px', width: '100%' }} />
              <div className="skeleton" style={{ height: '42px', width: '100%' }} />
            </div>
          ) : jobs.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--text-muted)' }}>
              <FolderSearch size={36} color="var(--text-dim)" style={{ margin: '0 auto 12px' }} />
              <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-main)', marginBottom: '4px' }}>
                No active ML jobs found
              </div>
              <p style={{ fontSize: '12px', color: 'var(--text-dim)', maxWidth: '400px', margin: '0 auto' }}>
                Create a scoped ML job above to request access to dataset feature vectors under policy governance.
              </p>
            </div>
          ) : (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>JOB ID</th>
                    <th>PURPOSE</th>
                    <th>SCOPE</th>
                    <th>VIEW</th>
                    <th>STATUS</th>
                    <th>EXPIRES AT</th>
                    <th>ACTION</th>
                  </tr>
                </thead>
                <tbody>
                  {jobs.map((j) => (
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
                        <span
                          style={{
                            fontSize: '10.5px',
                            fontFamily: 'var(--font-mono)',
                            fontWeight: 700,
                            textTransform: 'uppercase',
                            padding: '3px 8px',
                            borderRadius: '5px',
                            background:
                              j.status === 'approved'
                                ? 'var(--success-bg)'
                                : j.status === 'pending'
                                ? 'var(--warning-bg)'
                                : 'var(--danger-bg)',
                            color:
                              j.status === 'approved'
                                ? '#4ade80'
                                : j.status === 'pending'
                                ? '#fbbf24'
                                : '#f87171',
                            border: `1px solid ${
                              j.status === 'approved'
                                ? 'var(--success-border)'
                                : j.status === 'pending'
                                ? 'var(--warning-border)'
                                : 'var(--danger-border)'
                            }`,
                          }}
                        >
                          {j.status}
                        </span>
                      </td>
                      <td style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                          <Clock size={12} color="var(--text-dim)" />
                          <span>{new Date(j.expires_at).toLocaleString()}</span>
                        </div>
                      </td>
                      <td>
                        {['pending', 'approved'].includes(j.status) && (
                          <button
                            className="btn-danger"
                            style={{ padding: '4px 10px', fontSize: '11px' }}
                            onClick={() => handleCancel(j.job_id)}
                          >
                            Cancel
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
