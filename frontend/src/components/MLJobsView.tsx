import React, { useEffect, useState } from 'react'
import type { MLJob, UserRole } from '../types'
import { createMLJob, listMLJobs, cancelMLJob } from '../api'
import { Cpu, PlusCircle, AlertCircle, RefreshCw } from 'lucide-react'

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
        dataset_scope: datasetScope,
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
    <div style={{ maxWidth: '1100px', margin: '0 auto', padding: '32px 24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '24px' }}>
        <div>
          <h1 className="page-title">ML Job Workflows &amp; Scoping</h1>
          <p className="page-desc">
            Trainers must bind data access to an active, approved, time-bound ML job. Approved jobs receive cryptographically signed manifests.
          </p>
        </div>
        <button className="btn-secondary" onClick={loadJobs} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Job Creation Form (Available to trainer and admin) */}
      {['admin', 'trainer'].includes(currentRole) && (
        <div className="double-bezel" style={{ marginBottom: '28px' }}>
          <div className="double-bezel-inner">
            <h2 style={{ fontSize: '15px', fontWeight: 700, marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <PlusCircle size={16} color="var(--primary)" />
              <span>Create New Scoped ML Job</span>
            </h2>

            <form onSubmit={handleCreate}>
              <div className="grid-2" style={{ marginBottom: '16px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px' }}>
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
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px' }}>
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

              <div className="grid-2" style={{ marginBottom: '18px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px' }}>
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
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px' }}>
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
                <Cpu size={16} />
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
            background: 'rgba(244, 63, 94, 0.12)',
            border: '1px solid rgba(244, 63, 94, 0.3)',
            borderRadius: '6px',
            color: '#fb7185',
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
          <div style={{ fontSize: '15px', fontWeight: 700, color: '#fff', marginBottom: '16px' }}>
            Job Registry ({jobs.length} jobs)
          </div>

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
                  <tr key={j.id}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: '#fff' }}>
                      {j.id.slice(0, 8)}...
                    </td>
                    <td style={{ fontWeight: 600 }}>{j.purpose}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: '#60a5fa' }}>{j.dataset_scope}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{j.requested_view}</td>
                    <td>
                      <span
                        style={{
                          fontSize: '11px',
                          fontWeight: 700,
                          textTransform: 'uppercase',
                          padding: '3px 8px',
                          borderRadius: '4px',
                          background:
                            j.status === 'approved'
                              ? 'rgba(16, 185, 129, 0.15)'
                              : j.status === 'pending'
                              ? 'rgba(245, 158, 11, 0.15)'
                              : 'rgba(244, 63, 94, 0.15)',
                          color:
                            j.status === 'approved'
                              ? '#34d399'
                              : j.status === 'pending'
                              ? '#fbbf24'
                              : '#fb7185',
                        }}
                      >
                        {j.status}
                      </span>
                    </td>
                    <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      {new Date(j.expires_at).toLocaleString()}
                    </td>
                    <td>
                      {['pending', 'approved'].includes(j.status) && (
                        <button
                          className="btn-secondary"
                          style={{ padding: '4px 10px', fontSize: '11px' }}
                          onClick={() => handleCancel(j.id)}
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
        </div>
      </div>
    </div>
  )
}
