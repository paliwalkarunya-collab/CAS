import React, { useEffect, useState } from 'react'
import type { PolicyItem, UserRole } from '../types'
import { listPolicies, createPolicy } from '../api'
import { Shield, PlusCircle, RefreshCw } from 'lucide-react'

interface PoliciesViewProps {
  currentRole: UserRole
}

export const PoliciesView: React.FC<PoliciesViewProps> = ({ currentRole }) => {
  const [policies, setPolicies] = useState<PolicyItem[]>([])
  const [selectedPolicy, setSelectedPolicy] = useState<PolicyItem | null>(null)
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [newName, setNewName] = useState('')
  const [newDesc, setNewDesc] = useState('')
  const [newRego, setNewRego] = useState(`package cas_se.access

# Default deny
default allow := false

# Allow trainer with approved active job for feature_only view
allow if {
    input.actor_role == "trainer"
    input.requested_view == "feature_only"
    input.job_status == "approved"
    input.job_expired == false
}
`)
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadPolicies = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await listPolicies()
      setPolicies(data)
      if (data.length > 0 && !selectedPolicy) {
        setSelectedPolicy(data[0])
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load policies')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadPolicies()
  }, [])

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    setCreating(true)
    setError(null)
    try {
      const created = await createPolicy({
        name: newName.trim(),
        description: newDesc.trim(),
        rego_policy: newRego,
      })
      setShowCreate(false)
      setNewName('')
      setNewDesc('')
      await loadPolicies()
      setSelectedPolicy(created)
    } catch (err: any) {
      setError(err.message || 'Failed to create policy')
    } finally {
      setCreating(false)
    }
  }

  return (
    <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '32px 24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '24px' }}>
        <div>
          <h1 className="page-title">Open Policy Agent (OPA) Access Policies</h1>
          <p className="page-desc">
            Context-aware ABAC policies written in Rego. Policies evaluate identity, role, purpose, dataset scope, view type, and expiration.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button className="btn-secondary" onClick={loadPolicies} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
          {currentRole === 'admin' && (
            <button className="btn-primary" onClick={() => setShowCreate(!showCreate)}>
              <PlusCircle size={14} />
              <span>{showCreate ? 'Close Form' : 'Register New Policy'}</span>
            </button>
          )}
        </div>
      </div>

      {showCreate && (
        <div className="double-bezel" style={{ marginBottom: '28px' }}>
          <div className="double-bezel-inner">
            <h2 style={{ fontSize: '15px', fontWeight: 700, marginBottom: '16px' }}>New Rego Policy Definition</h2>
            <form onSubmit={handleCreate}>
              <div className="grid-2" style={{ marginBottom: '16px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px' }}>
                    POLICY IDENTIFIER NAME
                  </label>
                  <input
                    type="text"
                    className="input-field"
                    value={newName}
                    onChange={(e) => setNewName(e.target.value)}
                    placeholder="e.g. oncology_imaging_abac"
                    required
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px' }}>
                    DESCRIPTION
                  </label>
                  <input
                    type="text"
                    className="input-field"
                    value={newDesc}
                    onChange={(e) => setNewDesc(e.target.value)}
                    placeholder="e.g. Enforces feature-only views for active biopsy models"
                  />
                </div>
              </div>

              <div style={{ marginBottom: '20px' }}>
                <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px' }}>
                  REGO POLICY CODE
                </label>
                <textarea
                  className="input-field"
                  style={{ minHeight: '180px', fontFamily: 'var(--font-mono)', fontSize: '12px', lineHeight: 1.5 }}
                  value={newRego}
                  onChange={(e) => setNewRego(e.target.value)}
                  required
                />
              </div>

              <button type="submit" className="btn-primary" disabled={creating}>
                <Shield size={14} />
                <span>{creating ? 'Saving Policy...' : 'Save & Publish Policy Version'}</span>
              </button>
            </form>
          </div>
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
          }}
        >
          {error}
        </div>
      )}

      {/* Two Column Layout: Policy List & Rego Code Viewer */}
      <div className="grid-2">
        {/* Left: Policy List */}
        <div className="double-bezel">
          <div className="double-bezel-inner">
            <h2 style={{ fontSize: '15px', fontWeight: 700, marginBottom: '14px' }}>
              Policy Repository ({policies.length})
            </h2>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {policies.map((p) => (
                <div
                  key={p.id}
                  onClick={() => setSelectedPolicy(p)}
                  style={{
                    padding: '12px 16px',
                    borderRadius: '8px',
                    border: `1px solid ${selectedPolicy?.id === p.id ? 'var(--primary)' : 'var(--border-inner)'}`,
                    background: selectedPolicy?.id === p.id ? 'var(--bg-bezel)' : 'rgba(255,255,255,0.02)',
                    cursor: 'pointer',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                  }}
                >
                  <div>
                    <div style={{ fontSize: '13px', fontWeight: 700, color: '#fff' }}>{p.name}</div>
                    <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '2px' }}>
                      Version {p.version} • {new Date(p.created_at).toLocaleDateString()}
                    </div>
                  </div>
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
                    ACTIVE
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right: Rego Source Code Viewer */}
        <div className="double-bezel">
          <div className="double-bezel-inner">
            {selectedPolicy ? (
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                  <div style={{ fontSize: '15px', fontWeight: 700, color: '#fff' }}>
                    {selectedPolicy.name} <span style={{ color: 'var(--text-dim)', fontSize: '12px' }}>(v{selectedPolicy.version})</span>
                  </div>
                  <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
                    {selectedPolicy.id.slice(0, 8)}...
                  </span>
                </div>
                {selectedPolicy.description && (
                  <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '14px' }}>
                    {selectedPolicy.description}
                  </p>
                )}
                <div
                  style={{
                    background: 'var(--bg-canvas)',
                    border: '1px solid var(--border-inner)',
                    borderRadius: '8px',
                    padding: '16px',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '12px',
                    lineHeight: 1.5,
                    color: '#60a5fa',
                    overflowX: 'auto',
                    maxHeight: '400px',
                  }}
                >
                  <pre>{selectedPolicy.rego_policy}</pre>
                </div>
              </div>
            ) : (
              <div style={{ padding: '40px 0', textAlign: 'center', color: 'var(--text-dim)' }}>
                Select a policy on the left to view its Rego source.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
