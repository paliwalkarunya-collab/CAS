import React, { useEffect, useState } from 'react'
import type { PolicyItem, UserRole } from '../types'
import { listPolicies, createPolicy } from '../api'
import { Shield, PlusCircle, RefreshCw, FileCode } from 'lucide-react'

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
  }, [currentRole])

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
    <div className="app-container fade-in">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '28px', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
            <span className="section-label">DECLARATIVE ACCESS RULES</span>
          </div>
          <h1 className="page-title">Open Policy Agent (OPA) Access Policies</h1>
          <p className="page-desc">
            Context-aware ABAC policies declared in Rego. Policies evaluate subject identity, role, purpose, dataset scope, representation view, and job expiration.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button className="btn-secondary" onClick={loadPolicies} disabled={loading}>
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
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
            <h2 style={{ fontSize: '15px', fontWeight: 700, marginBottom: '18px', color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <FileCode size={16} color="var(--primary)" />
              <span>New Rego Policy Definition</span>
            </h2>
            <form onSubmit={handleCreate}>
              <div className="grid-2" style={{ marginBottom: '16px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px', fontFamily: 'var(--font-mono)' }}>
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
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px', fontFamily: 'var(--font-mono)' }}>
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
                <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px', fontFamily: 'var(--font-mono)' }}>
                  REGO POLICY CODE
                </label>
                <textarea
                  className="input-field"
                  style={{ minHeight: '180px', fontFamily: 'var(--font-mono)', fontSize: '12px', lineHeight: 1.6 }}
                  value={newRego}
                  onChange={(e) => setNewRego(e.target.value)}
                  required
                />
              </div>

              <button type="submit" className="btn-primary" disabled={creating}>
                <Shield size={14} />
                <span>{creating ? 'Publishing Policy...' : 'Save & Publish Policy Version'}</span>
              </button>
            </form>
          </div>
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
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <span style={{ fontSize: '14px', fontWeight: 700, color: '#fff' }}>Policy Repository</span>
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
                {policies.length} POLICIES
              </span>
            </div>

            {loading ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', padding: '12px 0' }}>
                <div className="skeleton" style={{ height: '52px', width: '100%' }} />
                <div className="skeleton" style={{ height: '52px', width: '100%' }} />
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {policies.length === 0 && !loading && (
                  <div style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-dim)', fontSize: '13px' }}>
                    No access policies found.
                  </div>
                )}
                {policies.map((p) => {
                  const policyId = p.policy_id || p.id || p.name
                  const selectedId = selectedPolicy?.policy_id || selectedPolicy?.id || selectedPolicy?.name || ''
                  const isSelected = selectedId === policyId
                  const version = p.version ?? p.latest_version ?? 1
                  return (
                    <div
                      key={policyId}
                      onClick={() => setSelectedPolicy(p)}
                      style={{
                        padding: '12px 16px',
                        borderRadius: '8px',
                        border: isSelected ? '1px solid var(--primary-border)' : '1px solid var(--border-inner)',
                        background: isSelected ? 'var(--primary-bg)' : 'var(--bg-canvas)',
                        cursor: 'pointer',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        transition: 'all 0.16s ease',
                      }}
                    >
                      <div>
                        <div style={{ fontSize: '13.5px', fontWeight: 700, color: '#fff' }}>{p.name}</div>
                        <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
                          Version {version} • {p.created_at ? new Date(p.created_at).toLocaleDateString() : 'Active'}
                        </div>
                      </div>
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
                        ACTIVE
                      </span>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </div>

        {/* Right: Rego Source Code Viewer */}
        <div className="double-bezel">
          <div className="double-bezel-inner">
            {selectedPolicy ? (() => {
              const selectedId = selectedPolicy.policy_id || selectedPolicy.id || ''
              const version = selectedPolicy.version ?? selectedPolicy.latest_version ?? 1
              return (
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                    <div style={{ fontSize: '15px', fontWeight: 700, color: '#fff' }}>
                      {selectedPolicy.name}{' '}
                      <span style={{ color: 'var(--primary)', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                        (v{version})
                      </span>
                    </div>
                    <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
                      ID: {selectedId ? selectedId.slice(0, 8) : 'active'}...
                    </span>
                  </div>
                  {selectedPolicy.description && (
                    <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '14px', lineHeight: 1.5 }}>
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
                      lineHeight: 1.6,
                      color: 'var(--primary)',
                      overflowX: 'auto',
                      maxHeight: '400px',
                    }}
                  >
                    <pre>{selectedPolicy.rego_policy}</pre>
                  </div>
                </div>
              )
            })() : (
              <div style={{ padding: '40px 0', textAlign: 'center', color: 'var(--text-dim)', fontSize: '13px' }}>
                Select a policy on the left to inspect its active Rego definition.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
