import React, { useState } from 'react'
import type { SearchResultItem } from '../types'
import { searchEnvelopes } from '../api'
import { Search, KeyRound, Shield, AlertCircle, FileSearch } from 'lucide-react'

interface SearchViewProps {
  onRequestAccess: (envelopeId: string) => void
}

export const SearchView: React.FC<SearchViewProps> = ({ onRequestAccess }) => {
  const [field, setField] = useState<'dataset_id' | 'subject_id'>('dataset_id')
  const [value, setValue] = useState('fashion_mnist')
  const [searching, setSearching] = useState(false)
  const [results, setResults] = useState<SearchResultItem[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!value.trim()) return

    setSearching(true)
    setError(null)
    setResults(null)

    try {
      const res = await searchEnvelopes(field, value.trim())
      setResults(res)
    } catch (err: any) {
      setError(err.message || 'Protected search failed')
    } finally {
      setSearching(false)
    }
  }

  return (
    <div className="app-container fade-in">
      <div style={{ marginBottom: '28px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
          <span className="section-label">ZERO-KNOWLEDGE INDEXING</span>
        </div>
        <h1 className="page-title">Protected Equality Search</h1>
        <p className="page-desc">
          Search operations utilize <strong>HMAC-SHA-256 blind equality tokens</strong>. Plaintext identifiers are never stored or queried in plaintext database index tables.
        </p>
      </div>

      {/* Search Input Box */}
      <div className="double-bezel" style={{ marginBottom: '28px' }}>
        <div className="double-bezel-inner">
          <form onSubmit={handleSearch}>
            <div style={{ display: 'flex', gap: '14px', alignItems: 'flex-end', flexWrap: 'wrap' }}>
              <div style={{ width: '220px' }}>
                <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px', fontFamily: 'var(--font-mono)' }}>
                  SEARCH INDEX FIELD
                </label>
                <select
                  className="select-field"
                  value={field}
                  onChange={(e) => setField(e.target.value as any)}
                >
                  <option value="dataset_id">dataset_id</option>
                  <option value="subject_id">subject_id</option>
                </select>
              </div>

              <div style={{ flex: 1, minWidth: '280px' }}>
                <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px', fontFamily: 'var(--font-mono)' }}>
                  TERM / IDENTIFIER (EXACT MATCH)
                </label>
                <input
                  type="text"
                  className="input-field"
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                  placeholder="e.g. fashion_mnist, subject-001"
                  required
                />
              </div>

              <button type="submit" className="btn-primary" disabled={searching} style={{ height: '40px' }}>
                <Search size={15} />
                <span>{searching ? 'Computing HMAC...' : 'Search Index'}</span>
              </button>
            </div>
          </form>

          {/* Cryptographic explanation footnote */}
          <div
            style={{
              marginTop: '16px',
              padding: '12px 16px',
              background: 'var(--bg-canvas)',
              border: '1px solid var(--border-inner)',
              borderRadius: '7px',
              fontSize: '12px',
              color: 'var(--text-muted)',
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
            }}
          >
            <Shield size={16} color="var(--primary)" style={{ flexShrink: 0 }} />
            <span>
              Query Token: <code style={{ color: 'var(--primary)', fontFamily: 'var(--font-mono)' }}>token = HMAC-SHA-256(index_key, normalize("{value}"))</code>. Matching occurs blindly without exposing raw terms to unauthorized observers.
            </span>
          </div>
        </div>
      </div>

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

      {/* Results */}
      {results !== null && (
        <div className="double-bezel">
          <div className="double-bezel-inner">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div style={{ fontSize: '15px', fontWeight: 700, color: '#fff' }}>
                Search Results ({results.length} encrypted {results.length === 1 ? 'envelope' : 'envelopes'} found)
              </div>
            </div>

            {results.length === 0 ? (
              <div style={{ padding: '36px 0', textAlign: 'center', color: 'var(--text-dim)' }}>
                <FileSearch size={32} style={{ margin: '0 auto 10px', opacity: 0.5 }} />
                <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-main)', marginBottom: '4px' }}>No envelopes matched this token</div>
                <p style={{ fontSize: '12px' }}>Verify the exact dataset or subject ID and try again.</p>
              </div>
            ) : (
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>ENVELOPE ID</th>
                      <th>SENSITIVITY CLASSIFICATION</th>
                      <th>ACTION</th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.map((r) => (
                      <tr key={r.envelope_id}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: '#fff' }}>
                          {r.envelope_id}
                        </td>
                        <td>
                          <span
                            style={{
                              fontSize: '10.5px',
                              fontFamily: 'var(--font-mono)',
                              fontWeight: 700,
                              textTransform: 'uppercase',
                              padding: '3px 8px',
                              borderRadius: '5px',
                              background: 'var(--warning-bg)',
                              color: '#fbbf24',
                              border: '1px solid var(--warning-border)',
                            }}
                          >
                            {r.sensitivity_label || 'RESTRICTED'}
                          </span>
                        </td>
                        <td>
                          <button
                            className="btn-secondary"
                            style={{ padding: '5px 12px', fontSize: '12px' }}
                            onClick={() => onRequestAccess(r.envelope_id)}
                          >
                            <KeyRound size={13} color="var(--primary)" />
                            <span>Request Access</span>
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
