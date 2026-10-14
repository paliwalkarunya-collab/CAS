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
    <div style={{ maxWidth: '1000px', margin: '0 auto', padding: '32px 24px' }}>
      <h1 className="page-title">Protected Equality Search</h1>
      <p className="page-desc">
        Search operations use <strong>HMAC-SHA-256 protected equality tokens</strong>. Search terms are normalized and transformed
        into cryptographically blind tokens. Plaintext identifiers are <strong>never stored in database index tables</strong>.
      </p>

      {/* Search Input Box */}
      <div className="double-bezel" style={{ marginBottom: '28px' }}>
        <div className="double-bezel-inner">
          <form onSubmit={handleSearch}>
            <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-end', flexWrap: 'wrap' }}>
              <div style={{ width: '200px' }}>
                <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px' }}>
                  SEARCH FIELD
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

              <div style={{ flex: 1, minWidth: '260px' }}>
                <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px' }}>
                  SEARCH VALUE (EXACT MATCH)
                </label>
                <input
                  type="text"
                  className="input-field"
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                  placeholder="e.g. fashion_mnist, patient-101"
                  required
                />
              </div>

              <button type="submit" className="btn-primary" disabled={searching} style={{ height: '42px' }}>
                <Search size={16} />
                <span>{searching ? 'Computing HMAC...' : 'Search'}</span>
              </button>
            </div>
          </form>

          {/* Cryptographic explanation footnote */}
          <div
            style={{
              marginTop: '16px',
              padding: '12px 14px',
              background: 'rgba(59, 130, 246, 0.06)',
              border: '1px solid rgba(59, 130, 246, 0.15)',
              borderRadius: '6px',
              fontSize: '12px',
              color: 'var(--text-muted)',
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
            }}
          >
            <Shield size={16} color="#60a5fa" style={{ flexShrink: 0 }} />
            <span>
              Query flow: <code>token = HMAC-SHA-256(index_key, normalize("{value}"))</code>. Matches records without revealing the query text to unauthorized observers.
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

      {/* Results */}
      {results !== null && (
        <div className="double-bezel">
          <div className="double-bezel-inner">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div style={{ fontSize: '15px', fontWeight: 700, color: '#fff' }}>
                Search Results ({results.length} envelopes found)
              </div>
            </div>

            {results.length === 0 ? (
              <div style={{ padding: '32px 0', textAlign: 'center', color: 'var(--text-dim)' }}>
                <FileSearch size={32} style={{ margin: '0 auto 10px', opacity: 0.5 }} />
                <div>No matching encrypted envelopes found for this search token.</div>
              </div>
            ) : (
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>ENVELOPE ID</th>
                      <th>SENSITIVITY</th>
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
                              fontSize: '11px',
                              fontWeight: 700,
                              textTransform: 'uppercase',
                              padding: '2px 8px',
                              borderRadius: '4px',
                              background: 'rgba(245, 158, 11, 0.15)',
                              color: '#fbbf24',
                            }}
                          >
                            {r.sensitivity_label || 'RESTRICTED'}
                          </span>
                        </td>
                        <td>
                          <button
                            className="btn-secondary"
                            style={{ padding: '6px 12px', fontSize: '12px' }}
                            onClick={() => onRequestAccess(r.envelope_id)}
                          >
                            <KeyRound size={13} />
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
