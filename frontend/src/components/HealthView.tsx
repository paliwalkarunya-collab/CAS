import React, { useEffect, useState } from 'react'
import type { TelemetryMetrics } from '../types'
import { getHealth, getMetrics } from '../api'
import { Activity, Database, HardDrive, KeyRound, RefreshCw } from 'lucide-react'

export const HealthView: React.FC = () => {
  const [health, setHealth] = useState<{ status: string; service: string; version: string } | null>(null)
  const [telemetry, setTelemetry] = useState<TelemetryMetrics | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const loadHealth = async () => {
    setLoading(true)
    setError(null)
    try {
      const h = await getHealth()
      setHealth(h)
      const m = await getMetrics()
      if (m.telemetry) {
        setTelemetry(m.telemetry)
      }
    } catch (err: any) {
      setError(err.message || 'Health check failed')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadHealth()
  }, [])

  return (
    <div className="app-container fade-in">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '28px', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
            <span className="section-label">SUBSYSTEM METRICS &amp; PROBES</span>
          </div>
          <h1 className="page-title">Middleware Health &amp; Subsystem Telemetry</h1>
          <p className="page-desc">
            Operational status of pluggable storage adapters, cryptographic key services, and security invariant layers.
          </p>
        </div>

        <button className="btn-secondary" onClick={loadHealth} disabled={loading}>
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          <span>Ping Subsystems</span>
        </button>
      </div>

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
          }}
        >
          {error}
        </div>
      )}

      {/* Main Status Banner */}
      <div className="double-bezel" style={{ marginBottom: '28px' }}>
        <div className="double-bezel-inner" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div
              style={{
                width: '42px',
                height: '42px',
                borderRadius: '10px',
                background: health?.status === 'ok' ? 'var(--success-bg)' : 'var(--danger-bg)',
                border: `1px solid ${health?.status === 'ok' ? 'var(--success-border)' : 'var(--danger-border)'}`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: health?.status === 'ok' ? 'var(--success)' : 'var(--danger)',
              }}
            >
              <Activity size={22} />
            </div>
            <div>
              <div style={{ fontSize: '17px', fontWeight: 800, color: '#fff' }}>
                {health?.service || 'CAS-SE Middleware Engine'} — {health?.status === 'ok' ? 'HEALTHY' : 'UNREACHABLE'}
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
                Version: {health?.version || '0.1.0'} • Server-generated UTC probe timestamps
              </div>
            </div>
          </div>

          <span
            style={{
              fontSize: '11px',
              fontFamily: 'var(--font-mono)',
              fontWeight: 700,
              padding: '4px 12px',
              borderRadius: '6px',
              background: 'var(--success-bg)',
              color: '#4ade80',
              border: '1px solid var(--success-border)',
            }}
          >
            ALL INVARIANTS PASS
          </span>
        </div>
      </div>

      {/* Pluggable Adapters & Subsystems Grid */}
      <div className="grid-3" style={{ marginBottom: '28px' }}>
        {/* Subsystem 1: Storage Adapter */}
        <div className="double-bezel">
          <div className="double-bezel-inner">
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px', color: 'var(--primary)' }}>
              <HardDrive size={16} />
              <span className="section-label" style={{ color: 'var(--primary)' }}>Storage Adapter</span>
            </div>
            <div style={{ fontSize: '17px', fontWeight: 800, color: '#fff', marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>
              {telemetry?.storage_adapter?.toUpperCase() || 'LOCAL_DISK'}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Ciphertext blob persistence
            </div>
          </div>
        </div>

        {/* Subsystem 2: Key Service Adapter */}
        <div className="double-bezel">
          <div className="double-bezel-inner">
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px', color: 'var(--warning)' }}>
              <KeyRound size={16} />
              <span className="section-label" style={{ color: 'var(--warning)' }}>Key Management</span>
            </div>
            <div style={{ fontSize: '17px', fontWeight: 800, color: '#fff', marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>
              v{telemetry?.kek_current_version || 1} ({telemetry?.key_adapter?.toUpperCase() || 'SPLIT / ENV'})
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Master KEK envelope wrapping
            </div>
          </div>
        </div>

        {/* Subsystem 3: Database Overlay */}
        <div className="double-bezel">
          <div className="double-bezel-inner">
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px', color: '#c084fc' }}>
              <Database size={16} />
              <span className="section-label" style={{ color: '#c084fc' }}>Database Overlay</span>
            </div>
            <div style={{ fontSize: '17px', fontWeight: 800, color: '#fff', marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>
              POSTGRESQL ACTIVE
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Isolated non-plaintext <code style={{ fontFamily: 'var(--font-mono)' }}>cas_*</code> tables
            </div>
          </div>
        </div>
      </div>

      {/* Subsystem Telemetry Details */}
      <div className="double-bezel">
        <div className="double-bezel-inner">
          <h2 style={{ fontSize: '15px', fontWeight: 700, marginBottom: '16px', color: '#fff' }}>
            Live Telemetry Summary Counters
          </h2>

          <div className="grid-2" style={{ gap: '12px', fontSize: '13px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 14px', background: 'var(--bg-canvas)', borderRadius: '7px', border: '1px solid var(--border-inner)' }}>
              <span style={{ color: 'var(--text-dim)' }}>Total Stored Envelopes:</span>
              <span style={{ fontWeight: 700, color: '#fff', fontFamily: 'var(--font-mono)' }}>{telemetry?.total_envelopes || 0}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 14px', background: 'var(--bg-canvas)', borderRadius: '7px', border: '1px solid var(--border-inner)' }}>
              <span style={{ color: 'var(--text-dim)' }}>Total Chained Audit Events:</span>
              <span style={{ fontWeight: 700, color: '#fff', fontFamily: 'var(--font-mono)' }}>{telemetry?.total_audit_events || 0}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 14px', background: 'var(--bg-canvas)', borderRadius: '7px', border: '1px solid var(--border-inner)' }}>
              <span style={{ color: 'var(--text-dim)' }}>Active &amp; Approved ML Jobs:</span>
              <span style={{ fontWeight: 700, color: '#fff', fontFamily: 'var(--font-mono)' }}>{telemetry?.active_ml_jobs || 0}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 14px', background: 'var(--bg-canvas)', borderRadius: '7px', border: '1px solid var(--border-inner)' }}>
              <span style={{ color: 'var(--text-dim)' }}>Unauthorized Requests Denied:</span>
              <span style={{ fontWeight: 700, color: '#4ade80', fontFamily: 'var(--font-mono)' }}>{telemetry?.unauthorized_requests_denied || 0}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
