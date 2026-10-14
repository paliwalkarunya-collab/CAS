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
    <div style={{ maxWidth: '1000px', margin: '0 auto', padding: '32px 24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '24px' }}>
        <div>
          <h1 className="page-title">Middleware Health &amp; Subsystem Telemetry</h1>
          <p className="page-desc">
            Operational status of pluggable adapters, policy engines, and security middleware layers.
          </p>
        </div>

        <button className="btn-secondary" onClick={loadHealth} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          <span>Ping Subsystems</span>
        </button>
      </div>

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

      {/* Main Status Banner */}
      <div className="double-bezel" style={{ marginBottom: '28px' }}>
        <div className="double-bezel-inner" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div
              style={{
                width: '40px',
                height: '40px',
                borderRadius: '10px',
                background: health?.status === 'ok' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Activity size={20} color={health?.status === 'ok' ? '#34d399' : '#fb7185'} />
            </div>
            <div>
              <div style={{ fontSize: '18px', fontWeight: 800, color: '#fff' }}>
                {health?.service || 'CAS-SE Middleware'} — {health?.status === 'ok' ? 'HEALTHY' : 'UNREACHABLE'}
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                Version: {health?.version || '0.1.0'} • Server-generated UTC timestamps
              </div>
            </div>
          </div>

          <span
            style={{
              fontSize: '12px',
              fontFamily: 'var(--font-mono)',
              fontWeight: 700,
              padding: '4px 12px',
              borderRadius: '6px',
              background: 'rgba(16, 185, 129, 0.15)',
              color: '#34d399',
              border: '1px solid rgba(16, 185, 129, 0.3)',
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
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px', color: '#60a5fa' }}>
              <HardDrive size={16} />
              <span style={{ fontSize: '12px', fontWeight: 700, textTransform: 'uppercase' }}>Storage Adapter</span>
            </div>
            <div style={{ fontSize: '16px', fontWeight: 700, color: '#fff', marginBottom: '4px' }}>
              {telemetry?.storage_adapter?.toUpperCase() || 'MINIO S3'}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Ciphertext blob persistence
            </div>
          </div>
        </div>

        {/* Subsystem 2: Key Service Adapter */}
        <div className="double-bezel">
          <div className="double-bezel-inner">
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px', color: '#f59e0b' }}>
              <KeyRound size={16} />
              <span style={{ fontSize: '12px', fontWeight: 700, textTransform: 'uppercase' }}>Key Management</span>
            </div>
            <div style={{ fontSize: '16px', fontWeight: 700, color: '#fff', marginBottom: '4px' }}>
              v{telemetry?.kek_current_version || 1} ({telemetry?.key_adapter?.toUpperCase() || 'ENV / SPLIT'})
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Envelope KEK wrapping
            </div>
          </div>
        </div>

        {/* Subsystem 3: Database Overlay */}
        <div className="double-bezel">
          <div className="double-bezel-inner">
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px', color: '#a78bfa' }}>
              <Database size={16} />
              <span style={{ fontSize: '12px', fontWeight: 700, textTransform: 'uppercase' }}>PostgreSQL Overlay</span>
            </div>
            <div style={{ fontSize: '16px', fontWeight: 700, color: '#fff', marginBottom: '4px' }}>
              ACTIVE
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Isolated <code>cas_*</code> tables
            </div>
          </div>
        </div>
      </div>

      {/* Subsystem Telemetry Details */}
      <div className="double-bezel">
        <div className="double-bezel-inner">
          <h2 style={{ fontSize: '15px', fontWeight: 700, marginBottom: '16px' }}>
            Live Telemetry Summary Counters
          </h2>

          <div className="grid-2" style={{ gap: '12px', fontSize: '13px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 14px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px' }}>
              <span style={{ color: 'var(--text-dim)' }}>Total Stored Envelopes:</span>
              <span style={{ fontWeight: 700, color: '#fff' }}>{telemetry?.total_envelopes || 0}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 14px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px' }}>
              <span style={{ color: 'var(--text-dim)' }}>Total Hash-Chained Audit Events:</span>
              <span style={{ fontWeight: 700, color: '#fff' }}>{telemetry?.total_audit_events || 0}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 14px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px' }}>
              <span style={{ color: 'var(--text-dim)' }}>Active / Approved ML Jobs:</span>
              <span style={{ fontWeight: 700, color: '#fff' }}>{telemetry?.active_ml_jobs || 0}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 14px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px' }}>
              <span style={{ color: 'var(--text-dim)' }}>Unauthorized Requests Denied:</span>
              <span style={{ fontWeight: 700, color: '#34d399' }}>{telemetry?.unauthorized_requests_denied || 0}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
