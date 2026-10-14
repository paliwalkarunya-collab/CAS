import React, { useEffect, useState } from 'react'
import type { TelemetryMetrics, UserRole } from '../types'
import { getMetrics, verifyAuditChain, listAnomalies } from '../api'
import {
  ShieldCheck,
  Lock,
  FileCheck2,
  AlertTriangle,
  Cpu,
  Layers,
  ArrowUpRight,
  CheckCircle2,
  RefreshCw,
} from 'lucide-react'

interface DashboardViewProps {
  currentRole: UserRole
  onNavigate: (tab: any) => void
}

export const DashboardView: React.FC<DashboardViewProps> = ({ currentRole, onNavigate }) => {
  const [telemetry, setTelemetry] = useState<TelemetryMetrics | null>(null)
  const [chainValid, setChainValid] = useState<boolean | null>(null)
  const [unreviewedAnomalies, setUnreviewedAnomalies] = useState<number>(0)
  const [loading, setLoading] = useState<boolean>(true)

  const loadData = async () => {
    setLoading(true)
    try {
      const metricRes = await getMetrics()
      if (metricRes.telemetry) {
        setTelemetry(metricRes.telemetry)
      }

      // Verify chain
      const verifyRes = await verifyAuditChain()
      setChainValid(verifyRes.is_valid)

      // Query anomalies
      if (['admin', 'auditor'].includes(currentRole)) {
        const anomRes = await listAnomalies(false)
        setUnreviewedAnomalies(anomRes.length)
      }
    } catch {
      // Fallback
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [currentRole])

  return (
    <div style={{ maxWidth: '1280px', margin: '0 auto', padding: '32px 24px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '28px' }}>
        <div>
          <h1 className="page-title">Middleware Telemetry & Governance Status</h1>
          <p className="page-desc">
            Operational dashboard monitoring context-aware policy enforcement, envelope storage, and tamper-evident auditing.
          </p>
        </div>
        <button className="btn-secondary" onClick={loadData} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          <span>Refresh Telemetry</span>
        </button>
      </div>

      {/* Primary Telemetry Grid */}
      <div className="grid-4" style={{ marginBottom: '28px' }}>
        {/* Card 1: Envelopes */}
        <div className="double-bezel">
          <div className="double-bezel-inner">
            <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-dim)', marginBottom: '8px' }}>
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>ENCRYPTED ENVELOPES</span>
              <Lock size={16} color="#60a5fa" />
            </div>
            <div style={{ fontSize: '28px', fontWeight: 800, color: '#fff', marginBottom: '4px' }}>
              {telemetry ? telemetry.total_envelopes : '--'}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              AES-256-GCM blobs in {telemetry?.storage_adapter?.toUpperCase() || 'OBJECT STORAGE'}
            </div>
          </div>
        </div>

        {/* Card 2: Audit Trail */}
        {/* Card 2: Audit Integrity */}
        <div
          className="double-bezel"
          style={{ cursor: 'pointer' }}
          onClick={() => onNavigate('audit_verify')}
          title="Inspect and Verify Cryptographic Audit Chain"
        >
          <div className="double-bezel-inner">
            <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-dim)', marginBottom: '8px' }}>
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>AUDIT CHAIN INTEGRITY</span>
              <FileCheck2 size={16} color="#34d399" />
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
              <span style={{ fontSize: '28px', fontWeight: 800, color: '#fff' }}>
                {telemetry ? telemetry.total_audit_events : '--'}
              </span>
              {chainValid !== null && (
                <span
                  style={{
                    fontSize: '11px',
                    fontWeight: 700,
                    padding: '2px 8px',
                    borderRadius: '4px',
                    background: chainValid ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)',
                    color: chainValid ? '#34d399' : '#fb7185',
                    border: `1px solid ${chainValid ? 'rgba(16, 185, 129, 0.3)' : 'rgba(244, 63, 94, 0.3)'}`,
                  }}
                >
                  {chainValid ? 'INTACT' : 'TAMPERED'}
                </span>
              )}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>HMAC-SHA-256 hash linked • Click to verify</div>
          </div>
        </div>

        {/* Card 3: Active ML Jobs */}
        <div className="double-bezel">
          <div className="double-bezel-inner">
            <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-dim)', marginBottom: '8px' }}>
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>ACTIVE ML JOBS</span>
              <Cpu size={16} color="#a78bfa" />
            </div>
            <div style={{ fontSize: '28px', fontWeight: 800, color: '#fff', marginBottom: '4px' }}>
              {telemetry ? telemetry.active_ml_jobs : '--'}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Approved, scoped &amp; time-bound</div>
          </div>
        </div>

        {/* Card 4: Anomaly Alerts */}
        <div className="double-bezel">
          <div className="double-bezel-inner">
            <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-dim)', marginBottom: '8px' }}>
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>ANOMALY ALERTS</span>
              <AlertTriangle size={16} color="#fbbf24" />
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
              <span style={{ fontSize: '28px', fontWeight: 800, color: '#fff' }}>
                {telemetry ? telemetry.total_anomalies : '--'}
              </span>
              {unreviewedAnomalies > 0 && (
                <span
                  style={{
                    fontSize: '11px',
                    fontWeight: 700,
                    padding: '2px 8px',
                    borderRadius: '4px',
                    background: 'rgba(245, 158, 11, 0.15)',
                    color: '#fbbf24',
                    border: '1px solid rgba(245, 158, 11, 0.3)',
                  }}
                >
                  {unreviewedAnomalies} NEW
                </span>
              )}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>IsolationForest audit heuristics</div>
          </div>
        </div>
      </div>

      {/* Two Column Layout: Architecture Invariants & Quick Actions */}
      <div className="grid-2">
        {/* Architecture Security Invariants */}
        <div className="double-bezel">
          <div className="double-bezel-inner">
            <h2 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ShieldCheck size={18} color="#34d399" />
              <span>Core Security Invariants</span>
            </h2>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div style={{ display: 'flex', gap: '12px' }}>
                <CheckCircle2 size={16} color="#34d399" style={{ flexShrink: 0, marginTop: '2px' }} />
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: '#fff' }}>Zero Plaintext in PostgreSQL</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    Payloads are strictly stored as AES-256-GCM ciphertext in object storage with randomized keys.
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '12px' }}>
                <CheckCircle2 size={16} color="#34d399" style={{ flexShrink: 0, marginTop: '2px' }} />
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: '#fff' }}>Fail-Closed OPA Policy Enforcement</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    Every access request verifies identity, purpose, view type, and job state. OPA downtime = immediate deny.
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '12px' }}>
                <CheckCircle2 size={16} color="#34d399" style={{ flexShrink: 0, marginTop: '2px' }} />
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: '#fff' }}>Data Minimization by Default</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    ML trainers receive compact 64-dim CNN feature vectors. Raw image access is blocked by policy.
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '12px' }}>
                <CheckCircle2 size={16} color="#34d399" style={{ flexShrink: 0, marginTop: '2px' }} />
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: '#fff' }}>Key Rotation Without Payload Re-encryption</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    Active KEK Version is <strong>v{telemetry?.kek_current_version || 1}</strong>. Rotating wrapping keys only rewraps DEKs in milliseconds.
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Quick Governance Actions */}
        <div className="double-bezel">
          <div className="double-bezel-inner">
            <h2 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Layers size={18} color="#60a5fa" />
              <span>Quick Navigation</span>
            </h2>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              <button
                className="btn-secondary"
                style={{ justifyContent: 'space-between', padding: '12px 16px' }}
                onClick={() => onNavigate('upload')}
              >
                <span>Upload Encrypted Dataset Record</span>
                <ArrowUpRight size={14} color="var(--text-dim)" />
              </button>

              <button
                className="btn-secondary"
                style={{ justifyContent: 'space-between', padding: '12px 16px' }}
                onClick={() => onNavigate('search')}
              >
                <span>Execute Protected Equality Search</span>
                <ArrowUpRight size={14} color="var(--text-dim)" />
              </button>

              <button
                className="btn-secondary"
                style={{ justifyContent: 'space-between', padding: '12px 16px' }}
                onClick={() => onNavigate('access')}
              >
                <span>Test Context-Aware Access Request</span>
                <ArrowUpRight size={14} color="var(--text-dim)" />
              </button>

              <button
                className="btn-secondary"
                style={{ justifyContent: 'space-between', padding: '12px 16px' }}
                onClick={() => onNavigate('benchmarks')}
              >
                <span>Inspect Privacy vs. Utility Benchmarks</span>
                <ArrowUpRight size={14} color="var(--text-dim)" />
              </button>

              <button
                className="btn-secondary"
                style={{ justifyContent: 'space-between', padding: '12px 16px' }}
                onClick={() => onNavigate('audit_verify')}
              >
                <span>Run Cryptographic Audit-Chain Verifier</span>
                <ArrowUpRight size={14} color="var(--text-dim)" />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
