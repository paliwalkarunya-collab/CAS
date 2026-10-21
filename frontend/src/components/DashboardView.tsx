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
  KeyRound,
  Database,
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
    <div className="app-container fade-in">
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '28px', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
            <span className="section-label">TELEMETRY &amp; SURFACES</span>
            <span style={{ color: 'var(--text-dim)' }}>/</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--success)' }} />
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--success)' }}>ONLINE</span>
            </div>
          </div>
          <h1 className="page-title">Middleware Telemetry &amp; Governance Status</h1>
          <p className="page-desc">
            Context-aware policy enforcement, AES-256-GCM envelope storage, and tamper-evident HMAC audit verification.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button className="btn-secondary" onClick={loadData} disabled={loading}>
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Primary Telemetry Grid: Asymmetric Layout */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '16px', marginBottom: '28px' }}>
        {/* Card 1: Envelopes (Span 4) */}
        <div className="double-bezel" style={{ gridColumn: 'span 4' }}>
          <div className="double-bezel-inner" style={{ height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <span className="section-label">ENCRYPTED ENVELOPES</span>
                <div style={{ padding: '6px', borderRadius: '6px', background: 'var(--primary-bg)', color: 'var(--primary)' }}>
                  <Lock size={15} />
                </div>
              </div>

              {loading && !telemetry ? (
                <div className="skeleton" style={{ height: '36px', width: '90px', marginBottom: '8px' }} />
              ) : (
                <div style={{ fontSize: '32px', fontWeight: 800, color: '#fff', marginBottom: '6px', fontFamily: 'var(--font-mono)', letterSpacing: '-0.03em' }}>
                  {telemetry ? telemetry.total_envelopes : '0'}
                </div>
              )}

              <div style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                AES-256-GCM encrypted payloads stored with randomized DEKs.
              </div>
            </div>

            <div style={{ marginTop: '16px', paddingTop: '12px', borderTop: '1px solid var(--border-inner)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
                <Database size={12} />
                <span>ADAPTER</span>
              </div>
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--primary)', fontWeight: 600 }}>
                {telemetry?.storage_adapter?.toUpperCase() || 'LOCAL_DISK'}
              </span>
            </div>
          </div>
        </div>

        {/* Card 2: Audit Integrity (Span 4) */}
        <div
          className="double-bezel"
          style={{ gridColumn: 'span 4', cursor: 'pointer' }}
          onClick={() => onNavigate('audit_verify')}
          title="Inspect and Verify Cryptographic Audit Chain"
        >
          <div className="double-bezel-inner" style={{ height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <span className="section-label">AUDIT CHAIN INTEGRITY</span>
                <div style={{ padding: '6px', borderRadius: '6px', background: chainValid ? 'var(--success-bg)' : 'var(--danger-bg)', color: chainValid ? 'var(--success)' : 'var(--danger)' }}>
                  <FileCheck2 size={15} />
                </div>
              </div>

              {loading && !telemetry ? (
                <div className="skeleton" style={{ height: '36px', width: '90px', marginBottom: '8px' }} />
              ) : (
                <div style={{ display: 'flex', alignItems: 'baseline', gap: '10px', marginBottom: '6px' }}>
                  <span style={{ fontSize: '32px', fontWeight: 800, color: '#fff', fontFamily: 'var(--font-mono)', letterSpacing: '-0.03em' }}>
                    {telemetry ? telemetry.total_audit_events : '0'}
                  </span>
                  {chainValid !== null && (
                    <span
                      style={{
                        fontSize: '10.5px',
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                        padding: '2px 8px',
                        borderRadius: '4px',
                        background: chainValid ? 'var(--success-bg)' : 'var(--danger-bg)',
                        color: chainValid ? 'var(--success)' : 'var(--danger)',
                        border: `1px solid ${chainValid ? 'var(--success-border)' : 'var(--danger-border)'}`,
                      }}
                    >
                      {chainValid ? 'VERIFIED' : 'TAMPERED'}
                    </span>
                  )}
                </div>
              )}

              <div style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                Cryptographic SHA-256 HMAC hash chain. Zero unverified log mutations.
              </div>
            </div>

            <div style={{ marginTop: '16px', paddingTop: '12px', borderTop: '1px solid var(--border-inner)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>CLICK TO VERIFY CHAIN</span>
              <ArrowUpRight size={13} color="var(--primary)" />
            </div>
          </div>
        </div>

        {/* Card 3: Active ML Jobs (Span 2) */}
        <div className="double-bezel" style={{ gridColumn: 'span 2' }}>
          <div className="double-bezel-inner" style={{ height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <span className="section-label">ML JOBS</span>
                <Cpu size={15} color="var(--primary)" />
              </div>
              {loading && !telemetry ? (
                <div className="skeleton" style={{ height: '36px', width: '60px', marginBottom: '8px' }} />
              ) : (
                <div style={{ fontSize: '32px', fontWeight: 800, color: '#fff', marginBottom: '6px', fontFamily: 'var(--font-mono)' }}>
                  {telemetry ? telemetry.active_ml_jobs : '0'}
                </div>
              )}
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Scoped manifests</div>
            </div>

            <div style={{ marginTop: '16px', paddingTop: '12px', borderTop: '1px solid var(--border-inner)' }}>
              <span style={{ fontSize: '10.5px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>BOUND WORKFLOWS</span>
            </div>
          </div>
        </div>

        {/* Card 4: Anomalies (Span 2) */}
        <div className="double-bezel" style={{ gridColumn: 'span 2' }}>
          <div className="double-bezel-inner" style={{ height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <span className="section-label">ANOMALIES</span>
                <AlertTriangle size={15} color="var(--warning)" />
              </div>
              {loading && !telemetry ? (
                <div className="skeleton" style={{ height: '36px', width: '60px', marginBottom: '8px' }} />
              ) : (
                <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px', marginBottom: '6px' }}>
                  <span style={{ fontSize: '32px', fontWeight: 800, color: '#fff', fontFamily: 'var(--font-mono)' }}>
                    {telemetry ? telemetry.total_anomalies : '0'}
                  </span>
                  {unreviewedAnomalies > 0 && (
                    <span style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--warning)' }}>
                      +{unreviewedAnomalies} NEW
                    </span>
                  )}
                </div>
              )}
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>IsolationForest</div>
            </div>

            <div style={{ marginTop: '16px', paddingTop: '12px', borderTop: '1px solid var(--border-inner)' }}>
              <span style={{ fontSize: '10.5px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>HEURISTICS CHECK</span>
            </div>
          </div>
        </div>
      </div>

      {/* Two Column Layout: Architecture Invariants & Quick Actions */}
      <div className="grid-2">
        {/* Architecture Security Invariants */}
        <div className="double-bezel">
          <div className="double-bezel-inner">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
              <h2 style={{ fontSize: '15px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px', color: '#fff' }}>
                <ShieldCheck size={17} color="var(--success)" />
                <span>Core Security Invariants</span>
              </h2>
              <span className="badge-role admin">ENFORCED</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                <div style={{ padding: '3px', borderRadius: '4px', background: 'var(--success-bg)', color: 'var(--success)', marginTop: '2px' }}>
                  <CheckCircle2 size={14} />
                </div>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: '#fff', marginBottom: '2px' }}>Zero Plaintext in PostgreSQL</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                    Payloads are strictly stored as AES-256-GCM ciphertext in object storage with randomized DEKs.
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                <div style={{ padding: '3px', borderRadius: '4px', background: 'var(--success-bg)', color: 'var(--success)', marginTop: '2px' }}>
                  <CheckCircle2 size={14} />
                </div>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: '#fff', marginBottom: '2px' }}>Fail-Closed OPA Policy Enforcement</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                    Every access request verifies identity, purpose, view type, and job state. OPA downtime = immediate deny.
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                <div style={{ padding: '3px', borderRadius: '4px', background: 'var(--success-bg)', color: 'var(--success)', marginTop: '2px' }}>
                  <CheckCircle2 size={14} />
                </div>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: '#fff', marginBottom: '2px' }}>Data Minimization by Default</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                    ML trainers receive compact 64-dim CNN feature vectors. Raw image access is blocked by policy.
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                <div style={{ padding: '3px', borderRadius: '4px', background: 'var(--primary-bg)', color: 'var(--primary)', marginTop: '2px' }}>
                  <KeyRound size={14} />
                </div>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: '#fff', marginBottom: '2px' }}>
                    Key Rotation Without Payload Re-encryption
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                    Active Master KEK is <strong style={{ color: 'var(--primary)', fontFamily: 'var(--font-mono)' }}>v{telemetry?.kek_current_version || 1}</strong>. Rotating keys only rewraps DEKs in milliseconds.
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Quick Governance Actions */}
        <div className="double-bezel">
          <div className="double-bezel-inner">
            <h2 style={{ fontSize: '15px', fontWeight: 700, marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '8px', color: '#fff' }}>
              <Layers size={17} color="var(--primary)" />
              <span>Quick Governance Actions</span>
            </h2>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '9px' }}>
              <button
                className="btn-secondary"
                style={{ justifyContent: 'space-between', padding: '11px 15px' }}
                onClick={() => onNavigate('upload')}
              >
                <span>Upload Encrypted Dataset Record</span>
                <ArrowUpRight size={14} color="var(--primary)" />
              </button>

              <button
                className="btn-secondary"
                style={{ justifyContent: 'space-between', padding: '11px 15px' }}
                onClick={() => onNavigate('search')}
              >
                <span>Execute Protected Equality Search</span>
                <ArrowUpRight size={14} color="var(--primary)" />
              </button>

              <button
                className="btn-secondary"
                style={{ justifyContent: 'space-between', padding: '11px 15px' }}
                onClick={() => onNavigate('access')}
              >
                <span>Test Context-Aware Access Request</span>
                <ArrowUpRight size={14} color="var(--primary)" />
              </button>

              <button
                className="btn-secondary"
                style={{ justifyContent: 'space-between', padding: '11px 15px' }}
                onClick={() => onNavigate('benchmarks')}
              >
                <span>Inspect Privacy vs. Utility Benchmarks</span>
                <ArrowUpRight size={14} color="var(--primary)" />
              </button>

              <button
                className="btn-secondary"
                style={{ justifyContent: 'space-between', padding: '11px 15px' }}
                onClick={() => onNavigate('audit_verify')}
              >
                <span>Run Cryptographic Audit-Chain Verifier</span>
                <ArrowUpRight size={14} color="var(--primary)" />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
