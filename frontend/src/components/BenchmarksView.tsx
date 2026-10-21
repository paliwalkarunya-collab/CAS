import React from 'react'
import { ShieldCheck, Zap, Database, CheckCircle2 } from 'lucide-react'

export const BenchmarksView: React.FC = () => {
  return (
    <div className="app-container fade-in">
      <div style={{ marginBottom: '28px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
          <span className="section-label">EMPIRICAL EVALUATION</span>
        </div>
        <h1 className="page-title">Privacy vs. Utility Benchmarks &amp; Experiments</h1>
        <p className="page-desc">
          Empirical comparison across the 3 core reference architectures (Plaintext, Encrypted-RBAC, CAS-SE)
          evaluating classification utility, cryptographic latency overhead, and raw data exposure minimization.
        </p>
      </div>

      {/* 3 Architecture Comparison Cards */}
      <div className="grid-3" style={{ marginBottom: '28px' }}>
        {/* Baseline 1: Plaintext */}
        <div className="double-bezel">
          <div className="double-bezel-inner" style={{ borderTop: '3px solid var(--danger)' }}>
            <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#f87171', marginBottom: '4px' }}>
              BASELINE 1
            </div>
            <div style={{ fontSize: '18px', fontWeight: 800, color: '#fff', marginBottom: '8px' }}>Plaintext RDBMS</div>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '16px', lineHeight: 1.5 }}>
              Standard training with raw image pixel inputs. No envelope encryption at rest, zero context-aware policy checks.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12.5px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Classifier F1 Utility:</span>
                <span style={{ fontWeight: 700, color: '#fff', fontFamily: 'var(--font-mono)' }}>1.000 (100%)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Raw Images Exposed:</span>
                <span style={{ fontWeight: 700, color: '#f87171', fontFamily: 'var(--font-mono)' }}>100% (High Risk)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Policy Denial Rate:</span>
                <span style={{ fontWeight: 700, color: '#f87171', fontFamily: 'var(--font-mono)' }}>0.0% (None)</span>
              </div>
            </div>
          </div>
        </div>

        {/* Baseline 2: Encrypted-RBAC */}
        <div className="double-bezel">
          <div className="double-bezel-inner" style={{ borderTop: '3px solid var(--warning)' }}>
            <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#fbbf24', marginBottom: '4px' }}>
              BASELINE 2
            </div>
            <div style={{ fontSize: '18px', fontWeight: 800, color: '#fff', marginBottom: '8px' }}>Encrypted-RBAC</div>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '16px', lineHeight: 1.5 }}>
              Encryption at rest in object storage, but coarse static role checks release full raw images to trainers.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12.5px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Classifier F1 Utility:</span>
                <span style={{ fontWeight: 700, color: '#fff', fontFamily: 'var(--font-mono)' }}>1.000 (100%)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Raw Images Exposed:</span>
                <span style={{ fontWeight: 700, color: '#fbbf24', fontFamily: 'var(--font-mono)' }}>100% to Trainer</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Policy Denial Rate:</span>
                <span style={{ fontWeight: 700, color: '#fbbf24', fontFamily: 'var(--font-mono)' }}>50.0% (Role-only)</span>
              </div>
            </div>
          </div>
        </div>

        {/* Baseline 3: CAS-SE (Highlighted) */}
        <div className="double-bezel" style={{ borderColor: 'var(--primary-border)', boxShadow: 'var(--shadow-glow)' }}>
          <div className="double-bezel-inner" style={{ borderTop: '3px solid var(--primary)', background: 'linear-gradient(180deg, rgba(56, 189, 248, 0.05) 0%, var(--bg-card) 100%)' }}>
            <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--primary)', marginBottom: '4px' }}>
              EVALUATED ARCHITECTURE
            </div>
            <div style={{ fontSize: '18px', fontWeight: 800, color: '#fff', marginBottom: '8px' }}>CAS-SE Middleware</div>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '16px', lineHeight: 1.5 }}>
              AES-256-GCM + OPA fail-closed ABAC + blind HMAC search + scoped ML jobs + <strong>CNN feature vectors</strong>.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12.5px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Classifier F1 Utility:</span>
                <span style={{ fontWeight: 700, color: '#4ade80', fontFamily: 'var(--font-mono)' }}>1.000 (Preserved)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Raw Images Exposed:</span>
                <span style={{ fontWeight: 700, color: '#4ade80', fontFamily: 'var(--font-mono)' }}>0% (Zero Raw Release)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Policy Denial Rate:</span>
                <span style={{ fontWeight: 700, color: '#4ade80', fontFamily: 'var(--font-mono)' }}>100.0% (Fail-Closed)</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Latency and Storage Overhead Section */}
      <div className="grid-2" style={{ marginBottom: '28px' }}>
        <div className="double-bezel">
          <div className="double-bezel-inner">
            <h2 style={{ fontSize: '15px', fontWeight: 700, marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px', color: '#fff' }}>
              <Zap size={17} color="var(--primary)" />
              <span>Micro-Latency Overhead Breakdown</span>
            </h2>

            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>OPERATION</th>
                    <th>PLAINTEXT</th>
                    <th>CAS-SE</th>
                    <th>OVERHEAD</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>Ingestion &amp; AES-GCM Encrypt (64 KB)</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>0.000 ms</td>
                    <td style={{ color: 'var(--primary)', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>0.073 ms</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>+0.072 ms</td>
                  </tr>
                  <tr>
                    <td>Protected Equality Search (HMAC)</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>0.000 ms</td>
                    <td style={{ color: '#4ade80', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>0.003 ms</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>+0.003 ms</td>
                  </tr>
                  <tr>
                    <td>Access Decision &amp; Audit Chaining</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>0.001 ms</td>
                    <td style={{ color: '#c084fc', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>0.007 ms</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>+0.006 ms</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div className="double-bezel">
          <div className="double-bezel-inner">
            <h2 style={{ fontSize: '15px', fontWeight: 700, marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px', color: '#fff' }}>
              <Database size={17} color="var(--primary)" />
              <span>Storage Overhead Impact</span>
            </h2>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '12.5px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '9px 12px', background: 'var(--bg-canvas)', borderRadius: '6px', border: '1px solid var(--border-inner)' }}>
                <span style={{ color: 'var(--text-dim)' }}>Raw Payload (Simulation):</span>
                <span style={{ fontWeight: 600, fontFamily: 'var(--font-mono)' }}>65,536 bytes (64 KB)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '9px 12px', background: 'var(--bg-canvas)', borderRadius: '6px', border: '1px solid var(--border-inner)' }}>
                <span style={{ color: 'var(--text-dim)' }}>AES-GCM Auth Tag + Nonce:</span>
                <span style={{ fontWeight: 600, fontFamily: 'var(--font-mono)' }}>28 bytes</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '9px 12px', background: 'var(--bg-canvas)', borderRadius: '6px', border: '1px solid var(--border-inner)' }}>
                <span style={{ color: 'var(--text-dim)' }}>Wrapped DEK (v1 Base64):</span>
                <span style={{ fontWeight: 600, fontFamily: 'var(--font-mono)' }}>80 bytes</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '9px 12px', background: 'var(--success-bg)', border: '1px solid var(--success-border)', borderRadius: '6px' }}>
                <span style={{ color: '#4ade80', fontWeight: 700 }}>Net Envelope Overhead:</span>
                <span style={{ color: '#4ade80', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>+236 bytes (+0.36%)</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Security Benchmark Empirical Verification Checklist */}
      <div className="double-bezel">
        <div className="double-bezel-inner">
          <h2 style={{ fontSize: '15px', fontWeight: 700, marginBottom: '18px', display: 'flex', alignItems: 'center', gap: '8px', color: '#fff' }}>
            <ShieldCheck size={17} color="var(--success)" />
            <span>Cryptographic &amp; Governance Verification Results</span>
          </h2>

          <div className="grid-2">
            <div style={{ display: 'flex', gap: '10px' }}>
              <CheckCircle2 size={16} color="#4ade80" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: '#fff', marginBottom: '2px' }}>Ciphertext Modification Detection: PASSED</div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                  Single-bit modification in stored ciphertext triggers immediate AES-256-GCM auth tag rejection.
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '10px' }}>
              <CheckCircle2 size={16} color="#4ade80" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: '#fff', marginBottom: '2px' }}>AAD Context Swapping Prevention: PASSED</div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                  Tampering with envelope ID, policy ID, or sensitivity label in AAD blocks decryption immediately.
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '10px' }}>
              <CheckCircle2 size={16} color="#4ade80" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: '#fff', marginBottom: '2px' }}>Single-Share Key Compromise Resistance: PASSED</div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                  Adversary holding 1-of-3 Shamir shares fails to reconstruct the master wrapping key.
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '10px' }}>
              <CheckCircle2 size={16} color="#4ade80" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: '#fff', marginBottom: '2px' }}>Threshold Secret Recovery (2-of-3): PASSED</div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                  Any 2 valid shares reconstruct the master wrapping key without loss.
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
