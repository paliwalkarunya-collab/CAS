import { ShieldCheck, Zap, Database, CheckCircle2 } from 'lucide-react'

export const BenchmarksView: React.FC = () => {
  return (
    <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '32px 24px' }}>
      <div style={{ marginBottom: '28px' }}>
        <h1 className="page-title">Privacy vs. Utility Benchmarks &amp; Experiments</h1>
        <p className="page-desc">
          Empirical evaluation results across the 3 required architectures (Plaintext, Encrypted-RBAC, CAS-SE)
          measuring classification utility, cryptographic latency overhead, and data exposure minimization.
        </p>
      </div>

      {/* 3 Baseline Summary Cards */}
      <div className="grid-3" style={{ marginBottom: '28px' }}>
        {/* Baseline 1: Plaintext */}
        <div className="double-bezel">
          <div className="double-bezel-inner" style={{ borderTop: '4px solid #ef4444' }}>
            <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#ef4444', marginBottom: '4px' }}>
              BASELINE 1
            </div>
            <div style={{ fontSize: '18px', fontWeight: 800, color: '#fff', marginBottom: '8px' }}>Plaintext</div>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '16px' }}>
              Standard training with raw image pixel inputs. No encryption at rest, no context-aware policy checks.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '13px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Classifier F1 Utility:</span>
                <span style={{ fontWeight: 700, color: '#fff' }}>1.000 (100%)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Raw Images Exposed:</span>
                <span style={{ fontWeight: 700, color: '#ef4444' }}>100% (High Risk)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Policy Denial Rate:</span>
                <span style={{ fontWeight: 700, color: '#ef4444' }}>0.0% (None)</span>
              </div>
            </div>
          </div>
        </div>

        {/* Baseline 2: Encrypted-RBAC */}
        <div className="double-bezel">
          <div className="double-bezel-inner" style={{ borderTop: '4px solid #f59e0b' }}>
            <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#f59e0b', marginBottom: '4px' }}>
              BASELINE 2
            </div>
            <div style={{ fontSize: '18px', fontWeight: 800, color: '#fff', marginBottom: '8px' }}>Encrypted-RBAC</div>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '16px' }}>
              Encryption at rest in object storage, but coarse role checks release full raw images to trainers.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '13px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Classifier F1 Utility:</span>
                <span style={{ fontWeight: 700, color: '#fff' }}>1.000 (100%)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Raw Images Exposed:</span>
                <span style={{ fontWeight: 700, color: '#f59e0b' }}>100% to Trainer</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Policy Denial Rate:</span>
                <span style={{ fontWeight: 700, color: '#f59e0b' }}>50.0% (Role-only)</span>
              </div>
            </div>
          </div>
        </div>

        {/* Baseline 3: CAS-SE */}
        <div className="double-bezel">
          <div className="double-bezel-inner" style={{ borderTop: '4px solid #10b981' }}>
            <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#10b981', marginBottom: '4px' }}>
              ARCHITECTURE
            </div>
            <div style={{ fontSize: '18px', fontWeight: 800, color: '#fff', marginBottom: '8px' }}>CAS-SE Middleware</div>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '16px' }}>
              AES-256-GCM + OPA fail-closed ABAC + blind HMAC search + scoped ML jobs + <strong>CNN feature vectors</strong>.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '13px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Classifier F1 Utility:</span>
                <span style={{ fontWeight: 700, color: '#34d399' }}>1.000 (Preserved)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Raw Images Exposed:</span>
                <span style={{ fontWeight: 700, color: '#34d399' }}>0% (Zero Raw Release)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Policy Denial Rate:</span>
                <span style={{ fontWeight: 700, color: '#34d399' }}>100.0% (Fail-Closed)</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Latency and Storage Overhead Section */}
      <div className="grid-2" style={{ marginBottom: '28px' }}>
        <div className="double-bezel">
          <div className="double-bezel-inner">
            <h2 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Zap size={18} color="#60a5fa" />
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
                    <td>0.000 ms</td>
                    <td style={{ color: '#60a5fa' }}>0.073 ms</td>
                    <td>+0.072 ms</td>
                  </tr>
                  <tr>
                    <td>Protected Equality Search (HMAC)</td>
                    <td>0.000 ms</td>
                    <td style={{ color: '#34d399' }}>0.003 ms</td>
                    <td>+0.003 ms</td>
                  </tr>
                  <tr>
                    <td>Access Decision &amp; Audit Chaining</td>
                    <td>0.001 ms</td>
                    <td style={{ color: '#a78bfa' }}>0.007 ms</td>
                    <td>+0.006 ms</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div className="double-bezel">
          <div className="double-bezel-inner">
            <h2 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Database size={18} color="#a78bfa" />
              <span>Storage Overhead Impact</span>
            </h2>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px' }}>
                <span style={{ color: 'var(--text-dim)' }}>Raw Payload (Simulation):</span>
                <span style={{ fontWeight: 600 }}>65,536 bytes (64 KB)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px' }}>
                <span style={{ color: 'var(--text-dim)' }}>AES-GCM Auth Tag + Nonce:</span>
                <span style={{ fontWeight: 600 }}>28 bytes</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px' }}>
                <span style={{ color: 'var(--text-dim)' }}>Wrapped DEK (v1 Base64):</span>
                <span style={{ fontWeight: 600 }}>80 bytes</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.2)', borderRadius: '6px' }}>
                <span style={{ color: '#34d399', fontWeight: 700 }}>Net Envelope Overhead:</span>
                <span style={{ color: '#34d399', fontWeight: 700 }}>+236 bytes (+0.36%)</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Security Benchmark Empirical Verification Checklist */}
      <div className="double-bezel">
        <div className="double-bezel-inner">
          <h2 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <ShieldCheck size={18} color="#34d399" />
            <span>Cryptographic &amp; Governance Verification Results</span>
          </h2>

          <div className="grid-2">
            <div style={{ display: 'flex', gap: '10px' }}>
              <CheckCircle2 size={16} color="#34d399" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: '#fff' }}>Ciphertext Modification Detection: PASSED</div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  Single-bit modification in stored ciphertext triggers immediate AES-256-GCM auth tag rejection.
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '10px' }}>
              <CheckCircle2 size={16} color="#34d399" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: '#fff' }}>AAD Context Swapping Prevention: PASSED</div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  Tampering with envelope ID, policy ID, or sensitivity label in AAD blocks decryption.
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '10px' }}>
              <CheckCircle2 size={16} color="#34d399" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: '#fff' }}>Single-Share Key Compromise Resistance: PASSED</div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  Adversary holding 1-of-3 Shamir shares fails to reconstruct the master wrapping key.
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '10px' }}>
              <CheckCircle2 size={16} color="#34d399" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: '#fff' }}>Threshold Secret Recovery (2-of-3): PASSED</div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
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
