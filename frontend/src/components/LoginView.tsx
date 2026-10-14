import React, { useState } from 'react'
import type { UserRole } from '../types'
import { login, register } from '../api'
import { Shield, AlertCircle, ArrowRight } from 'lucide-react'

interface LoginViewProps {
  onSuccess: (role: UserRole, username: string) => void
}

export const LoginView: React.FC<LoginViewProps> = ({ onSuccess }) => {
  const [isRegister, setIsRegister] = useState(false)
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('Pass123!')
  const [role, setRole] = useState<UserRole>('admin')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSubmitting(true)
    setError(null)

    try {
      if (isRegister) {
        await register(username.trim(), password, role)
        // Automatically login after registration
        const tokens = await login(username.trim(), password)
        onSuccess(tokens.role, tokens.username)
      } else {
        const tokens = await login(username.trim(), password)
        onSuccess(tokens.role, tokens.username)
      }
    } catch (err: any) {
      setError(err.message || 'Authentication failed')
    } finally {
      setSubmitting(false)
    }
  }

  const handleQuickLogin = async (quickUsername: string, quickRole: UserRole) => {
    setUsername(quickUsername)
    setPassword('Pass123!')
    setSubmitting(true)
    setError(null)
    try {
      const tokens = await login(quickUsername, 'Pass123!')
      onSuccess(tokens.role, tokens.username)
    } catch {
      // If user doesn't exist yet, try to register then login
      try {
        await register(quickUsername, 'Pass123!', quickRole)
        const tokens = await login(quickUsername, 'Pass123!')
        onSuccess(tokens.role, tokens.username)
      } catch (e: any) {
        setError(e.message || 'Quick login failed')
      }
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '24px',
      }}
    >
      <div style={{ width: '100%', maxWidth: '440px' }}>
        {/* Brand Header */}
        <div style={{ textAlign: 'center', marginBottom: '28px' }}>
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'linear-gradient(135deg, #3b82f6 0%, #10b981 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 14px',
              boxShadow: '0 0 24px rgba(59, 130, 246, 0.3)',
            }}
          >
            <Shield size={26} color="#fff" />
          </div>
          <h1 style={{ fontSize: '24px', fontWeight: 800, color: '#fff', letterSpacing: '-0.02em' }}>
            CAS-SE Architecture
          </h1>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '4px' }}>
            Reference Governance &amp; Access Dashboard
          </p>
        </div>

        {/* Double-Bezel Login Card */}
        <div className="double-bezel">
          <div className="double-bezel-inner">
            <div style={{ display: 'flex', gap: '8px', marginBottom: '20px' }}>
              <button
                type="button"
                className={`tab-btn ${!isRegister ? 'active' : ''}`}
                style={{ flex: 1, justifyContent: 'center' }}
                onClick={() => {
                  setIsRegister(false)
                  setError(null)
                }}
              >
                Sign In
              </button>
              <button
                type="button"
                className={`tab-btn ${isRegister ? 'active' : ''}`}
                style={{ flex: 1, justifyContent: 'center' }}
                onClick={() => {
                  setIsRegister(true)
                  setError(null)
                }}
              >
                Register
              </button>
            </div>

            <form onSubmit={handleSubmit}>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px' }}>
                  USERNAME
                </label>
                <div style={{ position: 'relative' }}>
                  <input
                    type="text"
                    className="input-field"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                  />
                </div>
              </div>

              <div style={{ marginBottom: isRegister ? '16px' : '20px' }}>
                <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px' }}>
                  PASSWORD
                </label>
                <input
                  type="password"
                  className="input-field"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>

              {isRegister && (
                <div style={{ marginBottom: '20px' }}>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', marginBottom: '6px' }}>
                    ASSIGNED ROLE
                  </label>
                  <select
                    className="select-field"
                    value={role}
                    onChange={(e) => setRole(e.target.value as UserRole)}
                  >
                    <option value="trainer">Trainer (ML training on feature vectors)</option>
                    <option value="researcher">Researcher (Explicit raw data access)</option>
                    <option value="uploader">Uploader (Encrypted envelope ingestion)</option>
                    <option value="auditor">Auditor (Audit trail &amp; chain verification)</option>
                    <option value="admin">Admin (Approval queue &amp; key rotation)</option>
                  </select>
                </div>
              )}

              {error && (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    padding: '10px 14px',
                    background: 'rgba(244, 63, 94, 0.12)',
                    border: '1px solid rgba(244, 63, 94, 0.3)',
                    borderRadius: '6px',
                    color: '#fb7185',
                    fontSize: '12px',
                    marginBottom: '18px',
                  }}
                >
                  <AlertCircle size={15} style={{ flexShrink: 0 }} />
                  <span>{error}</span>
                </div>
              )}

              <button
                type="submit"
                className="btn-primary"
                disabled={submitting}
                style={{ width: '100%', justifyContent: 'center' }}
              >
                <span>{submitting ? 'Authenticating...' : isRegister ? 'Create Account' : 'Sign In'}</span>
                <ArrowRight size={15} />
              </button>
            </form>

            {/* Quick Demo Logins */}
            <div style={{ marginTop: '24px', paddingTop: '20px', borderTop: '1px solid var(--border-inner)' }}>
              <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', marginBottom: '10px', textAlign: 'center' }}>
                QUICK DEMO PERSONAS
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '6px' }}>
                <button
                  type="button"
                  className="btn-secondary"
                  style={{ fontSize: '11px', padding: '6px 8px', justifyContent: 'center' }}
                  onClick={() => handleQuickLogin('admin_demo', 'admin')}
                >
                  Admin
                </button>
                <button
                  type="button"
                  className="btn-secondary"
                  style={{ fontSize: '11px', padding: '6px 8px', justifyContent: 'center' }}
                  onClick={() => handleQuickLogin('trainer_demo', 'trainer')}
                >
                  Trainer
                </button>
                <button
                  type="button"
                  className="btn-secondary"
                  style={{ fontSize: '11px', padding: '6px 8px', justifyContent: 'center' }}
                  onClick={() => handleQuickLogin('researcher_demo', 'researcher')}
                >
                  Researcher
                </button>
                <button
                  type="button"
                  className="btn-secondary"
                  style={{ fontSize: '11px', padding: '6px 8px', justifyContent: 'center' }}
                  onClick={() => handleQuickLogin('auditor_demo', 'auditor')}
                >
                  Auditor
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
