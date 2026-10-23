import React, { useEffect, useState } from 'react'
import type { User, UserRole } from './types'
import { authStorage, getMe } from './api'
import { Navbar, type TabId } from './components/Navbar'
import { DashboardView } from './components/DashboardView'
import { UploadView } from './components/UploadView'
import { SearchView } from './components/SearchView'
import { AccessRequestView } from './components/AccessRequestView'
import { MLJobsView } from './components/MLJobsView'
import { AdminApprovalView } from './components/AdminApprovalView'
import { AuditView } from './components/AuditView'
import { AuditVerificationView } from './components/AuditVerificationView'
import { AnomaliesView } from './components/AnomaliesView'
import { PoliciesView } from './components/PoliciesView'
import { BenchmarksView } from './components/BenchmarksView'
import { HealthView } from './components/HealthView'
import { LoginView } from './components/LoginView'

export const App: React.FC = () => {
  const [currentUser, setCurrentUser] = useState<User | null>(null)
  const [currentRole, setCurrentRole] = useState<UserRole>('admin')
  const [currentTab, setCurrentTab] = useState<TabId>('dashboard')
  const [prefillEnvelopeId, setPrefillEnvelopeId] = useState<string>('')

  useEffect(() => {
    const handleAuthExpired = () => {
      authStorage.clear()
      setCurrentUser(null)
    }
    window.addEventListener('auth:expired', handleAuthExpired)

    const savedUser = authStorage.getUser()
    const token = authStorage.getToken()
    if (savedUser && token) {
      setCurrentUser(savedUser)
      setCurrentRole(savedUser.role)
      // Validate session with backend; if invalid or expired, return cleanly to login
      getMe().then((me) => {
        setCurrentUser(me)
        setCurrentRole(me.role)
      }).catch(() => {
        authStorage.clear()
        setCurrentUser(null)
      })
    }

    return () => {
      window.removeEventListener('auth:expired', handleAuthExpired)
    }
  }, [])

  const handleLoginSuccess = (role: UserRole, username: string) => {
    const user: User = {
      id: 'active',
      username,
      role,
      is_active: true,
    }
    setCurrentUser(user)
    setCurrentRole(role)
  }

  const handleLogout = () => {
    authStorage.clear()
    setCurrentUser(null)
    setCurrentTab('dashboard')
  }

  const handleRequestAccessFromSearch = (envelopeId: string) => {
    setPrefillEnvelopeId(envelopeId)
    setCurrentTab('access')
  }

interface ErrorBoundaryProps {
  children: React.ReactNode
  fallbackTab: () => void
}

interface ErrorBoundaryState {
  hasError: boolean
  error: Error | null
}

class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('ErrorBoundary caught error:', error, errorInfo)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="app-container fade-in" style={{ padding: '60px 20px', textAlign: 'center' }}>
          <div className="double-bezel" style={{ maxWidth: '600px', margin: '0 auto' }}>
            <div className="double-bezel-inner" style={{ padding: '36px 24px' }}>
              <h2 style={{ fontSize: '18px', fontWeight: 800, color: '#f87171', marginBottom: '10px' }}>
                View Rendering Error
              </h2>
              <p style={{ color: 'var(--text-muted)', fontSize: '13px', marginBottom: '20px' }}>
                {this.state.error?.message || 'An unexpected rendering error occurred in this view.'}
              </p>
              <button
                className="btn-primary"
                onClick={() => {
                  this.setState({ hasError: false, error: null })
                  this.props.fallbackTab()
                }}
              >
                Return to Overview
              </button>
            </div>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}

  if (!currentUser) {
    return <LoginView onSuccess={handleLoginSuccess} />
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Navbar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        currentRole={currentRole}
        onRoleChange={setCurrentRole}
        username={currentUser.username}
        onLogout={handleLogout}
      />

      <main id="main-content" style={{ flex: 1 }}>
        <ErrorBoundary key={currentTab} fallbackTab={() => setCurrentTab('dashboard')}>
          {currentTab === 'dashboard' && (
            <DashboardView currentRole={currentRole} onNavigate={setCurrentTab} />
          )}
        {currentTab === 'upload' && (
          <UploadView
            currentRole={currentRole}
            onNavigateToAccess={handleRequestAccessFromSearch}
            onNavigateTab={setCurrentTab}
          />
        )}
        {currentTab === 'search' && (
          <SearchView onRequestAccess={handleRequestAccessFromSearch} />
        )}
        {currentTab === 'access' && (
          <AccessRequestView
            currentRole={currentRole}
            initialEnvelopeId={prefillEnvelopeId}
          />
        )}
        {currentTab === 'ml_jobs' && <MLJobsView currentRole={currentRole} />}
        {currentTab === 'admin_queue' && (
          <AdminApprovalView currentRole={currentRole} />
        )}
        {currentTab === 'audit' && <AuditView currentRole={currentRole} />}
        {currentTab === 'audit_verify' && (
          <AuditVerificationView currentRole={currentRole} />
        )}
        {currentTab === 'anomalies' && (
          <AnomaliesView currentRole={currentRole} />
        )}
        {currentTab === 'policies' && <PoliciesView currentRole={currentRole} />}
        {currentTab === 'benchmarks' && <BenchmarksView />}
        {currentTab === 'health' && <HealthView />}
        </ErrorBoundary>
      </main>

      <footer
        style={{
          borderTop: '1px solid var(--border-inner)',
          padding: '18px 28px',
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '12px',
          fontSize: '11.5px',
          color: 'var(--text-dim)',
          fontFamily: 'var(--font-mono)',
          background: 'rgba(9, 13, 22, 0.5)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span
            style={{
              width: '7px',
              height: '7px',
              borderRadius: '50%',
              background: 'var(--success)',
              boxShadow: '0 0 8px var(--success-glow)',
              display: 'inline-block',
            }}
          />
          <span style={{ color: 'var(--text-muted)' }}>CAS-SE ENGINE ACTIVE</span>
          <span>•</span>
          <span>Zero Plaintext in RDBMS</span>
          <span>•</span>
          <span>Fail-Closed OPA</span>
        </div>
        <div>
          <span>Tamper-Evident SHA-256 HMAC Chain</span>
        </div>
      </footer>
    </div>
  )
}

export default App
