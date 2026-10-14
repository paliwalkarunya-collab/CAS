import React, { useEffect, useState } from 'react'
import type { User, UserRole } from './types'
import { authStorage } from './api'
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
    const savedUser = authStorage.getUser()
    const token = authStorage.getToken()
    if (savedUser && token) {
      setCurrentUser(savedUser)
      setCurrentRole(savedUser.role)
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

      <main style={{ flex: 1 }}>
        {currentTab === 'dashboard' && (
          <DashboardView currentRole={currentRole} onNavigate={setCurrentTab} />
        )}
        {currentTab === 'upload' && <UploadView currentRole={currentRole} />}
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
      </main>

      <footer
        style={{
          borderTop: '1px solid var(--border-inner)',
          padding: '16px 28px',
          textAlign: 'center',
          fontSize: '12px',
          color: 'var(--text-dim)',
          fontFamily: 'var(--font-mono)',
        }}
      >
        CAS-SE Reference Architecture • Zero Plaintext in RDBMS • Fail-Closed OPA Policy • Tamper-Evident HMAC Hash Chain
      </footer>
    </div>
  )
}

export default App
