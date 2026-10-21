import React from 'react'
import type { UserRole } from '../types'
import {
  Shield,
  Layers,
  UploadCloud,
  Search,
  KeyRound,
  FileCheck,
  Cpu,
  CheckCircle,
  AlertTriangle,
  BarChart3,
  Activity,
  LogOut,
  UserCheck,
} from 'lucide-react'

export type TabId =
  | 'dashboard'
  | 'upload'
  | 'search'
  | 'access'
  | 'ml_jobs'
  | 'admin_queue'
  | 'audit'
  | 'audit_verify'
  | 'anomalies'
  | 'policies'
  | 'benchmarks'
  | 'health'

interface NavbarProps {
  currentTab: TabId
  onSelectTab: (tab: TabId) => void
  currentRole: UserRole
  onRoleChange: (role: UserRole) => void
  username: string
  onLogout: () => void
}

export const Navbar: React.FC<NavbarProps> = ({
  currentTab,
  onSelectTab,
  currentRole,
  onRoleChange,
  username,
  onLogout,
}) => {
  const tabs: Array<{ id: TabId; label: string; icon: React.ReactNode }> = [
    { id: 'dashboard', label: 'Overview', icon: <Layers size={15} /> },
    { id: 'upload', label: 'Ingest Envelope', icon: <UploadCloud size={15} /> },
    { id: 'search', label: 'Protected Search', icon: <Search size={15} /> },
    { id: 'access', label: 'Access Request', icon: <KeyRound size={15} /> },
    { id: 'ml_jobs', label: 'ML Workflows', icon: <Cpu size={15} /> },
    { id: 'admin_queue', label: 'Admin Queue', icon: <CheckCircle size={15} /> },
    { id: 'audit', label: 'Audit Trail', icon: <FileCheck size={15} /> },
    { id: 'audit_verify', label: 'Chain Verifier', icon: <Shield size={15} /> },
    { id: 'anomalies', label: 'Anomaly Alerts', icon: <AlertTriangle size={15} /> },
    { id: 'policies', label: 'OPA Policies', icon: <Shield size={15} /> },
    { id: 'benchmarks', label: 'Benchmarks', icon: <BarChart3 size={15} /> },
    { id: 'health', label: 'System Health', icon: <Activity size={15} /> },
  ]

  const roles: UserRole[] = ['admin', 'trainer', 'researcher', 'uploader', 'auditor']

  return (
    <header className="navbar">
      <div className="nav-brand">
        <div className="nav-logo">
          <Shield size={18} color="currentColor" />
        </div>
        <div>
          <div className="nav-title">CAS-SE</div>
          <div className="nav-subtitle">Data Governance Architecture</div>
        </div>
      </div>

      <nav className="tabs-scroll" aria-label="Main Navigation">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            className={`tab-btn ${currentTab === tab.id ? 'active' : ''}`}
            onClick={() => onSelectTab(tab.id)}
          >
            {tab.icon}
            <span>{tab.label}</span>
          </button>
        ))}
      </nav>

      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        {/* Active Role Switcher Pill */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
          <span style={{ fontSize: '10px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>ROLE:</span>
          <select
            className="select-field"
            style={{
              width: 'auto',
              padding: '5px 9px',
              fontSize: '11.5px',
              fontWeight: 700,
              fontFamily: 'var(--font-mono)',
              background: 'var(--bg-card)',
              borderColor: 'var(--border-outer)',
              borderRadius: '7px',
              cursor: 'pointer',
            }}
            value={currentRole}
            onChange={(e) => onRoleChange(e.target.value as UserRole)}
          >
            {roles.map((r) => (
              <option key={r} value={r}>
                {r.toUpperCase()}
              </option>
            ))}
          </select>
        </div>

        {/* User Pill */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '4px 10px',
            background: 'var(--bg-card)',
            border: '1px solid var(--border-inner)',
            borderRadius: '8px',
            boxShadow: 'var(--shadow-sm)',
          }}
        >
          <UserCheck size={14} color="var(--primary)" />
          <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-main)', fontFamily: 'var(--font-mono)' }}>{username}</span>
          <span className={`badge-role ${currentRole}`}>{currentRole}</span>
        </div>

        {/* Logout */}
        <button
          onClick={onLogout}
          title="Sign Out"
          className="btn-secondary"
          style={{
            padding: '6px 8px',
            borderRadius: '7px',
          }}
        >
          <LogOut size={14} />
        </button>
      </div>
    </header>
  )
}
