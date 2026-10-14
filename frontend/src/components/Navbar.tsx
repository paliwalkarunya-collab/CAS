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
          <Shield size={18} color="#ffffff" />
        </div>
        <div>
          <div className="nav-title">CAS-SE</div>
          <div className="nav-subtitle">Data Governance Architecture</div>
        </div>
      </div>

      <nav className="tabs-scroll">
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

      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        {/* Active Role Switcher Pill */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>ROLE:</span>
          <select
            className="select-field"
            style={{ width: 'auto', padding: '6px 10px', fontSize: '12px', fontWeight: 600 }}
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
            padding: '5px 12px',
            background: 'rgba(255, 255, 255, 0.04)',
            border: '1px solid var(--border-inner)',
            borderRadius: '20px',
          }}
        >
          <UserCheck size={14} color="#60a5fa" />
          <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-main)' }}>{username}</span>
          <span className={`badge-role ${currentRole}`}>{currentRole}</span>
        </div>

        {/* Logout */}
        <button
          onClick={onLogout}
          title="Sign Out"
          style={{
            background: 'transparent',
            border: 'none',
            color: 'var(--text-dim)',
            cursor: 'pointer',
            padding: '6px',
            borderRadius: '6px',
            display: 'flex',
            alignItems: 'center',
          }}
        >
          <LogOut size={16} />
        </button>
      </div>
    </header>
  )
}
