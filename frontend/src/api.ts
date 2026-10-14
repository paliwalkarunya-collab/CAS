/**
 * CAS-SE Centralized API Client
 * Manages JWT tokens, authenticated requests, and error normalization.
 */

import type {
  AccessDecisionResponse,
  AnomalyAlert,
  AuditEvent,
  AuthTokens,
  ChainVerifyResult,
  CheckpointResult,
  EnvelopeSummary,
  KeyVersionItem,
  MLJob,
  PolicyItem,
  SearchResultItem,
  TelemetryMetrics,
  UploadResponse,
  User,
  UserRole,
} from './types'

const TOKEN_KEY = 'cas_se_access_token'
const USER_KEY = 'cas_se_current_user'

export const authStorage = {
  getToken(): string | null {
    return localStorage.getItem(TOKEN_KEY)
  },
  setToken(token: string) {
    localStorage.setItem(TOKEN_KEY, token)
  },
  getUser(): User | null {
    const raw = localStorage.getItem(USER_KEY)
    return raw ? JSON.parse(raw) : null
  },
  setUser(user: User) {
    localStorage.setItem(USER_KEY, JSON.stringify(user))
  },
  clear() {
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(USER_KEY)
  },
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers || {})
  const token = authStorage.getToken()
  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`)
  }

  const res = await fetch(path, {
    ...options,
    headers,
  })

  if (!res.ok) {
    let errorDetail = `Request failed: ${res.status} ${res.statusText}`
    try {
      const errorJson = await res.json()
      if (errorJson.detail) {
        errorDetail = typeof errorJson.detail === 'string' ? errorJson.detail : JSON.stringify(errorJson.detail)
      }
    } catch {
      // Keep default error
    }
    throw new Error(errorDetail)
  }

  return res.json() as Promise<T>
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

export async function login(username: string, password: string): Promise<AuthTokens> {
  const data = await request<AuthTokens>('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: username.trim(), password }),
  })

  authStorage.setToken(data.access_token)
  authStorage.setUser({
    id: 'active',
    username: data.username || username.trim(),
    role: data.role || 'trainer',
    is_active: true,
  })
  return data
}

export async function register(username: string, password: string, role: UserRole): Promise<User> {
  return request<User>('/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, role }),
  })
}

export async function getMe(): Promise<User> {
  return request<User>('/auth/me')
}

// ---------------------------------------------------------------------------
// Envelopes & Ingestion
// ---------------------------------------------------------------------------

export async function uploadEnvelope(
  file: File,
  datasetId: string,
  subjectId: string,
  sensitivity: string,
): Promise<UploadResponse> {
  const form = new FormData()
  form.append('file', file)
  form.append('dataset_id', datasetId)
  form.append('subject_id', subjectId)
  form.append('sensitivity_label', sensitivity)

  return request<UploadResponse>('/envelopes', {
    method: 'POST',
    body: form,
  })
}

export async function listEnvelopes(limit = 20): Promise<EnvelopeSummary[]> {
  return request<EnvelopeSummary[]>(`/envelopes?limit=${limit}`)
}

// ---------------------------------------------------------------------------
// Protected Search
// ---------------------------------------------------------------------------

export async function searchEnvelopes(field: 'dataset_id' | 'subject_id', value: string): Promise<SearchResultItem[]> {
  return request<SearchResultItem[]>(`/search?field=${encodeURIComponent(field)}&value=${encodeURIComponent(value)}`)
}

// ---------------------------------------------------------------------------
// Context-Aware Access Requests
// ---------------------------------------------------------------------------

export async function requestAccess(payload: {
  envelope_id: string
  purpose: string
  requested_view: 'metadata_only' | 'masked_image' | 'feature_only' | 'raw_image'
  job_id?: string
}): Promise<AccessDecisionResponse> {
  return request<AccessDecisionResponse>('/access-request', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

// ---------------------------------------------------------------------------
// ML Jobs
// ---------------------------------------------------------------------------

export async function createMLJob(payload: {
  purpose: string
  dataset_scope: string
  requested_view: string
  duration_hours?: number
}): Promise<MLJob> {
  return request<MLJob>('/ml-jobs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export async function listMLJobs(): Promise<MLJob[]> {
  return request<MLJob[]>('/ml-jobs')
}

export async function approveMLJob(jobId: string): Promise<{ status: string; job_id: string; manifest_token: string }> {
  return request<{ status: string; job_id: string; manifest_token: string }>(`/ml-jobs/${jobId}/approve`, {
    method: 'POST',
  })
}

export async function rejectMLJob(jobId: string, reason: string): Promise<{ status: string; job_id: string }> {
  return request<{ status: string; job_id: string }>(`/ml-jobs/${jobId}/reject`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason }),
  })
}

export async function cancelMLJob(jobId: string): Promise<{ status: string; job_id: string }> {
  return request<{ status: string; job_id: string }>(`/ml-jobs/${jobId}/cancel`, {
    method: 'POST',
  })
}

// ---------------------------------------------------------------------------
// Audit & Verification
// ---------------------------------------------------------------------------

export async function queryAudit(params: {
  eventType?: string
  decision?: string
  limit?: number
} = {}): Promise<AuditEvent[]> {
  const q = new URLSearchParams()
  if (params.eventType) q.append('event_type', params.eventType)
  if (params.decision) q.append('decision', params.decision)
  if (params.limit) q.append('limit', String(params.limit))
  return request<AuditEvent[]>(`/audit?${q.toString()}`)
}

export async function verifyAuditChain(): Promise<ChainVerifyResult> {
  return request<ChainVerifyResult>('/audit/verify')
}

export async function getAuditCheckpoint(): Promise<CheckpointResult> {
  return request<CheckpointResult>('/audit/checkpoint')
}

// ---------------------------------------------------------------------------
// Anomalies (IsolationForest)
// ---------------------------------------------------------------------------

export async function listAnomalies(reviewed?: boolean): Promise<AnomalyAlert[]> {
  const q = reviewed !== undefined ? `?reviewed=${reviewed}` : ''
  return request<AnomalyAlert[]>(`/anomalies${q}`)
}

export async function runAnomalyScan(lookbackHours = 72): Promise<{ status: string; alerts_created: number }> {
  return request<{ status: string; alerts_created: number }>(`/anomalies/run?lookback_hours=${lookbackHours}`, {
    method: 'POST',
  })
}

export async function reviewAnomaly(alertId: string): Promise<AnomalyAlert> {
  return request<AnomalyAlert>(`/anomalies/${alertId}/review`, {
    method: 'PATCH',
  })
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

export async function listPolicies(): Promise<PolicyItem[]> {
  return request<PolicyItem[]>('/policies')
}

export async function createPolicy(payload: {
  name: string
  description?: string
  rego_policy: string
}): Promise<PolicyItem> {
  return request<PolicyItem>('/policies', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

// ---------------------------------------------------------------------------
// Key Lifecycle & Management
// ---------------------------------------------------------------------------

export async function listKeyVersions(): Promise<KeyVersionItem[]> {
  return request<KeyVersionItem[]>('/keys')
}

export async function rotateKey(): Promise<{
  status: string
  old_kek_version: number
  new_kek_version: number
  envelopes_rewrapped: number
}> {
  return request<{
    status: string
    old_kek_version: number
    new_kek_version: number
    envelopes_rewrapped: number
  }>('/keys/rotate', {
    method: 'POST',
  })
}

// ---------------------------------------------------------------------------
// System Health & Telemetry
// ---------------------------------------------------------------------------

export async function getHealth(): Promise<{ status: string; service: string; version: string }> {
  return request<{ status: string; service: string; version: string }>('/health')
}

export async function getMetrics(): Promise<{ status: string; telemetry: TelemetryMetrics }> {
  return request<{ status: string; telemetry: TelemetryMetrics }>('/metrics')
}
