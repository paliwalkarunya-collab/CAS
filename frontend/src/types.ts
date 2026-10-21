/**
 * CAS-SE Reference Frontend TypeScript Interfaces
 * Strictly conforms to PRD and backend OpenAPI schemas.
 * Never stores or exposes raw DEKs, keys, or storage credentials.
 */

export type UserRole = 'admin' | 'uploader' | 'trainer' | 'researcher' | 'auditor'

export interface User {
  id: string
  username: string
  role: UserRole
  is_active: boolean
}

export interface AuthTokens {
  access_token: string
  refresh_token: string
  token_type: string
  role: UserRole
  username: string
}

export interface EnvelopeSummary {
  id: string
  dataset_id?: string
  subject_id?: string
  sensitivity_label: 'public' | 'internal' | 'confidential' | 'restricted'
  created_at?: string
  ciphertext_hash?: string
  kek_version?: number
}

export interface UploadResponse {
  envelope_id: string
  object_uri: string
  ciphertext_sha256: string
  kek_version: number
  sensitivity_label: string
}

export interface SearchResultItem {
  envelope_id: string
  dataset_id?: string
  subject_id?: string
  sensitivity_label: string
}

export interface AccessDecisionResponse {
  decision: string
  reason: string
  allowed_view?: 'metadata_only' | 'masked_image' | 'feature_only' | 'raw_image' | null
  permitted_view?: 'metadata_only' | 'masked_image' | 'feature_only' | 'raw_image' | null
  envelope_id?: string
  data_b64?: string | null
  policy_id?: string | null
  policy_version?: number | null
  data?: {
    metadata?: Record<string, unknown>
    feature_vector?: number[]
    masked_image_b64?: string
    raw_payload_b64?: string
  }
}

export interface MLJob {
  job_id: string
  requester_id: string
  purpose: string
  dataset_scope: string[]
  requested_view: string
  status: 'pending' | 'approved' | 'rejected' | 'in_progress' | 'completed' | 'cancelled' | 'expired'
  expires_at: string
  created_at: string
  rejection_reason?: string
}

export interface AuditEvent {
  event_id: string
  event_type: string
  actor_id?: string
  actor_role?: string
  envelope_id?: string
  decision?: string
  reason?: string
  job_id?: string
  occurred_at: string
}

export interface ChainVerifyResult {
  is_valid: boolean
  message: string
  events_verified: number
}

export interface CheckpointResult {
  last_event_id?: string
  last_event_hmac?: string
  total_events: number
  checkpoint_timestamp: string
  checkpoint_signature: string
}

export interface AnomalyAlert {
  alert_id: string
  alert_type: string
  actor_id?: string
  anomaly_score?: number
  description?: string
  is_reviewed: boolean
  detected_at: string
}

export interface PolicyItem {
  id?: string
  policy_id?: string
  name: string
  description?: string
  version?: number
  latest_version?: number
  is_active: boolean
  rego_policy: string
  created_at: string
  updated_at?: string
}

export interface KeyVersionItem {
  version_number: number
  created_at: string
  is_current: boolean
}

export interface TelemetryMetrics {
  total_envelopes: number
  total_audit_events: number
  total_anomalies: number
  active_ml_jobs: number
  unauthorized_requests_denied: number
  kek_current_version: number
  storage_adapter: string
  key_adapter: string
  database_status?: string
}

export interface BaselineBenchmark {
  architecture: string
  dataset: string
  accuracy: number
  precision: number
  recall: number
  f1_score: number
  training_duration_ms: number
  raw_images_released: number
  raw_releases_avoided: number
  unauthorized_denial_rate: number
  encryption_overhead_ms: number
  view_type: string
}

export interface BenchmarkReport {
  generated_at_iso: string
  dataset: string
  baseline_comparisons: BaselineBenchmark[]
  performance_benchmarks: Array<{
    operation: string
    plaintext_latency_ms: number
    cas_se_latency_ms: number
    overhead_ms: number
    overhead_percentage: number
    sample_size: number
    unit: string
  }>
  security_benchmarks: Array<{
    test_case: string
    expected_outcome: string
    actual_outcome: string
    passed: boolean
    description: string
  }>
  storage_overhead: {
    raw_payload_bytes: number
    ciphertext_bytes: number
    net_overhead_bytes: number
    net_overhead_percentage: number
  }
}
