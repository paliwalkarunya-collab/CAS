# CAS-SE Access Control Policy
# Package: cas_se.access
#
# Default: DENY all access.
# Every allow rule must explicitly pass all context checks.
# OPA unavailability means this policy is never evaluated → caller defaults to deny.
#
# Policy input structure:
#   input.identity.user_id        - authenticated user ID (server-verified)
#   input.identity.role           - authoritative role (from DB, not JWT payload)
#   input.resource.envelope_id    - target data envelope
#   input.resource.sensitivity    - sensitivity label (e.g., "restricted")
#   input.resource.dataset_scope_token - HMAC-protected dataset scope token
#   input.context.purpose         - stated purpose (model_training, research, debugging)
#   input.context.requested_view  - desired data view
#   input.context.job.id          - ML job ID
#   input.context.job.status      - job status (approved / expired / rejected)
#   input.context.job.expires_at  - ISO8601 expiry timestamp (nanoseconds for time.now_ns)
#   input.context.job.dataset_scope - approved dataset IDs (array)
#   input.context.policy_version  - policy version at time of job approval

package cas_se.access

import future.keywords.if
import future.keywords.in

# ============================================================
# Default: DENY everything
# ============================================================
default allow := false
default decision := "deny"
default allowed_view := null
default reason := "Access denied by default policy"

# ============================================================
# Trainer: feature-only access for approved, unexpired ML job
# ============================================================
allow if {
    input.identity.role == "trainer"
    input.context.requested_view == "feature_only"
    input.context.job.status == "approved"
    _job_not_expired
    _dataset_in_scope
}

# Trainer raw-image requests always denied — no exceptions
deny_raw if {
    input.identity.role == "trainer"
    input.context.requested_view == "raw_image"
}

# ============================================================
# Researcher: raw_image only with explicit approval
# ============================================================
allow if {
    input.identity.role == "researcher"
    input.context.requested_view == "raw_image"
    input.context.job.status == "approved"
    input.context.job.purpose == "research"
    _job_not_expired
    _dataset_in_scope
}

allow if {
    input.identity.role == "researcher"
    input.context.requested_view in ["feature_only", "metadata_only", "masked_image"]
    input.context.job.status == "approved"
    _job_not_expired
    _dataset_in_scope
}

# ============================================================
# Uploader: metadata-only access to their own uploads
# ============================================================
allow if {
    input.identity.role == "uploader"
    input.context.requested_view == "metadata_only"
    input.resource.uploaded_by == input.identity.user_id
}

# ============================================================
# Auditor: metadata-only, no image/payload access
# ============================================================
allow if {
    input.identity.role == "auditor"
    input.context.requested_view == "metadata_only"
}

# ============================================================
# Admin: metadata access (raw access still requires explicit job)
# ============================================================
allow if {
    input.identity.role == "admin"
    input.context.requested_view == "metadata_only"
}

# ============================================================
# Debugging: always masked output, no direct identifiers
# ============================================================
allow if {
    input.context.purpose == "debugging"
    input.context.requested_view == "masked_image"
    input.identity.role in ["admin", "researcher"]
}

# ============================================================
# Decision output
# ============================================================
decision := "feature_only" if {
    allow
    input.context.requested_view == "feature_only"
    not deny_raw
}

decision := "raw_image" if {
    allow
    input.context.requested_view == "raw_image"
    input.identity.role == "researcher"
    not deny_raw
}

decision := "masked_image" if {
    allow
    input.context.requested_view in ["masked_image", "debugging"]
}

decision := "metadata_only" if {
    allow
    input.context.requested_view == "metadata_only"
}

allowed_view := decision if allow

reason := "Access granted" if allow

reason := "Trainer raw-image access is never permitted" if deny_raw

reason := "Job is expired" if {
    not _job_not_expired
    input.context.job.status == "approved"
}

reason := "Dataset not in approved job scope" if {
    not _dataset_in_scope
    input.context.job.status == "approved"
}

reason := "Job not approved (status: pending, rejected, or cancelled)" if {
    input.context.job.status != "approved"
}

# ============================================================
# Helper rules
# ============================================================
_job_not_expired if {
    # expires_at stored as nanoseconds since epoch
    input.context.job.expires_at > time.now_ns()
}

_dataset_in_scope if {
    input.resource.dataset_scope_token in input.context.job.dataset_scope
}

_dataset_in_scope if {
    # If no dataset restriction, job scope contains "*"
    "*" in input.context.job.dataset_scope
}
