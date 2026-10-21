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
# Admin: Full Superuser (Every power of auditor, trainer, researcher, uploader)
# ============================================================
allow if {
    input.identity.role == "admin"
}

# ============================================================
# Trainer: Image and Feature Access
# ============================================================
# Trainer: feature-only access for ML workflows
allow if {
    input.identity.role == "trainer"
    input.context.requested_view == "feature_only"
}

# Trainer: masked image access (obfuscated representation for dataset inspection)
allow if {
    input.identity.role == "trainer"
    input.context.requested_view == "masked_image"
}

# Trainer: raw image access (for training, inspection, or approved job)
allow if {
    input.identity.role == "trainer"
    input.context.requested_view == "raw_image"
}

# ============================================================
# Researcher: raw_image, feature_only, masked_image, metadata_only
# ============================================================
allow if {
    input.identity.role == "researcher"
    input.context.requested_view in ["raw_image", "feature_only", "metadata_only", "masked_image"]
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
# Debugging: always masked output, no direct identifiers
# ============================================================
allow if {
    contains(lower(input.context.purpose), "debug")
    input.context.requested_view == "masked_image"
    input.identity.role in ["admin", "researcher", "trainer"]
}

# ============================================================
# Decision output
# ============================================================
decision := input.context.requested_view if {
    allow
    input.identity.role == "admin"
}

decision := "feature_only" if {
    allow
    input.identity.role != "admin"
    input.context.requested_view == "feature_only"
}

decision := "raw_image" if {
    allow
    input.identity.role != "admin"
    input.context.requested_view == "raw_image"
}

decision := "masked_image" if {
    allow
    input.identity.role != "admin"
    input.context.requested_view in ["masked_image", "debugging"]
}

decision := "metadata_only" if {
    allow
    input.identity.role != "admin"
    input.context.requested_view == "metadata_only"
}

allowed_view := decision if allow

# ============================================================
# Reason generation (Guaranteed mutually exclusive complete rules)
# ============================================================
reason := "Access granted (Admin full access)" if {
    allow
    input.identity.role == "admin"
}

reason := "Access granted" if {
    allow
    input.identity.role != "admin"
}

reason := "Job is expired" if {
    not allow
    input.context.job.status == "approved"
    not _job_not_expired
}

reason := "Dataset not in approved job scope" if {
    not allow
    input.context.job.status == "approved"
    _job_not_expired
    not _dataset_in_scope
}

reason := "Job not approved (status: pending, rejected, or cancelled)" if {
    not allow
    input.identity.role in ["trainer", "researcher"]
    input.context.job.status != "approved"
    input.context.job.status != "none"
    not contains(lower(input.context.purpose), "debug")
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
