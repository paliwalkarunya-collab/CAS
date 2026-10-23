import { test, expect } from '@playwright/test'

test.describe('CAS-SE Reference Governance Dashboard E2E', () => {
  test.beforeEach(async ({ page }) => {
    // Hermetic API route mocking for E2E validation
    await page.route('**/auth/login', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          access_token: 'e2e-mock-jwt-token',
          refresh_token: 'e2e-mock-refresh-token',
          role: 'admin',
          username: 'admin',
        }),
      })
    })

    await page.route('**/metrics', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          status: 'healthy',
          envelopes_total: 12,
          protected_indexes_total: 24,
          audit_events_total: 48,
          active_policies_total: 1,
          ml_jobs_total: 3,
          anomaly_alerts_total: 0,
        }),
      })
    })

    await page.route('**/health', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          status: 'ok',
          environment: 'development',
          adapters: {
            storage: 'minio',
            key_service: 'env',
            identity: 'builtin',
          },
        }),
      })
    })

    await page.route('**/policies', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          {
            id: '11111111-1111-1111-1111-111111111111',
            name: 'cas_se_default_policy',
            description: 'Default fail-closed ABAC policy',
            rego_policy: 'package cas_se.access\ndefault allow := false',
            is_active: true,
            created_at: '2026-01-01T00:00:00Z',
            updated_at: '2026-01-01T00:00:00Z',
          },
        ]),
      })
    })

    await page.route(url => url.pathname.endsWith('/keys'), async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { version_number: 1, created_at: '2026-01-01T00:00:00Z', is_current: true },
        ]),
      })
    })

    await page.route(url => url.pathname.endsWith('/keys/status'), async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          adapter: 'split',
          is_unlocked: true,
          threshold: 2,
          total_shares: 3,
          current_version: 1,
          shares_provided_count: 2,
          recovered_versions: [1],
          message: 'Key service is unlocked and ready.',
        }),
      })
    })

    await page.route('**/ml-jobs**', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([]),
      })
    })

    await page.route('**/audit**', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([]),
      })
    })

    await page.route('**/anomalies**', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([]),
      })
    })

    await page.route('**/envelopes**', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([]),
      })
    })

    await page.goto('/')
  })

  test('User authentication and quick demo persona switching', async ({ page }) => {
    // 1. Verify Login page renders
    await expect(page.locator('text=CAS-SE Architecture')).toBeVisible()
    await expect(page.locator('text=Cryptographic Access & Reference Governance Dashboard')).toBeVisible()

    // 2. Click quick persona login as Admin
    await page.click('button:has-text("Admin")')

    // 3. Verify user logged in and Navbar rendered with admin role
    await expect(page.locator('.badge-role.admin').first()).toBeVisible()
    await expect(page.locator('text=Overview')).toBeVisible()
    await expect(page.locator('text=Middleware Telemetry & Governance Status')).toBeVisible()
  })

  test('Navigation tabs render double-bezel views properly', async ({ page }) => {
    // Login as Admin
    await page.click('button:has-text("Admin")')

    // Switch to Ingest Envelope
    await page.click('button:has-text("Ingest Envelope")')
    await expect(page.locator('text=Ingest Encrypted Data Envelope')).toBeVisible()
    await expect(page.locator('text=SENSITIVITY LABEL')).toBeVisible()

    // Switch to Protected Search
    await page.click('button:has-text("Protected Search")')
    await expect(page.locator('text=Protected Equality Search')).toBeVisible()
    await expect(page.locator('text=SEARCH INDEX FIELD')).toBeVisible()

    // Switch to Access Request
    await page.click('button:has-text("Access Request")')
    await expect(page.locator('text=Context-Aware Access & Data Minimization')).toBeVisible()

    // Switch to Benchmarks
    await page.click('button:has-text("Benchmarks")')
    await expect(page.locator('text=Privacy vs. Utility Benchmarks & Experiments')).toBeVisible()
    await expect(page.locator('text=Plaintext').first()).toBeVisible()
    await expect(page.locator('text=Encrypted-RBAC').first()).toBeVisible()
    await expect(page.locator('text=CAS-SE Middleware').first()).toBeVisible()

    // Switch to System Health
    await page.click('button:has-text("System Health")')
    await expect(page.locator('text=Middleware Health & Subsystem Telemetry')).toBeVisible()
  })

  test('Active role simulation switching enforces RBAC view gates', async ({ page }) => {
    await page.click('button:has-text("Admin")')

    // Switch simulated role to trainer
    await page.selectOption('select', 'trainer')
    await expect(page.locator('.badge-role.trainer')).toBeVisible()

    // Navigating to Admin Queue as trainer displays access gate
    await page.click('button:has-text("Admin Queue")')
    await expect(page.locator('text=Admin Authorization Required')).toBeVisible()

    // Navigating to Audit Trail as trainer displays access gate
    await page.click('button:has-text("Audit Trail")')
    await expect(page.locator('text=Auditor Authorization Required')).toBeVisible()
  })

  test('Audit chain verification runner in Auditor view', async ({ page }) => {
    await page.route('**/audit/verify', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          is_valid: true,
          events_verified: 42,
          message: 'HMAC-SHA-256 chain is complete and unmodified.',
          broken_event_id: null,
        }),
      })
    })

    await page.click('button:has-text("Admin")')
    await page.click('button:has-text("Audit Trail")')
    await expect(page.locator('text=Tamper-Evident Audit Trail')).toBeVisible()

    await page.click('button:has-text("Verify Chain Integrity")')
    await expect(page.locator('text=Audit Chain Verification Succeeded')).toBeVisible()
    await expect(page.locator('text=sequential events checked')).toBeVisible()
  })

  test('Dedicated Audit-Chain Verification Page', async ({ page }) => {
    await page.route('**/audit/verify', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          is_valid: true,
          events_verified: 42,
          message: 'Audit chain intact -- 42 events verified',
        }),
      })
    })

    await page.click('button:has-text("Admin")')
    await page.click('button:has-text("Chain Verifier")')
    await expect(page.locator('text=Audit-Chain Verification')).toBeVisible()
    await expect(page.locator('text=Audit Hash Chain Verified Intact')).toBeVisible()
    await expect(page.locator('text=Cryptographic Chain Formula')).toBeVisible()
    await expect(page.locator('text=Sequential Chain Link Inspector')).toBeVisible()
  })

  test('Multi-format file picker accepts PDF, documents, and data formats', async ({ page }) => {
    await page.click('button:has-text("Admin")')
    await page.click('button:has-text("Ingest Envelope")')
    await expect(page.locator('text=Ingest Encrypted Data Envelope')).toBeVisible()

    // Verify accept attribute allows non-image files
    const fileInput = page.locator('#file-upload-input')
    const acceptAttr = await fileInput.getAttribute('accept')
    expect(acceptAttr).toContain('.pdf')
    expect(acceptAttr).toContain('.docx')
    expect(acceptAttr).toContain('.xlsx')
    expect(acceptAttr).toContain('.txt')
    expect(acceptAttr).toContain('.csv')
    expect(acceptAttr).toContain('.json')

    // Set a mock PDF file
    await fileInput.setInputFiles({
      name: 'Experiment_4_AWS_S3_Lambda_Orthogonal_Final.pdf',
      mimeType: 'application/pdf',
      buffer: Buffer.from('%PDF-1.4 mock binary stream %%EOF'),
    })

    // Verify UI reflects selected file metadata
    await expect(page.locator('text=Experiment_4_AWS_S3_Lambda_Orthogonal_Final.pdf').first()).toBeVisible()
    await expect(page.locator('text=application/pdf')).toBeVisible()
  })

  test('Shamir locked error banner provides direct navigation to key controls', async ({ page }) => {
    await page.route('**/envelopes', async (route) => {
      if (route.request().method() === 'POST') {
        await route.fulfill({
          status: 503,
          contentType: 'application/json',
          body: JSON.stringify({
            detail: 'Key service is locked -- Shamir secret reconstruction required before data ingestion.',
          }),
        })
      } else {
        await route.continue()
      }
    })

    await page.route(url => url.pathname.endsWith('/keys/status'), async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          adapter: 'split',
          is_unlocked: false,
          threshold: 2,
          total_shares: 3,
          current_version: 1,
          shares_provided_count: 0,
          recovered_versions: [],
          message: 'Key service is LOCKED.',
        }),
      })
    })

    await page.click('button:has-text("Admin")')
    await page.click('button:has-text("Ingest Envelope")')

    // Attach file and submit
    await page.locator('#file-upload-input').setInputFiles({
      name: 'Experiment_4.pdf',
      mimeType: 'application/pdf',
      buffer: Buffer.from('%PDF-1.4 test'),
    })
    await page.click('button:has-text("Encrypt & Ingest Envelope")')

    // Verify locked error banner and button appear
    await expect(page.locator('text=Key service is locked')).toBeVisible()
    const goKeysBtn = page.locator('button:has-text("Go to Key Controls")')
    await expect(goKeysBtn).toBeVisible()

    // Clicking button navigates directly to Admin Approvals / Key Lifecycle
    await goKeysBtn.click()
    await expect(page.locator('text=Shamir Secret Sharing (2-of-3) Custodian State')).toBeVisible()
  })

  test('Shamir bootstrap fresh key in Admin Approvals activates key service', async ({ page }) => {
    let isUnlocked = false

    await page.route(url => url.pathname.endsWith('/keys/status'), async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          adapter: 'split',
          is_unlocked: isUnlocked,
          threshold: 2,
          total_shares: 3,
          current_version: isUnlocked ? 2 : 1,
          shares_provided_count: isUnlocked ? 2 : 0,
          recovered_versions: isUnlocked ? [2] : [],
          message: isUnlocked ? 'Key service is unlocked and ready.' : 'Key service is LOCKED.',
        }),
      })
    })

    await page.route(url => url.pathname.endsWith('/keys/shamir/init'), async (route) => {
      isUnlocked = true
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          version: 2,
          threshold: 2,
          total_shares: 3,
          shares: [
            '1-mockshare1111111111111111111111111111111111111111111111111111111111111111',
            '2-mockshare2222222222222222222222222222222222222222222222222222222222222222',
            '3-mockshare3333333333333333333333333333333333333333333333333333333333333333',
          ],
          warning: 'Distribute shares to custodians immediately.',
        }),
      })
    })

    await page.click('button:has-text("Admin")')
    await page.click('button:has-text("Admin Queue")')

    // Confirm dialog handler
    page.on('dialog', async (dialog) => {
      await dialog.accept()
    })

    await page.click('button:has-text("Bootstrap Fresh Split")')
    await expect(page.locator('text=Fresh Shamir KEK v2 initialized and unlocked in memory.')).toBeVisible()
  })

  test('Access Request view handles decrypted non-image documents with download link', async ({ page }) => {
    await page.route('**/access-request', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          decision: 'raw_image',
          envelope_id: 'test-pdf-env-001',
          content_type: 'application/pdf',
          data_b64: Buffer.from('%PDF-1.4 Mock Decrypted Report Payload').toString('base64'),
          reason: 'Authorized researcher access',
        }),
      })
    })

    await page.click('button:has-text("Admin")')
    await page.click('button:has-text("Access Request")')

    await page.fill('#envelope-id-input', 'test-pdf-env-001')
    await page.click('button:has-text("Submit Access Request")')

    // Verify decision and download button for PDF document
    await expect(page.locator('text=ACCESS GRANTED')).toBeVisible()
    await expect(page.locator('text=Decrypted Payload (application/pdf)')).toBeVisible()
    await expect(page.locator('button:has-text("Download Decrypted File")')).toBeVisible()
  })

  test('Zero secrets, DEKs, or credentials leaked in DOM', async ({ page }) => {
    await page.click('button:has-text("Admin")')

    // Inspect page source text for forbidden secret leaks
    const pageContent = await page.content()
    expect(pageContent).not.toContain('CAS_KEK_V1')
    expect(pageContent).not.toContain('minioadmin')
    expect(pageContent).not.toContain('audit_integrity_key_bytes')
    expect(pageContent).not.toContain('raw_dek')
  })
})
