# Security Audit

- **Date:** 2026-04-22
- **Scope:** C++ application code, Remote web assets, CI workflows, vendored dependencies
- **Method:** Static inspection and pattern scan (`rg`) only

## Executive Summary
The repository has meaningful security controls (CodeQL workflow, dependency review action, explicit CVE mention in changelog), but still carries risk from legacy C/C++ code patterns, permissive remote-UI CSP defaults, and old vendored components.

## Severity-Ranked Findings

### High
1. **Potential unsafe string handling in core protocol path.**
   - `Envy/KadProtocol.cpp` contains direct `strcpy` usage on keyword data.
   - Risk: buffer overflow or memory corruption if source constraints drift.
2. **Legacy external-process/shell invocation surface is broad.**
   - Many `ShellExecute` call sites in `Envy/` and utility libraries.
   - Risk: command/path injection if any path/URL reaches these APIs unsafely.
3. **Outdated vendored components increase latent CVE risk.**
   - MiniUPnPc identifies as 2.0 (2016-era headers).
   - UnRAR headers indicate 5.30 lineage (2015-era).

### Medium
1. **Client-side security controls in `Remote/security-config.js` are advisory, not authoritative.**
   - CSP values include `'unsafe-inline'` by default.
2. **Security scanning is split across multiple workflows and may miss non-default paths if workflows drift.**
3. **No repository-wide secret scanning baseline config committed (e.g., gitleaks/trufflehog policy file).**

### Low
1. **Security assumptions are distributed across code and docs rather than captured as an explicit threat model.**
2. **No documented cryptographic policy (approved algorithms / deprecation strategy) for legacy hashes.**

## OWASP-Oriented Review Notes
- **A01 Broken Access Control:** Remote admin/auth model documented, but no single authoritative authz doc.
- **A03 Injection:** Command invocation and URL execution points need strict validation contracts.
- **A05 Security Misconfiguration:** CSP relaxed for inline scripts.
- **A06 Vulnerable/Outdated Components:** Present in vendored services.
- **A09 Logging/Monitoring:** Logging exists, but no documented centralized security event strategy.

## Secrets Handling Review
- No hardcoded production secrets were found in the inspected files.
- Session/token references in `Remote/` appear to be templates/config usage, not leaked credentials.
- Recommendation: add automated secret scanning in CI and pre-commit guidance.

## Recommendations
1. Replace unsafe C string calls in first-party code with bounded/safer alternatives.
2. Centralize and sanitize all shell/URL launch flows behind one validated helper.
3. Upgrade or isolate high-risk vendored libraries; add SBOM + vulnerability tracking.
4. Harden remote UI CSP and enforce server-side CSRF/authz checks as primary control.
5. Add explicit threat model and security architecture document to `/docs`.
