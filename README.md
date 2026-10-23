# DVWA Web Security Review

A hands-on web security configuration review of **Damn Vulnerable Web Application (DVWA)** running in an authorized local Docker lab.

> **Scope:** All testing was limited to `http://127.0.0.1:8080` in a local training environment. No third-party systems were targeted.

## Overview

This project documents observations from reviewing HTTP responses, selected security headers, session cookie attributes, and web-server directory listing behavior.

### Findings summary

| # | Finding | Preliminary severity | Evidence |
|---|---|---|---|
| 1 | Directory listing enabled under `/dvwa/` and `/dvwa/includes/` | Low–Medium, context-dependent | [Evidence 04](evidence/04-directory-listing.png), [Evidence 05](evidence/05-includes-directory-listing.png) |
| 2 | Selected HTTP security headers absent from the tested login response | Low–Medium, context-dependent | [Evidence 02](evidence/02-login-security-headers.png) |
| 3 | Session cookie hardening attributes not observed | Low–Medium, context-dependent | [Evidence 03](evidence/03-session-cookie-attributes-redacted.png) |

These are preliminary ratings for an intentionally vulnerable lab, not a formal CVSS assessment. The root redirect is recorded as contextual evidence, not a vulnerability by itself.

## Full Report

Read the detailed report for scope, methodology, impact, recommendations, limitations, and verification steps:

**[web-security-review.md](web-security-review.md)**

## Lab Environment

| Component | Purpose |
|---|---|
| Kali Linux | Security testing environment |
| Docker | Runs the local DVWA container |
| DVWA | Intentionally vulnerable training application |
| `curl` | Inspects HTTP responses, headers, cookies, and directory paths |

**Local target:** `http://127.0.0.1:8080`

## Methodology

1. Checked the HTTP response from the root endpoint and noted its redirect to `login.php`.
2. Inspected the login endpoint for selected HTTP security headers.
3. Examined `Set-Cookie` attributes and redacted cookie values in saved evidence.
4. Requested `/dvwa/` and `/dvwa/includes/` to verify whether directory indexes were returned.
5. Documented observations, context-dependent severity, potential impact, and recommended remediation.

Testing was limited to non-destructive requests against the local lab.

## Evidence

| File | Description |
|---|---|
| `evidence/01-initial-http-response.png` | Initial HTTP response and redirect |
| `evidence/02-login-security-headers.png` | Selected security-header check on the login response |
| `evidence/03-session-cookie-attributes-redacted.png` | Cookie attribute inspection with values redacted |
| `evidence/04-directory-listing.png` | Directory listing at `/dvwa/` |
| `evidence/05-includes-directory-listing.png` | Directory listing at `/dvwa/includes/` |

Check that these filenames exactly match the uploaded files. Do not upload screenshots that expose session IDs, credentials, or other sensitive values.

## Key Recommendations

- Disable Apache directory indexing where it is not required (for example, configure `Options -Indexes` in the appropriate server configuration).
- Configure appropriate HTTP security headers, including a tailored Content Security Policy, anti-framing protection, `X-Content-Type-Options: nosniff`, and suitable referrer and permissions policies.
- For production HTTPS deployments, configure session cookies with appropriate `HttpOnly`, `Secure`, and `SameSite` attributes.
- Re-test the affected endpoints after remediation and record the results.

## Limitations

- This was a limited configuration review of a local, intentionally vulnerable training application.
- Only the documented endpoints and responses were checked.
- No full authenticated assessment, source-code review, exploit validation, or production impact analysis was performed.
- Missing headers or cookie attributes alone do not prove that a related exploit is possible.
- Apache version disclosure was observed but is not presented as a standalone vulnerability.

## Skills Demonstrated

- HTTP response and header analysis
- Session cookie configuration review
- Web-server directory listing assessment
- Evidence collection and redaction
- Risk communication and remediation documentation
- Authorized lab testing

## Disclaimer

This project is for educational purposes. Only assess systems you own or have explicit permission to test.
