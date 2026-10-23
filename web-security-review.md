# DVWA Web Security Review

## 1. Executive Summary

A limited security configuration review was performed against **Damn Vulnerable Web Application (DVWA)** running in an isolated local lab. The review used `curl` to inspect HTTP responses, cookie attributes, and directory paths exposed by the web server.

The evidence supports three findings for documentation:

1. **Directory listing enabled** under `/dvwa/` and `/dvwa/includes/`.
2. **Selected HTTP security headers missing** from the observed `/login.php` response.
3. **Session-cookie hardening attributes not observed** in the tested HTTP response.

These observations are from an intentionally vulnerable training application on `127.0.0.1:8080`; they must not be interpreted as evidence about an external or production system. Severity ratings below are preliminary and should be adjusted to the application's deployment context.

## 2. Scope and Environment

- **Target:** DVWA running locally at `http://127.0.0.1:8080`
- **Target endpoints:** `/`, `/login.php`, `/dvwa/`, `/dvwa/includes/`, and `/security.php`
- **Testing host:** Kali Linux in VMware
- **Deployment:** Docker-hosted local training application
- **Tools:** `curl`
- **Authorization:** Self-owned, intentionally vulnerable lab; no external systems were tested.

## 3. Methodology

1. Requested the application root and recorded its HTTP redirect to `login.php`.
2. Inspected the login response headers and checked for selected security headers.
3. Examined `Set-Cookie` response headers, then redacted cookie values in the saved evidence.
4. Requested `/dvwa/` and `/dvwa/includes/` and inspected the returned directory index pages.
5. Matched observations to screenshots and documented recommended mitigations.

Testing was limited to non-destructive HTTP requests. No exploit attempts or authenticated testing are represented by this report.

## 4. Findings

### Finding 01 — Directory Listing Enabled

- **Affected components:** `/dvwa/` and `/dvwa/includes/`
- **Preliminary severity:** Low to Medium, depending on exposure and the sensitivity of listed files
- **Confidence:** High
- **Evidence:** `evidence/04-directory-listing.png`, `evidence/05-includes-directory-listing.png`

**Observation**

Requests to `/dvwa/` and `/dvwa/includes/` returned Apache-generated directory index pages. The output listed subdirectories and files, including `css/`, `images/`, `includes/`, `js/`, `dvwaPage.inc.php`, and `dvwaPhpIds.inc.php`.

**Potential impact**

Directory listings reveal application structure and file names to visitors. This can make reconnaissance easier and may expose sensitive files if such files are present in a listed directory. The screenshots establish that names are listed; they do not establish that the listed PHP source code is downloadable or that secrets were exposed.

**Recommendation**

Disable directory indexing for the web root and relevant directories (for Apache, configure `Options -Indexes` in the appropriate server or directory configuration). Restrict direct access to internal or non-public files, and verify that the server returns an appropriate application page or `403 Forbidden` instead of a directory index.

### Finding 02 — Selected HTTP Security Headers Missing

- **Affected component:** `/login.php` response
- **Preliminary severity:** Low to Medium, depending on the application and threat model
- **Confidence:** High for the specific headers checked in the captured response
- **Evidence:** `evidence/02-login-security-headers.png`

**Observation**

The captured response returned `HTTP/1.1 200 OK`. The header-filter command did not display any of the selected headers: `X-Frame-Options`, `Content-Security-Policy`, `X-Content-Type-Options`, `Strict-Transport-Security`, `Referrer-Policy`, or `Permissions-Policy`.

This establishes that those headers were not present in that particular response as tested. It does not prove that every response from the application omits them.

**Potential impact**

- Without an anti-framing policy, a page may be more susceptible to clickjacking if it can be framed by an attacker-controlled site.
- Without a suitable Content Security Policy, the browser has fewer restrictions to help limit some script-injection consequences.
- Without `X-Content-Type-Options: nosniff`, browsers may perform MIME sniffing in some contexts.
- Missing referrer and permissions policies can reduce control over referrer information and browser features.

**Recommendation**

Configure and verify appropriate headers across relevant responses. Consider `Content-Security-Policy` tailored to the application's resources, `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors` directive, `X-Content-Type-Options: nosniff`, a suitable `Referrer-Policy`, and a restrictive `Permissions-Policy`.

**Context note:** The lab was accessed over plain HTTP on localhost. HSTS is designed for HTTPS and should be evaluated on an HTTPS deployment; its absence on this local HTTP response alone should not be treated as a standalone production finding.

### Finding 03 — Session Cookie Attributes Not Observed

- **Affected component:** Cookies returned by `/login.php`
- **Preliminary severity:** Low to Medium; confirm application behavior and deployment context
- **Confidence:** High for the attributes visible in the captured response
- **Evidence:** `evidence/03-session-cookie-attributes-redacted.png`

**Observation**

The response contained `Set-Cookie` headers for `PHPSESSID` and `security`. In the captured output, the cookie directives shown did not include `HttpOnly`, `Secure`, or `SameSite`. Cookie values were redacted in the saved evidence.

**Potential impact**

- Missing `HttpOnly` on a session cookie can allow client-side scripts to read the cookie if a script-injection vulnerability is present.
- Missing `SameSite` can weaken the browser's cross-site cookie sending restrictions and may increase cross-site request forgery exposure depending on application behavior.
- The `Secure` attribute helps prevent cookies from being sent over unencrypted HTTP. It should be used for cookies on an HTTPS deployment.

The screenshot does not independently prove that an exploitable XSS or CSRF vulnerability exists.

**Recommendation**

For production over HTTPS, set `HttpOnly` and `Secure` on session cookies and choose an appropriate `SameSite` policy (often `Lax` unless the application's flow requires otherwise). Review the `security` cookie separately to determine whether it needs to be client-accessible, and avoid placing sensitive state in client-controlled cookies. Re-test the actual deployed response after configuration changes.

## 5. Supporting Evidence

| Evidence file | What it demonstrates | Use |
|---|---|---|
| `evidence/01-initial-http-response.png` | Root request returns `302 Found` and redirects to `login.php` | Context only; not a vulnerability by itself |
| `evidence/02-login-security-headers.png` | `HTTP/1.1 200 OK` and no output for the selected security-header filter | Finding 02 |
| `evidence/03-session-cookie-attributes-redacted.png` | Redacted `Set-Cookie` output preserving visible cookie directives | Finding 03 |
| `evidence/04-directory-listing.png` | Directory index for `/dvwa/` | Finding 01 |
| `evidence/05-includes-directory-listing.png` | Directory index for `/dvwa/includes/` | Finding 01, additional supporting evidence |

Ensure the filenames and case in the repository match the names above. Do not publish unredacted session identifiers or authenticated cookies.

## 6. Remediation and Verification Plan

1. Disable directory indexing and re-request both directory paths; confirm the index is no longer returned.
2. Configure security headers appropriate to the app and deployment, then inspect the relevant response headers again.
3. Set cookie attributes appropriate to the production HTTPS deployment and verify the resulting `Set-Cookie` directives.
4. Re-run the same checks after changes and attach new evidence showing the results.

## 7. Limitations

- This was a limited configuration review of a local, intentionally vulnerable training app.
- Findings are based on the specific endpoints and responses tested; other routes and methods may behave differently.
- No full authenticated assessment, exploit validation, source-code review, or production impact analysis was performed.
- Risk ratings are preliminary, not a formal CVSS score.
- Apache version disclosure in a response is not reported as a standalone vulnerability because version disclosure alone does not establish exploitable risk.

## 8. Conclusion

The captured evidence supports documenting directory listing, missing selected HTTP security headers, and missing cookie-hardening attributes as configuration weaknesses in the local DVWA lab. The root redirect is retained as contextual evidence only. Apply the recommended hardening, re-test, and update the report with verified results before treating any item as remediated.

---

**Disclaimer:** This report is for educational purposes and records testing of a local, authorized training environment only. Test only systems you own or have explicit permission to assess.
