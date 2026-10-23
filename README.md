# SWYNEX-Web-Security-Review

A hands-on web security configuration review of **DVWA (Damn Vulnerable Web Application)** in an authorized local lab, completed as **Task 3: Web Security Review** of the SWYNEX Cyber Security Internship.

> **Scope:** All testing was limited to `http://127.0.0.1:8080` in my own Docker lab. No third-party or production system was tested.

---

## At a Glance

| Item | Details |
|------|---------|
| Target | DVWA at `http://127.0.0.1:8080` |
| Environment | Kali Linux (VMware) + Docker |
| Method | Non-destructive `curl` requests, manual review of responses |
| Findings | 3 configuration weaknesses |
| Evidence | 5 screenshots, with session values redacted |
| Result | Low to Medium preliminary risk, context-dependent |

---

## Full Report

**[Read the full web security review](web-security-review.md)**

It covers scope, methodology, impact, recommendations, a verification plan, and limitations.

---

## Summary of Findings

| # | Finding | Where | Preliminary severity | Evidence |
|---|---------|-------|----------------------|----------|
| 1 | Directory listing enabled | `/dvwa/`, `/dvwa/includes/` | Low to Medium | [04](evidence/04-directory-listing.png), [05](evidence/05-includes-directory-listing.png) |
| 2 | Selected HTTP security headers missing | `/login.php` response | Low to Medium | [02](evidence/02-login-security-headers.png) |
| 3 | Session cookie hardening attributes not observed | `Set-Cookie` from `/login.php` | Low to Medium | [03](evidence/03-session-cookie-attributes-redacted.png) |

The root redirect to `login.php` ([01](evidence/01-initial-http-response.png)) is kept as **context only**. It is not a vulnerability.

Ratings are preliminary and depend on context. This is not a formal CVSS assessment.

---

## What Each Finding Means

### 1. Directory listing enabled
**What I saw:** Apache returned an index page listing folders and files under `/dvwa/` and `/dvwa/includes/`.
**Why it matters:** Visitors can learn the application structure and file names, which makes reconnaissance easier.
**What it does not prove:** that source code was downloadable or that any secret was exposed.

### 2. Selected security headers missing
**What I saw:** the `/login.php` response showed none of `X-Frame-Options`, `Content-Security-Policy`, `X-Content-Type-Options`, `Strict-Transport-Security`, `Referrer-Policy`, or `Permissions-Policy`.
**Why it matters:** these headers add browser-side protection against clickjacking, some script-injection effects, and MIME sniffing.
**Context:** the lab runs on plain HTTP, so HSTS is not treated as a standalone finding here.

### 3. Session cookie attributes not observed
**What I saw:** `Set-Cookie` for `PHPSESSID` and `security` showed no `HttpOnly`, `Secure`, or `SameSite`.
**Why it matters:** these attributes limit script access to the cookie, restrict it to HTTPS, and reduce cross-site sending.
**What it does not prove:** that an exploitable XSS or CSRF flaw exists.

---

## Methodology

```text
Request -> Inspect response -> Compare with expected hardening
        -> Capture evidence -> Redact -> Rate -> Recommend
```

1. Requested the root endpoint and recorded the redirect to `login.php`.
2. Inspected the login response for selected security headers.
3. Examined `Set-Cookie` attributes, then redacted cookie values in the evidence.
4. Requested `/dvwa/` and `/dvwa/includes/` to check for directory indexes.
5. Documented each observation with severity, impact, and a fix.

Example commands (run only against your own lab):

```bash
curl -I http://127.0.0.1:8080/
curl -sI http://127.0.0.1:8080/login.php | grep -iE "x-frame-options|content-security-policy|x-content-type-options|strict-transport-security|referrer-policy|permissions-policy"
curl -sI http://127.0.0.1:8080/login.php | grep -i set-cookie     # redact values before sharing
curl -s http://127.0.0.1:8080/dvwa/ | head
```

---

## Recommended Fixes

**Disable directory indexing (Apache):**

```apache
Options -Indexes
```

**Add security headers (Apache `mod_headers`), then tune the CSP to the app:**

```apache
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), camera=(), microphone=()"
Header always set Content-Security-Policy "default-src 'self'"
```

**Harden session cookies (PHP, for an HTTPS deployment):**

```ini
session.cookie_httponly = 1
session.cookie_secure   = 1
session.cookie_samesite = Lax
```

After each change, repeat the same `curl` checks and save new evidence to confirm the fix.

---

## Evidence

| File | What it shows | Used for |
|------|---------------|----------|
| `evidence/01-initial-http-response.png` | Root request and redirect to `login.php` | Context only |
| `evidence/02-login-security-headers.png` | Security-header check on the login response | Finding 2 |
| `evidence/03-session-cookie-attributes-redacted.png` | Cookie attributes, values redacted | Finding 3 |
| `evidence/04-directory-listing.png` | Directory index at `/dvwa/` | Finding 1 |
| `evidence/05-includes-directory-listing.png` | Directory index at `/dvwa/includes/` | Finding 1 |

Session identifiers and cookie values are redacted in the screenshots.

---

## Repository Structure

```text
SWYNEX-Web-Security-Review/
├── README.md
├── web-security-review.md
└── evidence/
    ├── 01-initial-http-response.png
    ├── 02-login-security-headers.png
    ├── 03-session-cookie-attributes-redacted.png
    ├── 04-directory-listing.png
    └── 05-includes-directory-listing.png
```

---

## Limitations

- A limited configuration review of a local, intentionally vulnerable application.
- Only the documented endpoints and responses were checked.
- No authenticated testing, source-code review, exploit validation, or production impact analysis.
- Missing headers or cookie attributes do not prove an exploit is possible.
- Apache version disclosure was seen but is not reported as a standalone vulnerability.

---

## Skills Demonstrated

- HTTP response and header analysis
- Session cookie configuration review
- Directory listing assessment
- Evidence collection and redaction of sensitive values
- Context-aware risk rating without overstating findings
- Clear remediation and verification planning

---

## Author

**Rakesh Babriya**
Computer Science Engineering student (IoT, Blockchain, Cybersecurity)

- GitHub: [realeesh17](https://github.com/realeesh17)
- LinkedIn: [rakeshbabriya](https://www.linkedin.com/in/rakeshbabriya)

---

## Disclaimer

This project is for **educational purposes only**. Assess only systems you own or have explicit permission to test.

---

Completed as part of the **SWYNEX Technologies** internship task series.

`#SWYNEX #Internship #CyberSecurity #WebSecurity #DVWA #LearningInPublic`
