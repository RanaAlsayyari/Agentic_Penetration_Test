# CVSS 3.1 Scoring Guide

Source: https://www.first.org/cvss/v3.1/specification-document
Version: CVSS 3.1 (current widely-adopted version)

---

## What is a CVSS Vector String?

A CVSS vector string encodes all 8 metric values into one readable string.
Format: CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_

Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = Score 9.8 (Critical)
This means: Network-accessible, Low complexity, No privileges needed,
No user interaction, Unchanged scope, High impact on all three CIA pillars.

---

## The 8 Metrics — Work Through Each One

### Metric 1: Attack Vector (AV)
How the attacker reaches the vulnerable component.

| Value | Code | Description | When to use |
|---|---|---|---|
| Network | N | Exploitable remotely over the internet | Most web vulnerabilities |
| Adjacent | A | Requires access to the same network segment | LAN-based attacks |
| Local | L | Requires local system access | Local file vulnerabilities |
| Physical | P | Requires physical access to device | Hardware attacks |

**Web app default:** Almost always N (Network) for web vulnerabilities.

---

### Metric 2: Attack Complexity (AC)
Conditions beyond attacker control that must exist.

| Value | Code | Description | When to use |
|---|---|---|---|
| Low | L | No special conditions needed, repeatable | SQLi, XSS, most injection |
| High | H | Specific conditions required, not always reliable | Race conditions, requires specific config |

**Web app default:** L for most injection and access control findings.
Use H only if exploitation genuinely requires timing, specific state, or rare conditions.

---

### Metric 3: Privileges Required (PR)
Level of privileges an attacker must have before exploiting.

| Value | Code | Description | When to use |
|---|---|---|---|
| None | N | No authentication required | Unauthenticated findings |
| Low | L | Basic user privileges sufficient | Authenticated user can exploit |
| High | H | Admin or elevated privileges needed | Only admins can trigger |

---

### Metric 4: User Interaction (UI)
Whether exploitation requires action from a user other than the attacker.

| Value | Code | Description | When to use |
|---|---|---|---|
| None | N | No user interaction needed | SQLi, server-side vulnerabilities |
| Required | R | A user must take some action | Reflected XSS (victim must click link) |

**Note:** Stored XSS = UI:N (victim just visits the page, no special action).
Reflected XSS = UI:R (victim must be tricked into clicking a crafted URL).

---

### Metric 5: Scope (S)
Whether a vulnerability can affect resources beyond its security scope.

| Value | Code | Description | When to use |
|---|---|---|---|
| Unchanged | U | Impact limited to the vulnerable component | Most web findings |
| Changed | C | Impact extends to other components | XSS affecting browser, SSRF reaching internal services |

---

### Metric 6: Confidentiality Impact (C)
Impact on confidentiality of information.

| Value | Code | Description |
|---|---|---|
| None | N | No impact on confidentiality |
| Low | L | Some restricted information disclosed |
| High | H | All information within the component disclosed |

---

### Metric 7: Integrity Impact (I)
Impact on integrity (ability to modify information).

| Value | Code | Description |
|---|---|---|
| None | N | No impact on integrity |
| Low | L | Some data can be modified, limited scope |
| High | H | Total loss of integrity, attacker can modify any data |

---

### Metric 8: Availability Impact (A)
Impact on availability of the component.

| Value | Code | Description |
|---|---|---|
| None | N | No impact on availability |
| Low | L | Reduced performance or interruptions |
| High | H | Total loss of availability |

---

## Common Web Vulnerability Vector Reference

Use these as starting points — always adjust based on the specific finding context.

| Finding Type | Typical Vector | Typical Score | Reasoning |
|---|---|---|---|
| SQL Injection (unauthenticated, full DB access) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 Critical | Network, easy, no auth, full CIA impact |
| SQL Injection (authenticated user) | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 8.8 High | Same but requires login |
| Stored XSS | AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N | 6.4 Medium | Scope changes (affects other users' browsers) |
| Reflected XSS | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 Medium | User must click crafted link |
| Broken Access Control (IDOR) | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | 8.1 High | Authenticated, can read/modify other users' data |
| Missing Auth on Admin Function | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 Critical | No privileges, full impact |
| SSRF (internal network access) | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N | 8.6 High | Scope changed, confidentiality impact |
| Sensitive Data in HTTP (cleartext) | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N | 5.9 Medium | Requires MITM position (AC:H) |
| Missing Security Headers (CSP/HSTS) | AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N | 3.1 Low | Hard to exploit directly, limited impact |
| Directory Listing | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 Medium | Information disclosure |
| OS Command Injection | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | 10.0 Critical | Full server compromise |

---

## CVSS Score to Severity Label

| Score Range | Severity Label |
|---|---|
| 9.0 – 10.0 | Critical |
| 7.0 – 8.9 | High |
| 4.0 – 6.9 | Medium |
| 0.1 – 3.9 | Low |
| 0.0 | Info / None |

---

## Score Calculation (simplified)

CVSS scores are calculated by a formula defined in the CVSS 3.1 specification.
For the purposes of this system, use the reference table above for common findings.
For findings not in the table, use the CVSS 3.1 calculator at:
https://www.first.org/cvss/calculator/3.1

The key principle: a finding with Network access, Low complexity, No privileges,
No user interaction, and High impact on all three CIA pillars always scores 9.8.
Each metric that increases attacker difficulty or reduces impact lowers the score.

---

## Discrepancy Note Template

When your CVSS severity differs from the Analyst's severity_estimate, use this format:
"Analyst assessed [X]; CVSS 3.1 calculates [Y] ([score]) because [specific metric]
reflects [reason]. Example: Attack Complexity is High because exploitation requires
[specific condition]."