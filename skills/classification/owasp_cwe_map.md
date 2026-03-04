# OWASP Top 10 2025 — Category to CWE Mapping

Source: https://owasp.org/Top10/
Version: OWASP Top 10 2025
Verified: against official OWASP Top 10 2025 website pages

---

## A01:2025 — Broken Access Control

Description: Access control enforces policy such that users cannot act outside
of their intended permissions. Failures lead to unauthorized information
disclosure, modification or destruction of data, or performing business
functions outside the user's limits.

Common patterns:
- Violation of principle of least privilege — access available to anyone by default
- Bypassing access control checks by modifying the URL, internal application state,
  or the HTML page, or using attack tools that modify API requests
- Insecure Direct Object References (IDOR) — viewing or editing someone else's
  account by providing its unique identifier
- API with missing access controls for POST, PUT, and DELETE
- Elevation of privilege — acting as a user without being logged in, or gaining
  admin access as a regular user
- JWT token tampering to elevate privileges
- CORS misconfiguration allowing API access from unauthorized origins
- Force browsing to authenticated or privileged pages

Mapped CWEs (official):
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
  https://cwe.mitre.org/data/definitions/22.html
- CWE-23: Relative Path Traversal
  https://cwe.mitre.org/data/definitions/23.html
- CWE-36: Absolute Path Traversal
  https://cwe.mitre.org/data/definitions/36.html
- CWE-59: Improper Link Resolution Before File Access ('Link Following')
  https://cwe.mitre.org/data/definitions/59.html
- CWE-61: UNIX Symbolic Link (Symlink) Following
  https://cwe.mitre.org/data/definitions/61.html
- CWE-65: Windows Hard Link
  https://cwe.mitre.org/data/definitions/65.html
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
  https://cwe.mitre.org/data/definitions/200.html
- CWE-201: Exposure of Sensitive Information Through Sent Data
  https://cwe.mitre.org/data/definitions/201.html
- CWE-219: Storage of File with Sensitive Data Under Web Root
  https://cwe.mitre.org/data/definitions/219.html
- CWE-276: Incorrect Default Permissions
  https://cwe.mitre.org/data/definitions/276.html
- CWE-281: Improper Preservation of Permissions
  https://cwe.mitre.org/data/definitions/281.html
- CWE-282: Improper Ownership Management
  https://cwe.mitre.org/data/definitions/282.html
- CWE-283: Unverified Ownership
  https://cwe.mitre.org/data/definitions/283.html
- CWE-284: Improper Access Control
  https://cwe.mitre.org/data/definitions/284.html
- CWE-285: Improper Authorization
  https://cwe.mitre.org/data/definitions/285.html
- CWE-352: Cross-Site Request Forgery (CSRF)
  https://cwe.mitre.org/data/definitions/352.html
- CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
  https://cwe.mitre.org/data/definitions/359.html
- CWE-377: Insecure Temporary File
  https://cwe.mitre.org/data/definitions/377.html
- CWE-379: Creation of Temporary File in Directory with Insecure Permissions
  https://cwe.mitre.org/data/definitions/379.html
- CWE-402: Transmission of Private Resources into a New Sphere ('Resource Leak')
  https://cwe.mitre.org/data/definitions/402.html
- CWE-424: Improper Protection of Alternate Path
  https://cwe.mitre.org/data/definitions/424.html
- CWE-425: Direct Request ('Forced Browsing')
  https://cwe.mitre.org/data/definitions/425.html
- CWE-441: Unintended Proxy or Intermediary ('Confused Deputy')
  https://cwe.mitre.org/data/definitions/441.html
- CWE-497: Exposure of Sensitive System Information to an Unauthorized Control Sphere
  https://cwe.mitre.org/data/definitions/497.html
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory
  https://cwe.mitre.org/data/definitions/538.html
- CWE-540: Inclusion of Sensitive Information in Source Code
  https://cwe.mitre.org/data/definitions/540.html
- CWE-548: Exposure of Information Through Directory Listing
  https://cwe.mitre.org/data/definitions/548.html
- CWE-552: Files or Directories Accessible to External Parties
  https://cwe.mitre.org/data/definitions/552.html
- CWE-566: Authorization Bypass Through User-Controlled SQL Primary Key
  https://cwe.mitre.org/data/definitions/566.html
- CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
  https://cwe.mitre.org/data/definitions/601.html
- CWE-615: Inclusion of Sensitive Information in Source Code Comments
  https://cwe.mitre.org/data/definitions/615.html
- CWE-639: Authorization Bypass Through User-Controlled Key
  https://cwe.mitre.org/data/definitions/639.html
- CWE-668: Exposure of Resource to Wrong Sphere
  https://cwe.mitre.org/data/definitions/668.html
- CWE-732: Incorrect Permission Assignment for Critical Resource
  https://cwe.mitre.org/data/definitions/732.html
- CWE-749: Exposed Dangerous Method or Function
  https://cwe.mitre.org/data/definitions/749.html
- CWE-862: Missing Authorization
  https://cwe.mitre.org/data/definitions/862.html
- CWE-863: Incorrect Authorization
  https://cwe.mitre.org/data/definitions/863.html
- CWE-918: Server-Side Request Forgery (SSRF)
  https://cwe.mitre.org/data/definitions/918.html
- CWE-922: Insecure Storage of Sensitive Information
  https://cwe.mitre.org/data/definitions/922.html
- CWE-1275: Sensitive Cookie with Improper SameSite Attribute
  https://cwe.mitre.org/data/definitions/1275.html

OWASP Reference: https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/

---

## A02:2025 — Security Misconfiguration

Description: Security misconfiguration is when a system, application, or cloud
service is set up incorrectly from a security perspective, creating vulnerabilities.
100% of applications tested had some form of misconfiguration.

Common patterns:
- Missing appropriate security hardening across any part of the application stack
- Unnecessary features enabled or installed (ports, services, accounts, frameworks)
- Default accounts and passwords still enabled and unchanged
- Error handling reveals stack traces or overly informative error messages to users
- Latest security features disabled or not configured securely after upgrades
- Security settings in servers, frameworks, libraries not set to secure values
- Server does not send security headers or they are not set to secure values

Mapped CWEs (official):
- CWE-5: J2EE Misconfiguration: Data Transmission Without Encryption
  https://cwe.mitre.org/data/definitions/5.html
- CWE-11: ASP.NET Misconfiguration: Creating Debug Binary
  https://cwe.mitre.org/data/definitions/11.html
- CWE-13: ASP.NET Misconfiguration: Password in Configuration File
  https://cwe.mitre.org/data/definitions/13.html
- CWE-15: External Control of System or Configuration Setting
  https://cwe.mitre.org/data/definitions/15.html
- CWE-16: Configuration
  https://cwe.mitre.org/data/definitions/16.html
- CWE-260: Password in Configuration File
  https://cwe.mitre.org/data/definitions/260.html
- CWE-315: Cleartext Storage of Sensitive Information in a Cookie
  https://cwe.mitre.org/data/definitions/315.html
- CWE-489: Active Debug Code
  https://cwe.mitre.org/data/definitions/489.html
- CWE-526: Exposure of Sensitive Information Through Environmental Variables
  https://cwe.mitre.org/data/definitions/526.html
- CWE-547: Use of Hard-coded, Security-relevant Constants
  https://cwe.mitre.org/data/definitions/547.html
- CWE-611: Improper Restriction of XML External Entity Reference
  https://cwe.mitre.org/data/definitions/611.html
- CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
  https://cwe.mitre.org/data/definitions/614.html
- CWE-776: Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')
  https://cwe.mitre.org/data/definitions/776.html
- CWE-942: Permissive Cross-domain Policy with Untrusted Domains
  https://cwe.mitre.org/data/definitions/942.html
- CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
  https://cwe.mitre.org/data/definitions/1004.html
- CWE-1174: ASP.NET Misconfiguration: Improper Model Validation
  https://cwe.mitre.org/data/definitions/1174.html

OWASP Reference: https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/

---

## A03:2025 — Software Supply Chain Failures

Description: Failures in the process of building, distributing, or updating
software caused by vulnerabilities or malicious changes in third-party code,
tools, or dependencies. Highest average incidence rate at 5.19%.

Common patterns:
- Not tracking versions of all components including transitive dependencies
- Using vulnerable, unsupported, or out-of-date components
- Not scanning for vulnerabilities regularly
- No change management or tracking of changes within the supply chain
- Components from untrusted sources used in production
- Not fixing or upgrading platform, frameworks, dependencies in timely fashion
- CI/CD pipeline has weaker security than the systems it builds and deploys

Mapped CWEs (official):
- CWE-447: Use of Obsolete Function
  https://cwe.mitre.org/data/definitions/447.html
- CWE-1035: 2017 Top 10 A9: Using Components with Known Vulnerabilities
  https://cwe.mitre.org/data/definitions/1035.html
- CWE-1104: Use of Unmaintained Third Party Components
  https://cwe.mitre.org/data/definitions/1104.html
- CWE-1329: Reliance on Component That is Not Updateable
  https://cwe.mitre.org/data/definitions/1329.html
- CWE-1357: Reliance on Insufficiently Trustworthy Component
  https://cwe.mitre.org/data/definitions/1357.html
- CWE-1395: Dependency on Vulnerable Third-Party Component
  https://cwe.mitre.org/data/definitions/1395.html

Note: Full coverage of A03 benefits from NVD API for CVE lookups against
detected component versions. Current skill file provides framework and CWE
mapping only.

OWASP Reference: https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/

---

## A04:2025 — Cryptographic Failures

Description: Failures related to the lack of cryptography, insufficiently strong
cryptography, leaking of cryptographic keys, and related errors. Focuses on
failures related to data in transit and data at rest.

Common patterns:
- Data transmitted without TLS or with weak TLS versions/ciphers
- Old or weak cryptographic algorithms used (MD5, SHA1, CBC mode)
- Default or weak crypto keys, missing key rotation
- Crypto keys checked into source code repositories
- Encryption not enforced — missing browser security headers
- Passwords stored with insufficient hashing (not Argon2/bcrypt/scrypt)
- Weak or predictable random number generation
- Padding oracle vulnerabilities, algorithm downgrade possible

Mapped CWEs (official):
- CWE-261: Weak Encoding for Password
  https://cwe.mitre.org/data/definitions/261.html
- CWE-296: Improper Following of a Certificate's Chain of Trust
  https://cwe.mitre.org/data/definitions/296.html
- CWE-319: Cleartext Transmission of Sensitive Information
  https://cwe.mitre.org/data/definitions/319.html
- CWE-320: Key Management Errors
  https://cwe.mitre.org/data/definitions/320.html
- CWE-321: Use of Hard-coded Cryptographic Key
  https://cwe.mitre.org/data/definitions/321.html
- CWE-322: Key Exchange without Entity Authentication
  https://cwe.mitre.org/data/definitions/322.html
- CWE-323: Reusing a Nonce, Key Pair in Encryption
  https://cwe.mitre.org/data/definitions/323.html
- CWE-324: Use of a Key Past its Expiration Date
  https://cwe.mitre.org/data/definitions/324.html
- CWE-325: Missing Required Cryptographic Step
  https://cwe.mitre.org/data/definitions/325.html
- CWE-326: Inadequate Encryption Strength
  https://cwe.mitre.org/data/definitions/326.html
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm
  https://cwe.mitre.org/data/definitions/327.html
- CWE-328: Reversible One-Way Hash
  https://cwe.mitre.org/data/definitions/328.html
- CWE-329: Not Using a Random IV with CBC Mode
  https://cwe.mitre.org/data/definitions/329.html
- CWE-330: Use of Insufficiently Random Values
  https://cwe.mitre.org/data/definitions/330.html
- CWE-331: Insufficient Entropy
  https://cwe.mitre.org/data/definitions/331.html
- CWE-332: Insufficient Entropy in PRNG
  https://cwe.mitre.org/data/definitions/332.html
- CWE-334: Small Space of Random Values
  https://cwe.mitre.org/data/definitions/334.html
- CWE-335: Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)
  https://cwe.mitre.org/data/definitions/335.html
- CWE-336: Same Seed in Pseudo-Random Number Generator (PRNG)
  https://cwe.mitre.org/data/definitions/336.html
- CWE-337: Predictable Seed in Pseudo-Random Number Generator (PRNG)
  https://cwe.mitre.org/data/definitions/337.html
- CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
  https://cwe.mitre.org/data/definitions/338.html
- CWE-340: Generation of Predictable Numbers or Identifiers
  https://cwe.mitre.org/data/definitions/340.html
- CWE-342: Predictable Exact Value from Previous Values
  https://cwe.mitre.org/data/definitions/342.html
- CWE-347: Improper Verification of Cryptographic Signature
  https://cwe.mitre.org/data/definitions/347.html
- CWE-523: Unprotected Transport of Credentials
  https://cwe.mitre.org/data/definitions/523.html
- CWE-757: Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')
  https://cwe.mitre.org/data/definitions/757.html
- CWE-759: Use of a One-Way Hash without a Salt
  https://cwe.mitre.org/data/definitions/759.html
- CWE-760: Use of a One-Way Hash with a Predictable Salt
  https://cwe.mitre.org/data/definitions/760.html
- CWE-780: Use of RSA Algorithm without OAEP
  https://cwe.mitre.org/data/definitions/780.html
- CWE-916: Use of Password Hash With Insufficient Computational Effort
  https://cwe.mitre.org/data/definitions/916.html
- CWE-1240: Use of a Cryptographic Primitive with a Risky Implementation
  https://cwe.mitre.org/data/definitions/1240.html
- CWE-1241: Use of Predictable Algorithm in Random Number Generator
  https://cwe.mitre.org/data/definitions/1241.html

OWASP Reference: https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/

---

## A05:2025 — Injection

Description: An injection vulnerability allows untrusted user input to be sent
to an interpreter and causes the interpreter to execute parts of that input as
commands. 100% of applications tested, greatest number of CVEs of any category.

Common patterns:
- User-supplied data not validated, filtered, or sanitized
- Dynamic queries or non-parameterized calls used directly in the interpreter
- Unsanitized data used in ORM search parameters
- User input directly concatenated into SQL or OS commands
- Common types: SQL, NoSQL, OS command, ORM, LDAP, EL/OGNL injection
- Cross-site Scripting (XSS) — reflected, stored, DOM-based

Mapped CWEs (official):
- CWE-20: Improper Input Validation
  https://cwe.mitre.org/data/definitions/20.html
- CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')
  https://cwe.mitre.org/data/definitions/74.html
- CWE-76: Improper Neutralization of Equivalent Special Elements
  https://cwe.mitre.org/data/definitions/76.html
- CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')
  https://cwe.mitre.org/data/definitions/77.html
- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
  https://cwe.mitre.org/data/definitions/78.html
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
  https://cwe.mitre.org/data/definitions/79.html
- CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
  https://cwe.mitre.org/data/definitions/80.html
- CWE-83: Improper Neutralization of Script in Attributes in a Web Page
  https://cwe.mitre.org/data/definitions/83.html
- CWE-86: Improper Neutralization of Invalid Characters in Identifiers in Web Pages
  https://cwe.mitre.org/data/definitions/86.html
- CWE-88: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')
  https://cwe.mitre.org/data/definitions/88.html
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
  https://cwe.mitre.org/data/definitions/89.html
- CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')
  https://cwe.mitre.org/data/definitions/90.html
- CWE-91: XML Injection (aka Blind XPath Injection)
  https://cwe.mitre.org/data/definitions/91.html
- CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection')
  https://cwe.mitre.org/data/definitions/93.html
- CWE-94: Improper Control of Generation of Code ('Code Injection')
  https://cwe.mitre.org/data/definitions/94.html
- CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
  https://cwe.mitre.org/data/definitions/95.html
- CWE-96: Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')
  https://cwe.mitre.org/data/definitions/96.html
- CWE-97: Improper Neutralization of Server-Side Includes (SSI) Within a Web Page
  https://cwe.mitre.org/data/definitions/97.html
- CWE-98: Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')
  https://cwe.mitre.org/data/definitions/98.html
- CWE-99: Improper Control of Resource Identifiers ('Resource Injection')
  https://cwe.mitre.org/data/definitions/99.html
- CWE-103: Struts: Incomplete validate() Method Definition
  https://cwe.mitre.org/data/definitions/103.html
- CWE-104: Struts: Form Bean Does Not Extend Validation Class
  https://cwe.mitre.org/data/definitions/104.html
- CWE-112: Missing XML Validation
  https://cwe.mitre.org/data/definitions/112.html
- CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')
  https://cwe.mitre.org/data/definitions/113.html
- CWE-114: Process Control
  https://cwe.mitre.org/data/definitions/114.html
- CWE-115: Misinterpretation of Output
  https://cwe.mitre.org/data/definitions/115.html
- CWE-116: Improper Encoding or Escaping of Output
  https://cwe.mitre.org/data/definitions/116.html
- CWE-129: Improper Validation of Array Index
  https://cwe.mitre.org/data/definitions/129.html
- CWE-159: Improper Handling of Invalid Use of Special Elements
  https://cwe.mitre.org/data/definitions/159.html
- CWE-470: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')
  https://cwe.mitre.org/data/definitions/470.html
- CWE-493: Critical Public Variable Without Final Modifier
  https://cwe.mitre.org/data/definitions/493.html
- CWE-500: Public Static Field Not Marked Final
  https://cwe.mitre.org/data/definitions/500.html
- CWE-564: SQL Injection: Hibernate
  https://cwe.mitre.org/data/definitions/564.html
- CWE-610: Externally Controlled Reference to a Resource in Another Sphere
  https://cwe.mitre.org/data/definitions/610.html
- CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath Injection')
  https://cwe.mitre.org/data/definitions/643.html
- CWE-644: Improper Neutralization of HTTP Headers for Scripting Syntax
  https://cwe.mitre.org/data/definitions/644.html
- CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')
  https://cwe.mitre.org/data/definitions/917.html

OWASP Reference: https://owasp.org/Top10/2025/A05_2025-Injection/

---

## A06:2025 — Insecure Design

Description: A broad category representing missing or ineffective control design.
Distinct from insecure implementation — design flaws require redesign, not just
patching. Focuses on risks related to architectural flaws and business logic.

Common patterns:
- No rate limiting on authentication endpoints (enables credential stuffing)
- Password recovery via guessable security questions
- Business logic flaws (cinema booking attack, cart manipulation)
- Race conditions in critical financial operations
- Missing server-side validation (relying entirely on client-side checks)
- Insecure multi-tenancy data isolation
- No threat modeling performed during design phase

Mapped CWEs (official):
- CWE-73: External Control of File Name or Path
  https://cwe.mitre.org/data/definitions/73.html
- CWE-183: Permissive List of Allowed Inputs
  https://cwe.mitre.org/data/definitions/183.html
- CWE-256: Unprotected Storage of Credentials
  https://cwe.mitre.org/data/definitions/256.html
- CWE-266: Incorrect Privilege Assignment
  https://cwe.mitre.org/data/definitions/266.html
- CWE-269: Improper Privilege Management
  https://cwe.mitre.org/data/definitions/269.html
- CWE-286: Incorrect User Management
  https://cwe.mitre.org/data/definitions/286.html
- CWE-311: Missing Encryption of Sensitive Data
  https://cwe.mitre.org/data/definitions/311.html
- CWE-312: Cleartext Storage of Sensitive Information
  https://cwe.mitre.org/data/definitions/312.html
- CWE-313: Cleartext Storage in a File or on Disk
  https://cwe.mitre.org/data/definitions/313.html
- CWE-316: Cleartext Storage of Sensitive Information in Memory
  https://cwe.mitre.org/data/definitions/316.html
- CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
  https://cwe.mitre.org/data/definitions/362.html
- CWE-382: J2EE Bad Practices: Use of System.exit()
  https://cwe.mitre.org/data/definitions/382.html
- CWE-419: Unprotected Primary Channel
  https://cwe.mitre.org/data/definitions/419.html
- CWE-434: Unrestricted Upload of File with Dangerous Type
  https://cwe.mitre.org/data/definitions/434.html
- CWE-436: Interpretation Conflict
  https://cwe.mitre.org/data/definitions/436.html
- CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')
  https://cwe.mitre.org/data/definitions/444.html
- CWE-451: User Interface (UI) Misrepresentation of Critical Information
  https://cwe.mitre.org/data/definitions/451.html
- CWE-454: External Initialization of Trusted Variables or Data Stores
  https://cwe.mitre.org/data/definitions/454.html
- CWE-472: External Control of Assumed-Immutable Web Parameter
  https://cwe.mitre.org/data/definitions/472.html
- CWE-501: Trust Boundary Violation
  https://cwe.mitre.org/data/definitions/501.html
- CWE-522: Insufficiently Protected Credentials
  https://cwe.mitre.org/data/definitions/522.html
- CWE-525: Use of Web Browser Cache Containing Sensitive Information
  https://cwe.mitre.org/data/definitions/525.html
- CWE-539: Use of Persistent Cookies Containing Sensitive Information
  https://cwe.mitre.org/data/definitions/539.html
- CWE-598: Use of GET Request Method With Sensitive Query Strings
  https://cwe.mitre.org/data/definitions/598.html
- CWE-602: Client-Side Enforcement of Server-Side Security
  https://cwe.mitre.org/data/definitions/602.html
- CWE-628: Function Call with Incorrectly Specified Arguments
  https://cwe.mitre.org/data/definitions/628.html
- CWE-642: External Control of Critical State Data
  https://cwe.mitre.org/data/definitions/642.html
- CWE-646: Reliance on File Name or Extension of Externally-Supplied File
  https://cwe.mitre.org/data/definitions/646.html
- CWE-653: Insufficient Compartmentalization
  https://cwe.mitre.org/data/definitions/653.html
- CWE-656: Reliance on Security Through Obscurity
  https://cwe.mitre.org/data/definitions/656.html
- CWE-657: Violation of Secure Design Principles
  https://cwe.mitre.org/data/definitions/657.html
- CWE-676: Use of Potentially Dangerous Function
  https://cwe.mitre.org/data/definitions/676.html
- CWE-693: Protection Mechanism Failure
  https://cwe.mitre.org/data/definitions/693.html
- CWE-799: Improper Control of Interaction Frequency
  https://cwe.mitre.org/data/definitions/799.html
- CWE-807: Reliance on Untrusted Inputs in a Security Decision
  https://cwe.mitre.org/data/definitions/807.html
- CWE-841: Improper Enforcement of Behavioral Workflow
  https://cwe.mitre.org/data/definitions/841.html
- CWE-1021: Improper Restriction of Rendered UI Layers or Frames
  https://cwe.mitre.org/data/definitions/1021.html
- CWE-1022: Use of Web Link to Untrusted Target with window.opener Access
  https://cwe.mitre.org/data/definitions/1022.html
- CWE-1125: Excessive Attack Surface
  https://cwe.mitre.org/data/definitions/1125.html

OWASP Reference: https://owasp.org/Top10/2025/A06_2025-Insecure_Design/

---

## A07:2025 — Authentication Failures

Description: Authentication and session management implemented incorrectly,
allowing attackers to compromise passwords, keys, or session tokens, or exploit
implementation flaws to assume other users' identities.

Common patterns:
- Permits credential stuffing or brute force without blocking (no rate limiting)
- Permits default, weak, or well-known passwords
- Allows creation of accounts with known-breached credentials
- Weak or ineffective credential recovery (security questions)
- Plain text, encrypted, or weakly hashed passwords
- Missing or ineffective multi-factor authentication
- Session identifier exposed in URL
- Same session identifier reused after successful login
- Sessions not invalidated after logout or inactivity

Mapped CWEs (official):
- CWE-258: Empty Password in Configuration File
  https://cwe.mitre.org/data/definitions/258.html
- CWE-259: Use of Hard-coded Password
  https://cwe.mitre.org/data/definitions/259.html
- CWE-287: Improper Authentication
  https://cwe.mitre.org/data/definitions/287.html
- CWE-288: Authentication Bypass Using an Alternate Path or Channel
  https://cwe.mitre.org/data/definitions/288.html
- CWE-289: Authentication Bypass by Alternate Name
  https://cwe.mitre.org/data/definitions/289.html
- CWE-290: Authentication Bypass by Spoofing
  https://cwe.mitre.org/data/definitions/290.html
- CWE-291: Reliance on IP Address for Authentication
  https://cwe.mitre.org/data/definitions/291.html
- CWE-293: Using Referer Field for Authentication
  https://cwe.mitre.org/data/definitions/293.html
- CWE-294: Authentication Bypass by Capture-replay
  https://cwe.mitre.org/data/definitions/294.html
- CWE-295: Improper Certificate Validation
  https://cwe.mitre.org/data/definitions/295.html
- CWE-297: Improper Validation of Certificate with Host Mismatch
  https://cwe.mitre.org/data/definitions/297.html
- CWE-298: Improper Validation of Certificate with Host Mismatch
  https://cwe.mitre.org/data/definitions/298.html
- CWE-299: Improper Validation of Certificate with Host Mismatch
  https://cwe.mitre.org/data/definitions/299.html
- CWE-300: Channel Accessible by Non-Endpoint
  https://cwe.mitre.org/data/definitions/300.html
- CWE-302: Authentication Bypass by Assumed-Immutable Data
  https://cwe.mitre.org/data/definitions/302.html
- CWE-303: Incorrect Implementation of Authentication Algorithm
  https://cwe.mitre.org/data/definitions/303.html
- CWE-304: Missing Critical Step in Authentication
  https://cwe.mitre.org/data/definitions/304.html
- CWE-305: Authentication Bypass by Primary Weakness
  https://cwe.mitre.org/data/definitions/305.html
- CWE-306: Missing Authentication for Critical Function
  https://cwe.mitre.org/data/definitions/306.html
- CWE-307: Improper Restriction of Excessive Authentication Attempts
  https://cwe.mitre.org/data/definitions/307.html
- CWE-308: Use of Single-factor Authentication
  https://cwe.mitre.org/data/definitions/308.html
- CWE-309: Use of Password System for Primary Authentication
  https://cwe.mitre.org/data/definitions/309.html
- CWE-346: Origin Validation Error
  https://cwe.mitre.org/data/definitions/346.html
- CWE-350: Reliance on Reverse DNS Resolution for a Security-Critical Action
  https://cwe.mitre.org/data/definitions/350.html
- CWE-384: Session Fixation
  https://cwe.mitre.org/data/definitions/384.html
- CWE-521: Weak Password Requirements
  https://cwe.mitre.org/data/definitions/521.html
- CWE-613: Insufficient Session Expiration
  https://cwe.mitre.org/data/definitions/613.html
- CWE-620: Unverified Password Change
  https://cwe.mitre.org/data/definitions/620.html
- CWE-640: Weak Password Recovery Mechanism for Forgotten Password
  https://cwe.mitre.org/data/definitions/640.html
- CWE-798: Use of Hard-coded Credentials
  https://cwe.mitre.org/data/definitions/798.html
- CWE-940: Improper Verification of Source of a Communication Channel
  https://cwe.mitre.org/data/definitions/940.html
- CWE-941: Incorrectly Specified Destination in a Communication Channel
  https://cwe.mitre.org/data/definitions/941.html
- CWE-1390: Weak Authentication
  https://cwe.mitre.org/data/definitions/1390.html
- CWE-1391: Use of Weak Credentials
  https://cwe.mitre.org/data/definitions/1391.html
- CWE-1392: Use of Default Credentials
  https://cwe.mitre.org/data/definitions/1392.html
- CWE-1393: Use of Default Password
  https://cwe.mitre.org/data/definitions/1393.html

OWASP Reference: https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/

---

## A08:2025 — Software or Data Integrity Failures

Description: Failures to maintain trust boundaries and verify the integrity of
software, code, and data artifacts at a lower level than Supply Chain Failures.
Focuses on assumptions about software updates and critical data without
verifying integrity.

Common patterns:
- Application relies on plugins or libraries from untrusted sources or CDNs
- Insecure CI/CD pipeline without integrity checks
- Auto-update functionality without sufficient integrity verification
- Insecure deserialization — objects encoded in a structure an attacker can modify

Mapped CWEs (official):
- CWE-345: Insufficient Verification of Data Authenticity
  https://cwe.mitre.org/data/definitions/345.html
- CWE-353: Missing Support for Integrity Check
  https://cwe.mitre.org/data/definitions/353.html
- CWE-426: Untrusted Search Path
  https://cwe.mitre.org/data/definitions/426.html
- CWE-427: Uncontrolled Search Path Element
  https://cwe.mitre.org/data/definitions/427.html
- CWE-494: Download of Code Without Integrity Check
  https://cwe.mitre.org/data/definitions/494.html
- CWE-502: Deserialization of Untrusted Data
  https://cwe.mitre.org/data/definitions/502.html
- CWE-506: Embedded Malicious Code
  https://cwe.mitre.org/data/definitions/506.html
- CWE-509: Replicating Malicious Code (Virus or Worm)
  https://cwe.mitre.org/data/definitions/509.html
- CWE-565: Reliance on Cookies without Validation and Integrity Checking
  https://cwe.mitre.org/data/definitions/565.html
- CWE-784: Reliance on Cookies without Validation and Integrity Checking in a Security Decision
  https://cwe.mitre.org/data/definitions/784.html
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere
  https://cwe.mitre.org/data/definitions/829.html
- CWE-830: Inclusion of Web Functionality from an Untrusted Source
  https://cwe.mitre.org/data/definitions/830.html
- CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
  https://cwe.mitre.org/data/definitions/915.html
- CWE-926: Improper Export of Android Application Components
  https://cwe.mitre.org/data/definitions/926.html

OWASP Reference: https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/

---

## A09:2025 — Security Logging and Alerting Failures

Description: Insufficient logging, detection, monitoring, and active response
allows attackers to persist, pivot, and tamper without detection. Alerting is
explicitly part of this category — detection without alerting provides no
operational value.

Common patterns:
- Auditable events (logins, failures, high-value transactions) not logged
- Warnings and errors generate no or unclear log messages
- Log integrity not protected from tampering
- Application and API logs not monitored for suspicious activity
- Logs stored only locally with no backup
- No alerting thresholds or response escalation processes
- Penetration tests and DAST scans do not trigger alerts
- Sensitive information logged (PII, credentials)

Mapped CWEs (official):
- CWE-117: Improper Output Neutralization for Logs
  https://cwe.mitre.org/data/definitions/117.html
- CWE-221: Information Loss of Omission
  https://cwe.mitre.org/data/definitions/221.html
- CWE-223: Omission of Security-relevant Information
  https://cwe.mitre.org/data/definitions/223.html
- CWE-532: Insertion of Sensitive Information into Log File
  https://cwe.mitre.org/data/definitions/532.html
- CWE-778: Insufficient Logging
  https://cwe.mitre.org/data/definitions/778.html

OWASP Reference: https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/

---

## A10:2025 — Mishandling of Exceptional Conditions

Description: A new category for 2025. Programs fail to prevent, detect, and
respond to unusual and unpredictable situations, leading to crashes, unexpected
behavior, and sometimes vulnerabilities. 24 CWEs mapped. Covers improper error
handling, logical errors, failing open, and other scenarios from abnormal
conditions.

Common patterns:
- Unhandled exceptions revealing stack traces, file paths, or internal architecture
- Application crashes on malformed input exposing debug information
- Missing or incomplete input validation causing unexpected state
- Inconsistent exception handling — not handled at the function where they occur
- Exceptions not handled at all, leaving system in unknown state
- Failing open instead of failing closed in security decisions
- Not rolling back transactions properly on partial failure (state corruption)
- Resource exhaustion from not releasing resources after exceptions

Mapped CWEs (official):
- CWE-209: Generation of Error Message Containing Sensitive Information
  https://cwe.mitre.org/data/definitions/209.html
- CWE-215: Insertion of Sensitive Information Into Debugging Code
  https://cwe.mitre.org/data/definitions/215.html
- CWE-234: Failure to Handle Missing Parameter
  https://cwe.mitre.org/data/definitions/234.html
- CWE-235: Improper Handling of Extra Parameters
  https://cwe.mitre.org/data/definitions/235.html
- CWE-248: Uncaught Exception
  https://cwe.mitre.org/data/definitions/248.html
- CWE-252: Unchecked Return Value
  https://cwe.mitre.org/data/definitions/252.html
- CWE-274: Improper Handling of Insufficient Privileges
  https://cwe.mitre.org/data/definitions/274.html
- CWE-280: Improper Handling of Insufficient Permissions or Privileges
  https://cwe.mitre.org/data/definitions/280.html
- CWE-369: Divide By Zero
  https://cwe.mitre.org/data/definitions/369.html
- CWE-390: Detection of Error Condition Without Action
  https://cwe.mitre.org/data/definitions/390.html
- CWE-391: Unchecked Error Condition
  https://cwe.mitre.org/data/definitions/391.html
- CWE-394: Unexpected Status Code or Return Value
  https://cwe.mitre.org/data/definitions/394.html
- CWE-396: Declaration of Catch for Generic Exception
  https://cwe.mitre.org/data/definitions/396.html
- CWE-397: Declaration of Throws for Generic Exception
  https://cwe.mitre.org/data/definitions/397.html
- CWE-460: Improper Cleanup on Thrown Exception
  https://cwe.mitre.org/data/definitions/460.html
- CWE-476: NULL Pointer Dereference
  https://cwe.mitre.org/data/definitions/476.html
- CWE-478: Missing Default Case in Multiple Condition Expression
  https://cwe.mitre.org/data/definitions/478.html
- CWE-484: Omitted Break Statement in Switch
  https://cwe.mitre.org/data/definitions/484.html
- CWE-550: Server-generated Error Message Containing Sensitive Information
  https://cwe.mitre.org/data/definitions/550.html
- CWE-636: Not Failing Securely ('Failing Open')
  https://cwe.mitre.org/data/definitions/636.html
- CWE-703: Improper Check or Handling of Exceptional Conditions
  https://cwe.mitre.org/data/definitions/703.html
- CWE-754: Improper Check for Unusual or Exceptional Conditions
  https://cwe.mitre.org/data/definitions/754.html
- CWE-755: Improper Handling of Exceptional Conditions
  https://cwe.mitre.org/data/definitions/755.html
- CWE-756: Missing Custom Error Page
  https://cwe.mitre.org/data/definitions/756.html

OWASP Reference: https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/