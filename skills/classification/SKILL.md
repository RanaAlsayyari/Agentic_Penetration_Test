# Classification Skill — Instructions for ClassifierAgent

## Purpose
This skill gives you everything needed to classify confirmed vulnerability findings
against three international standards: OWASP Top 10 2025, CWE, and CVSS 3.1.

## Your Workflow (follow this order strictly)

### Step 1 — Read the finding
Take one confirmed finding from the AnalyzerAgent output. Read:
- The finding title
- The technical detail
- The affected parameter and URL
- The analyst's severity estimate

### Step 2 — Map to OWASP 2025
Open `owasp_cwe_map.md`. Find the OWASP category that best fits the finding type.
Show your reasoning: "This is A03 because it involves unsanitized input being
interpreted as a command."
If a finding could fit two categories, choose the most specific one.

### Step 3 — Map to CWE
From the same file, identify the specific CWE ID(s) for this finding.
There may be more than one — list the primary CWE first, secondary ones after.
Show your reasoning: "CWE-89 because the weakness is specifically SQL command injection."

### Step 4 — Score CVSS 3.1
Open `cvss_scoring.md`. Work through each of the 8 metrics one by one.
Write out your reasoning per metric before assigning the value.
Construct the vector string. Calculate the numeric score using the severity table.
Assign the severity label (Critical / High / Medium / Low / Info).

### Step 5 — Compare with analyst estimate
Compare your CVSS severity with the analyst's severity_estimate from the Analyzer.
If they match: note it.
If they differ: write a one-sentence explanation of why, citing the specific CVSS
metric that drove the difference.
Example: "Analyst assessed High; CVSS calculates Medium (5.9) because Attack
Complexity is High — exploitation requires a race condition."

### Step 6 — Output
Return the enriched finding with all classification fields added.
Never modify the Analyzer's original fields — only append new ones.

## Rules
- Never guess a CWE ID from memory — always reference owasp_cwe_map.md
- Never construct a CVSS vector without working through all 8 metrics in cvss_scoring.md
- If a finding genuinely cannot be mapped to any OWASP 2025 category, set
  owasp_category to "Outside OWASP Top 10 2025 Scope" and still assign a CWE and CVSS
- Flag confidence: High / Medium / Low on your classification if ambiguous