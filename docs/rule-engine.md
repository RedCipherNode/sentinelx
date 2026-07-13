# Rule Engine

## Overview

Rules are responsible for identifying suspicious indicators.

A rule never determines the final verdict. It only produces findings.

---

## Analysis Pipeline

```text
Input
  ↓
Rules
  ↓
Findings
  ↓
Risk Score
```

---

## Rule Responsibilities

A rule should:

* Inspect one specific behavior or artifact.
* Produce zero or more findings.
* Never modify the scanned content.
* Never execute untrusted content.

---

## Finding

A finding contains:

* Identifier
* Severity
* Title
* Evidence
* Recommendation

Example:

```text
ID: npm.postinstall

Severity: High

Title:
Postinstall lifecycle script detected

Evidence:
package.json -> scripts.postinstall

Recommendation:
Review the script before installing dependencies.
```

---

## Risk Scoring

Rules do not assign the final verdict.

Risk is calculated from all findings collected during analysis.

---

## Design Principles

* One rule, one responsibility.
* Findings represent facts.
* Risk is derived from facts.
* Rules should be deterministic.
* Rules must never execute untrusted content.
