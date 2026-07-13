# SentinelX Architecture

## Overview

SentinelX is a pre-execution threat analysis CLI designed to help users evaluate files, archives, projects, and URLs before opening, building, or executing them.

The project focuses on static analysis and explainable findings rather than malware execution or behavioral analysis.

---

## Goals

* Analyze untrusted content without executing it.
* Produce explainable findings instead of opaque verdicts.
* Support multiple input types through a unified analysis pipeline.
* Keep the architecture modular and easy to extend.
* Remain a lightweight, portable command-line application.

---

## Non-Goals

SentinelX is **not**:

* An antivirus.
* An EDR.
* A sandbox.
* A runtime monitoring tool.
* A malware removal utility.

---

## Analysis Scope

Current analysis targets include:

* Files
* Archives
* Source code projects
* URLs

Future versions may introduce additional analyzers without changing the overall architecture.

---

## Architecture

```text
           CLI
            │
            ▼
          Core
            │
   ┌────────┼────────┐
   ▼        ▼        ▼
Scanner   Analyzer  Reporter
            │
            ▼
          Findings
            │
            ▼
        Risk Scoring
```

### CLI

Responsible for:

* Parsing command-line arguments.
* Invoking the Core.
* Displaying results.
* Returning exit codes.

The CLI contains no analysis logic.

---

### Core

The Core owns every analysis capability.

Responsibilities include:

* Input discovery.
* File inspection.
* Archive inspection.
* Project inspection.
* URL inspection.
* Threat analysis.
* Finding generation.
* Risk scoring.
* Report generation.

The Core must remain independent from the CLI.

---

## Analysis Flow

```text
Input

↓

Scanner

↓

Analyzer

↓

Findings

↓

Risk Score

↓

Report
```

Each stage has a single responsibility.

---

## Findings

Every analyzer produces one or more findings.

A finding represents an observable fact.

Examples:

* Double file extension.
* Executable disguised as PDF.
* Suspicious PowerShell command.
* Git hook detected.
* NPM postinstall script.
* Embedded executable.

Findings should contain evidence rather than assumptions.

---

## Risk Assessment

Risk is derived from accumulated findings.

SentinelX does not classify content solely from a single indicator whenever possible.

The scoring implementation is documented separately.

---

## Reports

The reporting layer transforms analysis results into user-friendly output.

Supported formats may include:

* Terminal
* JSON
* HTML
* Markdown

Reports never perform analysis.

---

## Design Principles

### Never execute untrusted content

SentinelX performs static inspection only.

Untrusted files, scripts, projects, and archives must never be executed during analysis.

### Explain every result

Every warning should answer:

* What was detected?
* Why is it suspicious?
* Where was it found?

### Separate facts from conclusions

Evidence should be collected first.

Risk evaluation is derived from the collected evidence.

### Keep dependencies directional

```
CLI
 ↓
Core
```

The Core must not depend on the CLI.

---

## Project Structure

```text
sentinelx/

├── cli/
├── core/
├── docs/
├── tests/
├── Cargo.toml
├── README.md
└── LICENSE
```

The internal organization of `core` should evolve only when real complexity appears, not in anticipation of future features.

---

## Future Extensions

The architecture allows new analyzers to be added without changing the analysis pipeline.

Examples include:

* PE analysis
* Office documents
* PDF inspection
* Image inspection
* Steganography heuristics
* Threat intelligence providers

These extensions should integrate through the existing analysis flow rather than introducing new execution paths.
