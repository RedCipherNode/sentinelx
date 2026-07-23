# SentinelX Architecture

## Overview

SentinelX is an evidence-driven security inspection engine that analyzes digital targets before they are opened, executed, or trusted.

Rather than producing isolated detections, SentinelX performs a structured investigation that collects observations, derives findings, produces assessments, and presents explainable results.

The architecture is organized into independent domains with clearly defined responsibilities, allowing new target types and inspection capabilities to be introduced without changing the overall inspection pipeline.

---

# Design Principles

SentinelX follows several fundamental architectural principles.

- Never execute untrusted content.
- Collect evidence before producing assessments.
- Every assessment must be supported by observable evidence.
- Separate inspection from analysis and assessment.
- Keep responsibilities isolated.
- Maintain one-directional dependencies.
- Design for extensibility through composition rather than modification.
- Present information at multiple levels of detail without changing the underlying investigation model.

---

# Architectural Domains

The inspection pipeline is composed of independent domains.

```text
Inspection Target

↓

Routing

↓

Inspection

↓

Observation

↓

Analysis

↓

Finding

↓

Assessment

↓

Presentation

↓

Report
```

Each domain owns a single responsibility and communicates through well-defined artifacts.

---

# Domain Responsibilities

## Routing

Routing determines how an inspection target should be processed.

Responsibilities

- Resolve inspection target type.
- Select the appropriate inspector.
- Dispatch inspection requests.

Routing never performs inspection.

---

## Inspection

Inspection collects factual information directly from a target.

Responsibilities

- Read target structure.
- Extract metadata.
- Inspect format-specific structures.
- Produce observations.
- Discover additional inspection targets when applicable.

Inspection never performs threat reasoning or risk scoring.

---

## Observation

Observations represent raw evidence collected during inspection.

Examples include

- File metadata
- PE headers
- Archive structure
- Document properties
- Imported libraries
- Embedded resources

Observations contain facts only.

Observations never express conclusions.

---

## Analysis

Analysis evaluates observations to identify meaningful behaviors, relationships, and security-relevant characteristics.

Responsibilities

- Correlate observations.
- Detect suspicious patterns.
- Produce findings.

Analysis never assigns overall risk.

---

## Finding

Findings describe meaningful conclusions derived from observations.

Examples include

- Embedded executable detected
- Packed executable
- Suspicious import table
- Obfuscated script
- Potential downloader behavior

Every finding must be traceable back to supporting observations.

---

## Assessment

Assessment evaluates findings to determine the overall security posture of the inspected target.

Responsibilities

- Determine severity.
- Explain impact.
- Summarize security posture.

Assessments never exist without supporting findings.

---

## Presentation

Presentation transforms investigation data into user-facing outputs.

Presentation supports multiple presentation modes while using the same investigation model.

Presentation never performs inspection, analysis, or assessment.

---

# Investigation Model

Every inspection creates exactly one investigation.

Each investigation has a single root target provided by the user.

During inspection, additional targets may be discovered, such as archive entries, embedded files, or downloaded content.

These discovered targets become part of the same investigation.

This allows SentinelX to represent complex inspection hierarchies while preserving a single investigation context.

---

# Inspection Targets

SentinelX is designed around inspection targets rather than file extensions.

Examples include

- Executables
- Documents
- Archives
- Images
- Directories
- URLs
- Projects
- Scripts
- Commands

New target types can be introduced without changing the inspection pipeline.

---

# Evidence-Based Assessment

SentinelX follows an evidence-first model.

```text
Observation

↓

Finding

↓

Assessment
```

Assessments are always explainable.

Every conclusion can be traced back to supporting observations.

---

# Presentation Modes

SentinelX separates investigation from presentation.

The same investigation model may be presented in multiple ways.

## Summary

Provides concise results intended for quick interpretation.

## Detailed

Provides investigation details suitable for analysts.

## Full

Provides complete investigation data intended for advanced users and reverse engineers.

Presentation modes differ only in the amount of information displayed.

No information is hidden or restricted.

---

# Dependency Rules

Dependencies always flow downward.

```text
CLI

↓

Core

↓

Presentation
```

Within the Core,

```text
Routing

↓

Inspection

↓

Observation

↓

Analysis

↓

Finding

↓

Assessment
```

Rules

- Lower domains never depend on higher domains.
- Presentation never performs inspection.
- Assessment never performs inspection.
- Analysis never performs assessment.
- Inspection never performs analysis.

---

# Extensibility

SentinelX is designed to grow without changing the overall architecture.

New

- target types
- inspectors
- analyzers
- findings
- assessment strategies
- presentation formats

can be introduced while preserving the same investigation pipeline.

---

# Project Structure

```text
sentinelx/

├── cli/
├── core/
├── docs/
├── testdata/
├── Cargo.toml
├── README.md
└── LICENSE
```

Internal implementation may evolve over time while preserving the architectural principles described in this document.