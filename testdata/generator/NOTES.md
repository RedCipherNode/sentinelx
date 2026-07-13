# SentinelX Test Data Generator

## Purpose

This generator creates a completely harmless dataset for SentinelX.

The dataset is intended for:

- parser testing
- MIME detection
- extension detection
- archive inspection
- recursive archive traversal
- project detection
- metadata inspection
- CLI development

It is NOT intended for malware analysis.

---

## Usage

Install dependencies:

```bash
pip install -r requirements.txt
```

Generate dataset:

```bash
python generate.py
```

Generated output:

```
output/generated/
output/sentinelx-testdata.zip
```

---

## Rules

All generated files must be:

- Safe
- Generated locally
- No downloaded content
- No malware
- No exploits
- No macros
- No shellcode
- No obfuscation

Lorem Ipsum and placeholder content are preferred.

---

## Development Notes

Keep the generator simple.

Preferred architecture:

- Single file (`generate.py`)
- No unnecessary abstractions
- No classes
- No plugin system
- No configuration files

The primary users are SentinelX developers.

Favor readability over extensibility.

---

## Output Layout

```
output/
    generated/
    sentinelx-testdata.zip
```

The `generated/` directory is recreated on every run.

The ZIP is rebuilt on every run.

---

## Future Ideas

Potential additions:

- SQLite
- PEM / CRT
- Docker Compose
- GitHub Actions
- Terraform
- Kubernetes YAML
- EPUB
- SQLite database
- Large JSON
- Large CSV
- Nested archives
- Additional project templates

These should only be added when needed by SentinelX.