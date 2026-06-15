# Formats Index

All deliverable formats used by the pentest-bot. Read the relevant format file before generating any output.

| Format | File | Use When |
|--------|------|----------|
| Pentest Report (PDF) | `tzar-bot-report-style/pentest-report.md` | Final client deliverable after all findings validated |
| PDF Design System | `tzar-bot-report-style/SKILL.md` | Generating the PDF with ReportLab (colors, typography, layout) |
| Finding JSON Schema | `tzar-bot-report-style/pentest-report.md#schema` | Writing individual findings to artifacts/pentest-report.json |
| NDJSON Activity Log | `ndjson-log.md` | Executor activity logging (one JSON object per line) |
| HackerOne Report | `h1-report.md` | Bug bounty submission to HackerOne via API |
| HTB Flag Submission | `htb-flag.md` | HackTheBox flag capture and API submission |
| Recon Schema | `recon-schema.md` | Structured recon output (tech-stack.json, subdomains, ports) |
