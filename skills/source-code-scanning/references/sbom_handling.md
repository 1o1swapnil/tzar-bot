# SBOM Handling Notes

## Formats accepted

| Format | Spec versions | File hints |
|--------|---------------|------------|
| CycloneDX JSON | 1.4, 1.5, 1.6 | `bomFormat: "CycloneDX"`, `specVersion`, `components[]` |
| CycloneDX XML  | 1.4, 1.5, 1.6 | `xmlns="http://cyclonedx.org/schema/bom/..."` |
| SPDX JSON     | 2.2, 2.3 | `spdxVersion: "SPDX-2.3"`, `packages[]` |
| SPDX tag-value | 2.2, 2.3 | First line `SPDXVersion:` |
| SWID tags    | ISO/IEC 19770-2 | `<SoftwareIdentity>` XML |

## Mandatory enrichment per component

For each component, derive or fetch:

| Field | Source |
|-------|--------|
| `purl` | SBOM directly; canonicalize per PURL spec |
| `name`, `version` | SBOM |
| `license_declared` | SBOM (CycloneDX `licenses[]`, SPDX `licenseDeclared`) |
| `license_concluded` | SBOM if present, else "NOASSERTION" |
| `direct_or_transitive` | CycloneDX `dependencies[]` graph traversal; if absent, mark `unknown` |
| `depth` | shortest path from root in dependency graph |
| `cves` | from SCA tool; never invent |
| `kev_listed` | CISA KEV catalog (offline copy or authorized fetch) |
| `epss` | EPSS API (authorized fetch only) |
| `advisory_links` | GHSA, vendor, NVD URLs as provided by SCA tool |
| `fixed_in` | from SCA tool |
| `runtime_layer` (container) | Trivy `Layer.DiffID` |
| `language` | from PURL type (`pkg:maven`, `pkg:npm`, etc.) |

## License tiers (default policy — override per engagement)

| Tier | Examples | Use in proprietary build |
|------|----------|--------------------------|
| Permissive | MIT, BSD-2/3, Apache-2.0, ISC, Unlicense, 0BSD | OK |
| Weak copyleft | LGPL-2.1, LGPL-3.0, MPL-2.0, EPL-2.0, CDDL-1.0 | OK if dynamically linked |
| Strong copyleft | GPL-2.0, GPL-3.0, AGPL-3.0 | **Blocked** in proprietary distribution |
| Network copyleft | AGPL-3.0, SSPL | **Blocked** in SaaS distribution |
| Unknown / NOASSERTION | — | **Investigate** before allowing |
| Commercial / Proprietary | vendor-specific | Verify license entitlement |

Flag every `Unknown` and every Strong-copyleft entry on the SBOM tab.

## Supply-chain risk signals

Flag components matching any of:

- **Typosquat candidates**: Levenshtein ≤ 2 to a top-1000 package name.
- **Recently published** (< 30 days at scan time) **and** count of total releases < 5.
- **Single maintainer** (where registry exposes it).
- **Maintainer change within last 90 days** for high-impact packages.
- **No public source repo** linked.
- **Yanked / deprecated** by registry.
- **Internal package name** resolved from public registry (dependency confusion risk).
- **Binary-only** distribution where source-only is expected.

These do not always become findings — they are *signals* on the SBOM tab for the supply-chain reviewer.

## PURL canonicalization gotchas

- Maven: `pkg:maven/<group>/<artifact>@<version>` — group separator is `/`, not `.`.
- npm scoped: `pkg:npm/%40scope/name@version` — `@` is URL-encoded as `%40`.
- Golang: `pkg:golang/<module>@<version>` — module path includes domain.
- PyPI: case-insensitive, names normalized to lowercase, `-` and `_` and `.` collapse to `-`.
- Container images: `pkg:oci/<image>@<digest>?repository_url=...` — prefer digest over tag.

When comparing PURLs across tools, normalize before comparing or you will under-merge.
