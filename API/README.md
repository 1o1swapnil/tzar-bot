# API — API Security Testing

Tests targeting REST, GraphQL, gRPC, and SOAP APIs following OWASP API Security Top 10.

## When to Use This Folder

- REST API security assessments
- GraphQL API testing (introspection, batching, depth attacks)
- Microservices API security review
- OAuth 2.0 / JWT implementation testing
- API gateway and rate limiting testing
- Swagger/OpenAPI spec-driven testing

## Skills Used

`api-security` · `authentication` · `injection` · `reconnaissance` · `osint`

## Quick Start

```
# REST API test:
"test the API at https://api.target.com for OWASP API Top 10 issues"

# With Swagger spec:
"security test this API using the spec at https://api.target.com/swagger.json"

# GraphQL:
"test the GraphQL endpoint at https://target.com/graphql"
```

## Output Structure

```
API/
└── <api-name>/
    └── YYYYMMDD_HHMMSS/
        ├── attack-chain.md
        ├── recon/
        │   ├── api-endpoints.txt     # discovered endpoints
        │   ├── swagger.json          # OpenAPI spec (if found)
        │   └── graphql-schema.json   # GraphQL schema (if enabled)
        ├── findings/
        ├── logs/
        └── reports/API-Security-Report.pdf
```

## OWASP API Top 10 Coverage

- API1: BOLA / IDOR
- API2: Broken Authentication
- API3: Broken Object Property Level Authorization
- API4: Unrestricted Resource Consumption
- API5: Broken Function Level Authorization
- API6: Unrestricted Access to Sensitive Business Flows
- API7: Server Side Request Forgery
- API8: Security Misconfiguration
- API9: Improper Inventory Management
- API10: Unsafe Consumption of APIs
