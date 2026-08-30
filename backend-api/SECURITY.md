# CyberKavach API security setup

Phase 1 removes embedded credentials, hashes stored API keys, validates uploads,
blocks private-network URL scans, limits request rates, validates file uploads,
and stores only hashed local session identifiers for scan history.

## Required before deployment

1. Copy `.env.example` to a deployment secret store. Do not commit `.env`.
2. Set exact frontend origins, extension origin, and public API host. Do not use `*`.
3. Terminate TLS at a trusted reverse proxy and expose only HTTPS publicly.
4. Run the API as a non-root user with outbound firewall rules. URL scanning should
   have no route to private networks or cloud metadata, even if application checks fail.
5. Back up the database with restricted filesystem permissions.

## Verification

From the project root:

```sh
PYTHONPATH=backend-api .venv/bin/python -m unittest discover -s backend-api/tests -v
.venv/bin/python -m py_compile backend-api/*.py backend-api/tests/*.py
cd frontend-dashboard && npm run lint
```

No application can be guaranteed unhackable. Report suspected vulnerabilities
privately and rotate any credential that may have appeared in source or logs.
