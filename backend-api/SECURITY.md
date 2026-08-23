# CyberKavach API security setup

Phase 1 removes embedded credentials, hashes stored API keys, validates uploads,
blocks private-network URL scans, limits request rates, makes quota updates atomic,
and verifies payment amount/status/replay before issuing a license.

## Required before deployment

1. Revoke the Razorpay secret that was previously committed and create a new one.
2. Copy `.env.example` to a deployment secret store. Do not commit `.env`.
3. Set exact frontend origins, extension origin, and public API host. Do not use `*`.
4. Terminate TLS at a trusted reverse proxy and expose only HTTPS publicly.
5. Run the API as a non-root user with outbound firewall rules. URL scanning should
   have no route to private networks or cloud metadata, even if application checks fail.
6. Back up the database with restricted filesystem permissions.

## Verification

From the project root:

```sh
PYTHONPATH=backend-api .venv/bin/python -m unittest discover -s backend-api/tests -v
.venv/bin/python -m py_compile backend-api/*.py backend-api/tests/*.py
cd frontend-dashboard && npm run lint
```

No application can be guaranteed unhackable. Report suspected vulnerabilities
privately and rotate any credential that may have appeared in source or logs.
