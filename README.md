# StackSentry Platform

The web platform built on top of [StackSentry](https://github.com/vickkykruz/stacksentry) —
the automated web application security configuration scanner.

StackSentry (the package) is the scanning engine. This platform is the web
application that uses it to deliver public-facing features:

| Feature | Status | What it does |
|---------|--------|--------------|
| **Security badges** | 🟢 In progress | Public, embeddable security-grade SVG badges |
| Freelancer reports | ⚪ Planned | White-label PDF security audit reports |
| Compliance profiles | ⚪ Planned | Map findings to Cyber Essentials, PCI-DSS, ISO 27001, GDPR |
| CI/CD integration | ⚪ Planned | GitHub Action posting grades on pull requests |
| Regional assessment | ⚪ Planned | Shared-hosting-first mode for underserved ecosystems |
| Verifiable credentials | ⚪ Planned | Cryptographically signed security passports |

## Architecture

```
stacksentry-platform/
├── core/                  ← shared foundation, used by every feature
│   ├── ssrf_guard.py      ← blocks scanning of internal/private addresses
│   ├── scan_store.py      ← domain → grade store (SQLite)
│   ├── scanner.py         ← imports & calls the real StackSentry package
│   └── domain_verify.py   ← domain-ownership verification
├── features/
│   ├── badges/            ← Idea 1 — the first live feature
│   ├── reports/           ← Idea 2 (placeholder)
│   ├── compliance/        ← Idea 3 (placeholder)
│   ├── cicd/              ← Idea 4 (placeholder)
│   ├── regional/          ← Idea 5 (placeholder)
│   └── credentials/       ← Idea 6 (placeholder)
├── app.py                 ← wires the enabled features together
└── requirements.txt       ← depends on stacksentry>=1.0.0
```

**The scanner is StackSentry itself.** The platform depends on the real
`stacksentry` package (declared in `requirements.txt`) and calls its scanning
code directly. It is not a fork, not a reimplementation, and not a third-party
scanner — it is the same tool published to PyPI, used as a dependency.

## Trust model

A security badge is only meaningful if the grade cannot be faked. The platform
enforces this through four layers:

1. **Server-side scanning** — the grade comes from a scan the *platform* runs,
   never one a client reports. There is no "here is my grade" write endpoint.
2. **SSRF guard** — every scan target is checked before any request is made;
   private, loopback, link-local, and cloud-metadata addresses are refused.
3. **Domain verification** — only the verified owner of a domain can have its
   grade published.
4. **Cryptographic signing** — each badge links to a signed, timestamped,
   publicly verifiable scan record.

## Development

```bash
pip install -r requirements-dev.txt
pytest -v
```

## Deployment

Runs on the StackSentry VPS behind nginx, with Celery + Redis for out-of-band
scanning (badges never block on a scan). See `DEPLOY.md` (coming) for details.

## License

MIT — see [LICENSE](LICENSE).

---

*Built by Victor Chukwuemeka Onwuegbuchulem.*
