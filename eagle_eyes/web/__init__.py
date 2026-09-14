"""The hosted web product.

Everything in this package is additive. `eagle_eyes` itself -- the engine, the
sanitizer, the fingerprinter, the repositories -- runs on the standard library
and keeps running that way; only this package needs FastAPI, and only when the
web app is started. Importing `eagle_eyes.storage` from a CLI never pulls a
dependency in.

The security position is in docs/SECURITY.md and docs/PRODUCTION_MIGRATION.md.
The short version: a hosted instance is approved for synthetic data only. The
product's argument has always been that client logs, screenshots and code never
leave the estate, and hosting does not change that argument -- it changes where
this particular deployment is allowed to point.
"""
