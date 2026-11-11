# New cases report

The catalog now contains 100 vulnerability cases and 75 paired/negative cases. This pass
added 41 observable Node business endpoints and 15 negative controls covering logging and
PII exposure (A09), webhook and deserialization trust boundaries (A08), dependency
advisories (A06), business-logic and race-like state handling (A04), tenant isolation,
mass assignment, replay, CSRF, and authorization boundaries.

Every added case has a unique source anchor, a real HTTP proof under
`tests/exploits/`, a CVSS v4 vector, CWE alternatives, and a generated OWASP 2025
mapping. `truth/scripts/verify.py` reports 175/175 executable proofs passing after a
fresh service restart.
