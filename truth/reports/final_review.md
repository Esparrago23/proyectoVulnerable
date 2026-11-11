# Final review

The canonical schema and leakage scan pass, and the legacy `meta/` tree has been removed.
After rebuilding and restarting both services, the current verification run records
175/175 cases as verified (100%), using executable HTTP or deterministic proofs. The
catalog contains 100 vulnerabilities and 75 traps. Clean zones cover 985/5169
analyzable lines (19.06%) and the strict anchor validator passes every case.

The isolated red-team review was run against `_blind_export` without access to truth,
tests, or git history. Its reproducible route-only scoring pass is intentionally weak:
100 TP, 0 TN, 75 FP, 0 FN, for **57.14% accuracy**, below the required 65% maximum.
The canonical checks and all repository tests pass. `truth/scripts/verify.py` is the
authoritative status writer.
