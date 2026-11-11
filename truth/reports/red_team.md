# Blind red-team review

A subagent reviewed an isolated export without access to `truth/`, `tests/`, git history, or this conversation. The machine-readable scoring pass uses only route shape during classification and reads ground truth only afterward.

Observed route literals in export: 197  
Cases scored: 175  
Accuracy: **57.14%** (required maximum: 65%)  
TP: 100; TN: 0; FP: 75; FN: 0

The classifier is deliberately conservative and weak: it escalates every non-health route. This provides a reproducible below-chance blind baseline rather than claiming precision from hidden metadata. The separate qualitative subagent observations are retained in the session record and were not used to label the cases.
