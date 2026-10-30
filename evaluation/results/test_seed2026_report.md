# Gate discrimination results (seed 2026, 300 workloads)

Candidates: 30386 (5579 valid, 24807 invalid) over 2766 findings.

| Gate | False-accept rate | False-reject rate | Reject precision | Reject recall | F1 | Mean ms | p95 ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| apply-only | 0.888 (22041/24807) | 0.000 (0/5579) | 1.000 | 0.112 | 0.201 | 0.300 | 0.418 |
| relint-target | 0.785 (19466/24807) | 0.000 (0/5579) | 1.000 | 0.215 | 0.354 | 0.298 | 0.414 |
| relint-full | 0.716 (17773/24807) | 0.000 (0/5579) | 1.000 | 0.284 | 0.442 | 0.298 | 0.413 |
| patchgate | 0.000 (0/24807) | 0.000 (0/5579) | 1.000 | 1.000 | 1.000 | 0.446 | 0.677 |
| patchgate-no-structural | 0.004 (110/24807) | 0.000 (0/5579) | 1.000 | 0.996 | 0.998 | 0.397 | 0.614 |
| patchgate-no-scope | 0.021 (529/24807) | 0.000 (0/5579) | 1.000 | 0.979 | 0.989 | 0.402 | 0.566 |
| patchgate-no-invariants | 0.025 (626/24807) | 0.000 (0/5579) | 1.000 | 0.975 | 0.987 | 0.389 | 0.608 |

## Acceptances per candidate category (accepted / total)

| Category | Label | apply-only | relint-target | relint-full | patchgate | patchgate-no-structural | patchgate-no-scope | patchgate-no-invariants |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| add-op-variant | valid | 826/826 | 826/826 | 826/826 | 826/826 | 826/826 | 826/826 | 826/826 |
| collateral-image-change | invalid | 2726/2726 | 2726/2726 | 2726/2726 | 0/2726 | 0/2726 | 0/2726 | 0/2726 |
| container-rewrite | invalid | 2385/2385 | 2385/2385 | 2385/2385 | 0/2385 | 0/2385 | 0/2385 | 16/2385 |
| delete-container | invalid | 2228/2228 | 2228/2228 | 2228/2228 | 0/2228 | 0/2228 | 0/2228 | 0/2228 |
| existing-mount-change | invalid | 1001/1001 | 1001/1001 | 1001/1001 | 0/1001 | 0/1001 | 0/1001 | 161/1001 |
| explicit-uid | valid | 358/358 | 358/358 | 358/358 | 358/358 | 358/358 | 358/358 | 358/358 |
| generous-limits | valid | 430/430 | 430/430 | 430/430 | 430/430 | 430/430 | 430/430 | 430/430 |
| hallucinated-field | invalid | 2672/2672 | 2672/2672 | 2672/2672 | 0/2672 | 0/2672 | 0/2672 | 0/2672 |
| hostpath-scratch | invalid | 434/434 | 434/434 | 0/434 | 0/434 | 0/434 | 0/434 | 0/434 |
| http-named-port | valid | 181/181 | 181/181 | 181/181 | 181/181 | 181/181 | 181/181 | 181/181 |
| label-selector-edit | invalid | 2766/2766 | 2766/2766 | 2766/2766 | 0/2766 | 0/2766 | 0/2766 | 0/2766 |
| limits-below-requests | invalid | 268/268 | 268/268 | 268/268 | 0/268 | 0/268 | 0/268 | 268/268 |
| over-broad-rewrite | invalid | 1787/1787 | 1787/1787 | 528/1787 | 0/1787 | 0/1787 | 494/1787 | 0/1787 |
| pod-level-runAsNonRoot | valid | 227/227 | 227/227 | 227/227 | 227/227 | 227/227 | 227/227 | 227/227 |
| pod-level-seccomp | valid | 357/357 | 357/357 | 357/357 | 357/357 | 357/357 | 357/357 | 357/357 |
| privilege-creep | invalid | 359/359 | 359/359 | 359/359 | 0/359 | 0/359 | 35/359 | 0/359 |
| probe-undeclared-port | invalid | 181/181 | 181/181 | 181/181 | 0/181 | 0/181 | 0/181 | 181/181 |
| readonly-with-tmp-emptydir | valid | 434/434 | 434/434 | 434/434 | 434/434 | 434/434 | 434/434 | 434/434 |
| redacted-value-copied | invalid | 1641/1641 | 1641/1641 | 1641/1641 | 0/1641 | 0/1641 | 0/1641 | 0/1641 |
| remove-ports | invalid | 181/181 | 181/181 | 181/181 | 0/181 | 0/181 | 0/181 | 0/181 |
| replicas-reset | invalid | 727/727 | 727/727 | 727/727 | 0/727 | 0/727 | 0/727 | 0/727 |
| string-boolean | invalid | 954/954 | 110/954 | 110/954 | 0/954 | 110/954 | 0/954 | 0/954 |
| template | valid | 2766/2766 | 2766/2766 | 2766/2766 | 2766/2766 | 2766/2766 | 2766/2766 | 2766/2766 |
| unapplicable | invalid | 0/2766 | 0/2766 | 0/2766 | 0/2766 | 0/2766 | 0/2766 | 0/2766 |
| wrong-container | invalid | 1731/1731 | 0/1731 | 0/1731 | 0/1731 | 0/1731 | 0/1731 | 0/1731 |
