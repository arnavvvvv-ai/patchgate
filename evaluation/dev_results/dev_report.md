# Gate discrimination results (seed 7, 200 workloads)

Candidates: 18595 (3463 valid, 15132 invalid) over 1700 findings.

| Gate | False-accept rate | False-reject rate | Reject precision | Reject recall | F1 | Mean ms | p95 ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| apply-only | 0.888 (13432/15132) | 0.000 (0/3463) | 1.000 | 0.112 | 0.202 | 0.294 | 0.428 |
| relint-target | 0.787 (11912/15132) | 0.000 (0/3463) | 1.000 | 0.213 | 0.351 | 0.289 | 0.423 |
| relint-full | 0.717 (10852/15132) | 0.000 (0/3463) | 1.000 | 0.283 | 0.441 | 0.289 | 0.418 |
| patchgate | 0.000 (0/15132) | 0.000 (0/3463) | 1.000 | 1.000 | 1.000 | 0.418 | 0.675 |
| patchgate-no-structural | 0.005 (73/15132) | 0.000 (0/3463) | 1.000 | 0.995 | 0.998 | 0.383 | 0.620 |
| patchgate-no-scope | 0.022 (341/15132) | 0.000 (0/3463) | 1.000 | 0.978 | 0.989 | 0.377 | 0.559 |
| patchgate-no-invariants | 0.025 (377/15132) | 0.000 (0/3463) | 1.000 | 0.975 | 0.987 | 0.377 | 0.623 |

## Acceptances per candidate category (accepted / total)

| Category | Label | apply-only | relint-target | relint-full | patchgate | patchgate-no-structural | patchgate-no-scope | patchgate-no-invariants |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| add-op-variant | valid | 518/518 | 518/518 | 518/518 | 518/518 | 518/518 | 518/518 | 518/518 |
| collateral-image-change | invalid | 1673/1673 | 1673/1673 | 1673/1673 | 0/1673 | 0/1673 | 0/1673 | 0/1673 |
| container-rewrite | invalid | 1493/1493 | 1493/1493 | 1493/1493 | 0/1493 | 0/1493 | 0/1493 | 13/1493 |
| delete-container | invalid | 1242/1242 | 1242/1242 | 1242/1242 | 0/1242 | 0/1242 | 0/1242 | 0/1242 |
| existing-mount-change | invalid | 686/686 | 686/686 | 686/686 | 0/686 | 0/686 | 0/686 | 113/686 |
| explicit-uid | valid | 225/225 | 225/225 | 225/225 | 225/225 | 225/225 | 225/225 | 225/225 |
| generous-limits | valid | 257/257 | 257/257 | 257/257 | 257/257 | 257/257 | 257/257 | 257/257 |
| hallucinated-field | invalid | 1646/1646 | 1646/1646 | 1646/1646 | 0/1646 | 0/1646 | 0/1646 | 0/1646 |
| hostpath-scratch | invalid | 271/271 | 271/271 | 0/271 | 0/271 | 0/271 | 0/271 | 0/271 |
| http-named-port | valid | 94/94 | 94/94 | 94/94 | 94/94 | 94/94 | 94/94 | 94/94 |
| label-selector-edit | invalid | 1700/1700 | 1700/1700 | 1700/1700 | 0/1700 | 0/1700 | 0/1700 | 0/1700 |
| limits-below-requests | invalid | 157/157 | 157/157 | 157/157 | 0/157 | 0/157 | 0/157 | 157/157 |
| over-broad-rewrite | invalid | 1108/1108 | 1108/1108 | 319/1108 | 0/1108 | 0/1108 | 319/1108 | 0/1108 |
| pod-level-runAsNonRoot | valid | 170/170 | 170/170 | 170/170 | 170/170 | 170/170 | 170/170 | 170/170 |
| pod-level-seccomp | valid | 228/228 | 228/228 | 228/228 | 228/228 | 228/228 | 228/228 | 228/228 |
| privilege-creep | invalid | 226/226 | 226/226 | 226/226 | 0/226 | 0/226 | 22/226 | 0/226 |
| probe-undeclared-port | invalid | 94/94 | 94/94 | 94/94 | 0/94 | 0/94 | 0/94 | 94/94 |
| readonly-with-tmp-emptydir | valid | 271/271 | 271/271 | 271/271 | 271/271 | 271/271 | 271/271 | 271/271 |
| redacted-value-copied | invalid | 1024/1024 | 1024/1024 | 1024/1024 | 0/1024 | 0/1024 | 0/1024 | 0/1024 |
| remove-ports | invalid | 94/94 | 94/94 | 94/94 | 0/94 | 0/94 | 0/94 | 0/94 |
| replicas-reset | invalid | 425/425 | 425/425 | 425/425 | 0/425 | 0/425 | 0/425 | 0/425 |
| string-boolean | invalid | 597/597 | 73/597 | 73/597 | 0/597 | 73/597 | 0/597 | 0/597 |
| template | valid | 1700/1700 | 1700/1700 | 1700/1700 | 1700/1700 | 1700/1700 | 1700/1700 | 1700/1700 |
| unapplicable | invalid | 0/1700 | 0/1700 | 0/1700 | 0/1700 | 0/1700 | 0/1700 | 0/1700 |
| wrong-container | invalid | 996/996 | 0/996 | 0/996 | 0/996 | 0/996 | 0/996 | 0/996 |
