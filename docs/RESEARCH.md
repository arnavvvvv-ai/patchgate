# Research: problem evidence, candidate screening, related work

Research conducted 2026-10-29. Sources marked **[S]** were opened or searched during this session.
Sources marked **[K]** are well-known references cited from background knowledge; they were not
re-opened, and their specific claims should be checked before citing them in a paper.

## 1. Candidate screening

Five candidates were investigated. Scores run from 1 to 10, weighted as the brief specified: importance 20%,
differentiation 20%, depth 15%, feasibility 15%, measurability 15%, usefulness 10%, cost 5%.

| # | Candidate | Imp | Diff | Depth | Feas | Meas | Use | Cost | **Weighted** |
|---|---|---|---|---|---|---|---|---|---|
| A | **Verified, behaviour-preserving repair of K8s misconfigurations** | 8 | 6 | 8 | 8 | 8 | 8 | 9 | **7.65** |
| B | Verified LLM repair of ReDoS-vulnerable regexes | 7 | 3 | 8 | 7 | 9 | 6 | 9 | 6.65 |
| C | Strict Content-Security-Policy synthesis | 8 | 4 | 7 | 5 | 6 | 7 | 8 | 6.20 |
| D | Static DST/overlap analysis of scheduled jobs (cron, CronJob) | 6 | 5 | 6 | 9 | 8 | 6 | 10 | 6.75* |
| E | GitHub Actions workflow hardening (token permissions, pinning) | 8 | 2 | 6 | 8 | 6 | 7 | 9 | 6.15 |

\*D is disqualified despite its score: deterministic simulation and optimisation solve it better than an
LLM, so Gemini would have no meaningful role.

### A. Kubernetes verified repair (selected)
- **Problem.** Misconfigured manifests are common, and fixing them is manual or template-based. Rahman et al.
  (ACM TOSEM 2023) studied 2,039 open-source manifests, found 11 categories of security misconfiguration,
  and built the SLI-KUBE linter **[S]**. Red Hat's *State of Kubernetes Security 2024* reports that security is a
  top concern for 42% of respondents and that nearly 90% of organisations had an incident **[S]**. Secondary coverage
  says 45% of incidents were attributed to misconfiguration **[S, secondary source; check the primary report]**.
- **Current solutions.** Rule-based detectors: kube-linter, Checkov, Polaris, Kubescape **[K]**. Kubescape also
  ships `kubescape fix`, which auto-remediates manifests from scan results, with a dry-run mode **[S]**. LLM
  approaches: GenKubeSec (Malul et al., arXiv 2405.19954, 2024) detects, localises, reasons about and remediates
  misconfigurations; its remediation was judged by **expert review of a random sample** **[S]**. KubeGuard
  (Sgan Cohen et al., arXiv 2509.04191, 2025) refines manifests from runtime logs; its outputs are
  "recommendations that users … can review and adopt" **[S]**.
- **Verified gap.** None of the sources reviewed describes an automated, machine-checkable
  behaviour-preservation check on remediation patches. GenKubeSec relies on expert judgement; KubeGuard
  relies on human review; kubescape's fix documentation describes dry-run and interactive approval, but no
  semantic diff check **[S]**. *Assumption still to test:* that real LLM fixes actually exhibit the failure
  categories in our taxonomy, and how often. This is what the live study in `evaluation/live_eval.py` is for.
- **Analogy from program repair.** Patches that pass the available tests while being incorrect ("overfitting")
  are a known problem in automated program repair (Smith et al., *Is the cure worse than the disease?*,
  FSE 2015) **[K]**. Re-linting a manifest plays the same role as re-running tests.
- **Mechanism.** Per-control repair contracts, behavioural invariants, structural validation, and
  counterexample feedback to Gemini.
- **Weakness.** Static analysis only. The differentiation is narrower than "first LLM fixer"; the
  contribution is the acceptance gate.

### B. ReDoS regex repair (rejected)
- The problem is well established (Davis et al., FSE 2018 **[K]**; Siddiq et al., ICPC 2024, on LLM-generated
  vulnerable regexes **[S]**).
- **Rejected for overlap:** *Localized Regex Repair* (Sung et al., EACL 2026) already combines LLM generation
  with enforced reliability for ReDoS repair **[S]**. RegexScalpel (USENIX Security 2022) and Remedy (IEEE S&P 2022)
  repair regexes with formal methods **[K]**. Regex repair is also close to the brief's "language processing" exclusion.

### C. Strict CSP synthesis (rejected)
- Weichselbaum et al. (CCS 2016) found that 94.72% of real-world CSPs were bypassable **[S]**, so the problem is strong.
- **Rejected:** CSPAutoGen (CCS 2016) already generates policies automatically **[K]**, and Google's CSP Evaluator
  already analyses them **[K]**. A credible evaluation needs dynamic crawling and browser instrumentation of real
  sites, which is too much for six to eight weeks. Gemini's role would be marginal.

### D. Scheduled-job integrity (rejected)
- **Evidence:** the Kubernetes CronJob documentation lists scheduling limitations **[S]**. DST fall-back double runs
  are reported in real issue trackers (netresearch/go-cron issue #349) and in practitioner write-ups **[S]**.
- **Rejected:** exact calendar simulation with `zoneinfo` solves it deterministically. Gemini would be decoration,
  which fails the "meaningful GenAI" requirement.

### E. GitHub Actions hardening (rejected)
- **Rejected for overlap:** zizmor, actionlint and StepSecurity's secure-workflows tooling already audit
  workflows and generate hardening changes (token permissions, action pinning) **[K]**. No clear technical gap was found.

## 2. Prior-art and differentiation table (selected project)

| Work | Relevant capability | Verified limitation | PatchGate difference | Evidence | Remaining uncertainty |
|---|---|---|---|---|---|
| GenKubeSec (2024) | LLM detection, localisation, reasoning, remediation; precision 0.990 / recall 0.999 vs 3 rule-based tools | Remediation validated by an expert on a random sample, not automatically | Machine-checked acceptance gate for every patch; rejections fed back | arXiv abstract **[S]** | Full paper may describe more validation than the abstract |
| KubeGuard (2025) | LLM prompt chains refine Roles/NetworkPolicies/Deployments from runtime logs | Outputs are recommendations for human review | Gate is complementary: it could verify KubeGuard's Deployment edits | arXiv abstract **[S]** | Uses runtime logs, which PatchGate cannot |
| `kubescape fix` | Applies fixes from scan JSON; dry-run, interactive approval | Docs mention no behaviour-preservation check | Same template idea as our fallback, plus scope/invariant gate | kubescape README **[S]** | Internal implementation not inspected |
| kube-linter / Checkov / Polaris | Static detection | Detection only (Checkov fix suggestions are a commercial feature, **[K]**) | Repair plus verification | **[K]** | — |
| SLI-KUBE (Rahman et al. 2023) | Detection; empirical prevalence | Detection only | Uses its problem evidence; adds repair | TOSEM paper **[S]** | — |
| Coding assistants editing YAML | Free-form edits | No configuration-specific acceptance criterion (our claim, not a measured result) | `patchgate verify` can gate any external patch | practitioner reports **[S]** | No systematic study cited |

We do **not** claim PatchGate is the first verified repair tool, or that it is patentable. We claim
that the specific combination is implemented and measured here: per-control scope contracts,
behavioural invariants, structural checks, and counterexample feedback for LLM-proposed Kubernetes patches.

## 3. Research questions

- **RQ1.** How often do baseline gates (patch applies; re-lint target; re-lint all) accept harmful candidate
  patches, compared with PatchGate? How often does each wrongly reject valid patches?
- **RQ2.** When the proposer is real Gemini, how often is a single-shot patch harmful but re-lint-passing,
  and how often does verifier feedback turn a rejected patch into an accepted one? *(Run on 8 findings only, because of the free-tier quota; see EVALUATION.md.)*
- **RQ3.** What does each gate component (structural, scope, invariants) contribute? (Ablation.)
- **RQ4.** What can the static gate *not* catch? (Hand-written challenge set.)

Methodology and results: [EVALUATION.md](EVALUATION.md).

## 4. References

1. A. Rahman, S. I. Shamim, D. B. Bose, R. Pandita. *Security Misconfigurations in Open Source Kubernetes Manifests: An Empirical Study.* ACM TOSEM, 2023. https://dl.acm.org/doi/10.1145/3579639 [S]
2. E. Malul, Y. Meidan, D. Mimran, Y. Elovici, A. Shabtai. *GenKubeSec: LLM-Based Kubernetes Misconfiguration Detection, Localization, Reasoning, and Remediation.* arXiv:2405.19954, 2024. https://arxiv.org/abs/2405.19954 [S]
3. O. Sgan Cohen, E. Malul, Y. Meidan, D. Mimran, Y. Elovici, A. Shabtai. *KubeGuard: LLM-Assisted Kubernetes Hardening via Configuration Files and Runtime Logs Analysis.* arXiv:2509.04191, 2025. https://arxiv.org/abs/2509.04191 [S]
4. Red Hat. *The State of Kubernetes Security in 2024.* https://www.redhat.com/en/blog/state-kubernetes-security-2024 [S]
5. Kubescape project, README (`kubescape fix`). https://github.com/kubescape/kubescape [S]
6. Kubernetes documentation. *Pod Security Standards.* https://kubernetes.io/docs/concepts/security/pod-security-standards/ [K]
7. Kubernetes documentation. *CronJob.* https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/ [S]
8. L. Weichselbaum, M. Spagnuolo, S. Lekies, A. Janc. *CSP Is Dead, Long Live CSP!* ACM CCS 2016. https://research.google/pubs/csp-is-dead-long-live-csp-on-the-insecurity-of-whitelists-and-the-future-of-content-security-policy/ [S]
9. S. Sung et al. *Repairing Regex Vulnerabilities via Localization-Guided …* EACL 2026. https://aclanthology.org/2026.eacl-long.379/ [S]
10. M. L. Siddiq et al. *Understanding Regular Expression Denial of Service (ReDoS): Insights from LLM-Generated Regexes and Developer Forums.* ICPC 2024. https://dl.acm.org/doi/10.1145/3643916.3644424 [S]
11. E. K. Smith, E. T. Barr, C. Le Goues, Y. Brun. *Is the Cure Worse Than the Disease? Overfitting in Automated Program Repair.* ESEC/FSE 2015. [K]
12. Google. *Gemini API models.* https://ai.google.dev/gemini-api/docs/models (lists `gemini-2.5-flash` as stable, checked 2026-10-29) [S]
13. netresearch/go-cron issue #349, *CronJob executes twice during DST fall back.* https://github.com/netresearch/go-cron/issues/349 [S]
