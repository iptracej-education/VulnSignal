# VulnSignal Stage 1 Baseline Check

This is a development check, not a dataset release.

| Mode | MRR | Hit@1 | Hit@5 | Hit@10 | nDCG@10 |
| --- | ---: | ---: | ---: | ---: | ---: |
| source-only | 0.5977 | 0.5000 | 0.8333 | 0.8333 | 0.5782 |
| source + AST/CFG | 0.7302 | 0.6667 | 0.8333 | 0.8333 | 0.6015 |
| source + full static views | 0.8667 | 0.8333 | 1.0000 | 1.0000 | 0.7922 |
| validation-assisted | 0.8889 | 0.8333 | 1.0000 | 1.0000 | 0.8569 |

| Local working artifact | Path |
| --- | --- |
| Source-only runner | `reports/e030_evidence_grounded_dataset_30/run_source_only_baseline.py` |
| Multi-view runner | `reports/e030_evidence_grounded_dataset_30/run_multiview_baselines.py` |
| Model-ready builder | `reports/e030_evidence_grounded_dataset_30/build_model_ready_representations.py` |
| Comparison report | `reports/e030_evidence_grounded_dataset_30/baseline_multiview_comparison.md` |
| Next repair plan | `reports/e030_evidence_grounded_dataset_30/candidate_density_repair_plan.md` |

Stage 1 passes: full static views beat the source-only floor. Next step is candidate-density repair before expansion.
