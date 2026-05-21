# VulnSignal Document Index

This index is the entry point for the VulnSignal proposal, strategy documents, diagrams, and slides. The project name now foregrounds evidence signals and candidate ranking, not patch differences.

## Primary Documents

- [README.md](README.md) - project overview and naming boundary.
- [docs/PROPOSAL.md](docs/PROPOSAL.md) - formal VulnSignal project proposal.
- [docs/project/VULNSIGNAL_VISION.md](docs/project/VULNSIGNAL_VISION.md) - strategic vision.
- [docs/project/VULNSIGNAL_ARCHITECTURE.md](docs/project/VULNSIGNAL_ARCHITECTURE.md) - tool-grounded architecture.
- [docs/project/VULNSIGNAL_ROADMAP.md](docs/project/VULNSIGNAL_ROADMAP.md) - staged roadmap.
- [docs/project/VULNSIGNAL_PLAN.md](docs/project/VULNSIGNAL_PLAN.md) - execution plan.
- [docs/project/VULNSIGNAL_DATASET_STRATEGY.md](docs/project/VULNSIGNAL_DATASET_STRATEGY.md) - task-instance dataset strategy.
- [docs/project/VULNSIGNAL_GROUND_TRUTH_POLICY.md](docs/project/VULNSIGNAL_GROUND_TRUTH_POLICY.md) - accepted and rejected truth layers.
- [docs/project/VULNSIGNAL_MODEL_STRATEGY.md](docs/project/VULNSIGNAL_MODEL_STRATEGY.md) - model architecture and loss direction.
- [docs/project/VULNSIGNAL_DATA_GENERATION_KNOWLEDGE.md](docs/project/VULNSIGNAL_DATA_GENERATION_KNOWLEDGE.md) - accumulated dataset-generation rules, promotion criteria, and scaling lessons.
- [docs/project/VULNSIGNAL_TOOL_DERIVED_NORMALIZATION_POLICY.md](docs/project/VULNSIGNAL_TOOL_DERIVED_NORMALIZATION_POLICY.md) - normalization policy for tool-derived multi-view model inputs.
- [docs/project/VULNSIGNAL_CODEQL_FACT_SCHEMA.md](docs/project/VULNSIGNAL_CODEQL_FACT_SCHEMA.md) - normalized fact schema.
- [docs/project/VULNSIGNAL_ALIGNMENT_CHECKLIST.md](docs/project/VULNSIGNAL_ALIGNMENT_CHECKLIST.md) - required future experiment alignment questions.
- [docs/feasibility/object_lifetime_pilot_viability/README.md](docs/feasibility/object_lifetime_pilot_viability/README.md) - pilot viability gate for estimating 50-100 object-lifetime/refcount task instances.
- [docs/feasibility/hardcase_tool_feasibility/README.md](docs/feasibility/hardcase_tool_feasibility/README.md) - hard-case tool feasibility experiment with fixtures, commands, outputs, and validation.

## Visual Materials

- [diagrams/vulnsignal_detailed_architecture.png](diagrams/vulnsignal_detailed_architecture.png) - detailed PNG architecture overview covering ingestion, model, inference, evaluation, and audit boundaries.
- [docs/slides/vulnsignal_compact_visual_deck.html](docs/slides/vulnsignal_compact_visual_deck.html) - compact six-slide visual summary.
- [docs/slides/vulnsignal_dataset_development.html](docs/slides/vulnsignal_dataset_development.html) - detailed dataset-development deck.
- [docs/slides/vulnsignal_data_structures_i_intake_contract.html](docs/slides/vulnsignal_data_structures_i_intake_contract.html) - intake contract diagram.
- [docs/slides/vulnsignal_data_structures_ii_representation_encoding.html](docs/slides/vulnsignal_data_structures_ii_representation_encoding.html) - representation and encoding diagram.
- [docs/slides/vulnsignal_data_structures_iii_dataset_consumption.html](docs/slides/vulnsignal_data_structures_iii_dataset_consumption.html) - training and evaluation consumption diagram.

## Standalone Diagrams

- [diagrams/vulnsignal_detailed_architecture.png](diagrams/vulnsignal_detailed_architecture.png)
- [diagrams/vulnsignal_data_structures_i_intake_contract.html](diagrams/vulnsignal_data_structures_i_intake_contract.html)
- [diagrams/vulnsignal_data_structures_ii_representation_encoding.html](diagrams/vulnsignal_data_structures_ii_representation_encoding.html)
- [diagrams/vulnsignal_data_structures_iii_dataset_consumption.html](diagrams/vulnsignal_data_structures_iii_dataset_consumption.html)

## Validation

- [scripts/check_vulnsignal_alignment.py](scripts/check_vulnsignal_alignment.py) - local alignment gate for VulnSignal documentation.

## Dataset Proofs

- [reports/e022_object_lifetime_smoke/dataset_card.md](reports/e022_object_lifetime_smoke/dataset_card.md) - 20-task object-lifetime/refcount smoke dataset card and gate status.
- [reports/e022_object_lifetime_smoke/expansion_card.md](reports/e022_object_lifetime_smoke/expansion_card.md) - 20-task expansion status and admission boundary.
- [reports/e022_object_lifetime_smoke/full_source_probe/README.md](reports/e022_object_lifetime_smoke/full_source_probe/README.md) - full-source CodeQL extraction attempt for the first five smoke cases.
- [reports/e022_object_lifetime_smoke/kbuild_codeql_summary.md](reports/e022_object_lifetime_smoke/kbuild_codeql_summary.md) - all-20 Kbuild-backed CodeQL extraction summary and build blockers.
- [reports/e022_object_lifetime_smoke/codeql_vulnerable_fixed_comparison_20_summary.json](reports/e022_object_lifetime_smoke/codeql_vulnerable_fixed_comparison_20_summary.json) - vulnerable/fixed lifecycle-fact comparison counts.
- [reports/e022_object_lifetime_smoke/hard_negative_20_summary.json](reports/e022_object_lifetime_smoke/hard_negative_20_summary.json) - weak hard-negative candidate generation counts and policy.
- [reports/e022_object_lifetime_smoke/strong_label_promotion_20_summary.json](reports/e022_object_lifetime_smoke/strong_label_promotion_20_summary.json) - first executable rule-based label promotion counts.
- [rules/lifecycle/README.md](rules/lifecycle/README.md) - machine-readable lifecycle rule spec directory.
- [reports/e022_object_lifetime_smoke/evidence_automation_20_run_log.jsonl](reports/e022_object_lifetime_smoke/evidence_automation_20_run_log.jsonl) - one-command evidence automation run log.
- [reports/e022_object_lifetime_smoke/promotion_failure_analysis_20_summary.json](reports/e022_object_lifetime_smoke/promotion_failure_analysis_20_summary.json) - automated reasons for unpromoted candidates.
- [reports/e022_object_lifetime_smoke/rule_gap_report_20_summary.json](reports/e022_object_lifetime_smoke/rule_gap_report_20_summary.json) - rule-engineering triage buckets for unpromoted patch candidates.
- [reports/e022_object_lifetime_smoke/coccinelle_window_lifecycle_summary.json](reports/e022_object_lifetime_smoke/coccinelle_window_lifecycle_summary.json) - Coccinelle semantic-pattern match counts.
- [reports/e022_object_lifetime_smoke/coccinelle_wrapper_candidate_summary.json](reports/e022_object_lifetime_smoke/coccinelle_wrapper_candidate_summary.json) - Coccinelle wrapper-candidate match counts.
- [reports/e022_object_lifetime_smoke/joern_window_graph_summary.json](reports/e022_object_lifetime_smoke/joern_window_graph_summary.json) - Joern graph-export status for promoted candidate windows.
- [reports/e022_object_lifetime_smoke/tool_capability_status.json](reports/e022_object_lifetime_smoke/tool_capability_status.json) - local tool-lane availability.
- [reports/e022_object_lifetime_smoke/multiview_artifact_summary_20.json](reports/e022_object_lifetime_smoke/multiview_artifact_summary_20.json) - normalized multi-view artifact counts and current missing-view boundary.
- [schemas/tool_derived_normalization_registry.json](schemas/tool_derived_normalization_registry.json) - registry of model-view artifacts, accepted producer tools, and fallback policy.
