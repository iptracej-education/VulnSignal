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
