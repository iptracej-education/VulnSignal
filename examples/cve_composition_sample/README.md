# CVE Composition Sample

This directory shows what the VulnSignal dataset and representation records look like without publishing raw construction artifacts.

The records are derived from an admitted internal CVE composition package, then sanitized for release. Construction-only identifiers, CVE IDs, file paths, function names, line numbers, source hashes, raw CodeQL facts, raw Joern facts, patches, and source code are removed.

## Files

| File | Purpose |
| --- | --- |
| `dataset_summary.json` | Small summary of the full dataset shape and what this sample contains. |
| `sample_model_inputs.jsonl` | Two example model-input records using only model-visible L0 and L2 fields. |
| `sample_labels.jsonl` | Labels for the sample records, separated from model inputs. |
| `sample_l0_l2_record.json` | Expanded example of the model-visible representation for one vulnerable sample. |
| `sample_audit_record_redacted.json` | Redacted L1 audit trace showing how evidence is retained without exposing source-specific details. |
| `controlled_vocabulary_excerpt.json` | Vocabulary excerpt for the L0 and L2 terms used in this sample. |

## Label Meaning

The label is not copied from a file name, variance type, patch, or CVE text. It is accepted only after the candidate representation is checked against the accepted CVE composition rule.

```text
1 = candidate satisfies the accepted, tool-grounded vulnerable composition
0 = candidate fails the accepted composition
```

## Representation Layers

```text
raw tool facts
    -> L0 normalized execution/path events
    -> L1 concrete CVE audit chain
    -> L2 transferable vulnerability mechanism
```

Only L0 and L2 are shown as model-facing input in this sample. L1 is included only as a redacted audit example.

