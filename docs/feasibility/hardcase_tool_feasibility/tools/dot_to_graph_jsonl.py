#!/usr/bin/env python3
"""Convert Graphviz DOT files into a simple graph JSONL format.

This is a feasibility helper for VulnSignal optional graph-structure inputs.
It uses Graphviz's own DOT parser via `dot -Tjson`, then emits one JSON object
per source graph with normalized node and edge records.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


def graphviz_json(dot_path: Path) -> dict:
    completed = subprocess.run(
        ["dot", "-Tjson", str(dot_path)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return json.loads(completed.stdout)


def normalize_label(label: str | None) -> str:
    if not label:
        return ""
    return (
        label.replace("<BR/>", " | ")
        .replace("<BR />", " | ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
    )


def convert(dot_path: Path, tool: str, graph_kind: str) -> dict:
    graph = graphviz_json(dot_path)
    objects = graph.get("objects") or []

    nodes = []
    for obj in objects:
        nodes.append(
            {
                "node_id": str(obj.get("name", obj.get("_gvid", ""))),
                "label": normalize_label(obj.get("label")),
                "raw_gvid": obj.get("_gvid"),
            }
        )

    edges = []
    for edge in graph.get("edges") or []:
        tail_index = edge.get("tail")
        head_index = edge.get("head")
        tail = objects[tail_index].get("name") if isinstance(tail_index, int) else tail_index
        head = objects[head_index].get("name") if isinstance(head_index, int) else head_index
        edges.append(
            {
                "src": str(tail),
                "dst": str(head),
                "edge_label": normalize_label(edge.get("label")),
            }
        )

    return {
        "graph_id": f"{tool}:{graph_kind}:{dot_path.name}",
        "tool": tool,
        "graph_kind": graph_kind,
        "source_dot": str(dot_path),
        "graph_name": graph.get("name", dot_path.stem),
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tool", required=True)
    parser.add_argument("--graph-kind", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("dot_files", nargs="+")
    args = parser.parse_args()

    with Path(args.output).open("w", encoding="utf-8") as out:
        for dot_file in args.dot_files:
            record = convert(Path(dot_file), args.tool, args.graph_kind)
            out.write(json.dumps(record, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
