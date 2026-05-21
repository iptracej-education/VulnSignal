#!/usr/bin/env python3
"""Record local tool availability for automated evidence lanes."""

from __future__ import annotations

import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[1]


def write_json(path: Path, row: dict) -> None:
    with path.open("w") as fh:
        json.dump(row, fh, indent=2, sort_keys=False)
        fh.write("\n")


def executable(name: str) -> str | None:
    return shutil.which(name)


def main() -> int:
    svf_bin = REPO_ROOT / ".tools" / "SVF" / "Release-build" / "bin"
    svf_clang = REPO_ROOT / ".tools" / "SVF" / "llvm-21.1.0.obj" / "bin" / "clang"
    tools = {
        "codeql": {"path": executable("codeql"), "lane": "static_codeql"},
        "spatch": {"path": executable("spatch"), "lane": "static_coccinelle"},
        "joern": {"path": executable("joern"), "lane": "static_graph"},
        "joern-parse": {"path": executable("joern-parse"), "lane": "static_graph"},
        "joern-export": {"path": executable("joern-export"), "lane": "static_graph"},
        "syz-manager": {"path": executable("syz-manager"), "lane": "dynamic_oracle"},
        "qemu-system-x86_64": {"path": executable("qemu-system-x86_64"), "lane": "dynamic_oracle"},
        "clang": {
            "path": executable("clang") or (str(svf_clang) if svf_clang.exists() else None),
            "lane": "llvm_bitcode",
        },
        "svf-wpa": {
            "path": str(svf_bin / "wpa") if (svf_bin / "wpa").exists() else None,
            "lane": "static_svf",
        },
        "svf-ex": {
            "path": str(svf_bin / "svf-ex") if (svf_bin / "svf-ex").exists() else None,
            "lane": "static_svf",
        },
        "llvm2svf": {
            "path": str(svf_bin / "llvm2svf") if (svf_bin / "llvm2svf").exists() else None,
            "lane": "static_svf",
        },
    }
    write_json(
        ROOT / "tool_capability_status.json",
        {
            "tools": tools,
            "available_lanes": sorted({tool["lane"] for tool in tools.values() if tool["path"]}),
            "blocked_lanes": sorted({tool["lane"] for tool in tools.values() if not tool["path"]}),
            "notes": [
                "SVF binaries are available locally but require LLVM bitcode generated from buildable translation units.",
                "Dynamic syzkaller/QEMU oracle execution is not available in the current PATH.",
            ],
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
