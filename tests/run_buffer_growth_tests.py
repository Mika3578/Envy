#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run buffer ownership regressions from a Visual Studio Native Tools prompt."""

from pathlib import Path
import os
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parent.parent
    output = root / ".local" / "buffer-growth" / os.environ.get("VSCMD_ARG_TGT_ARCH", "native")
    output.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [sys.executable, str(root / "tests/extract_buffer_growth_methods.py"),
         "--output", str(output / "buffer_growth_methods.inc")], check=True,
    )
    for optimization in ("Od", "O2"):
        for mode in ("null", "throw"):
            target = output / f"{mode}-{optimization}"
            command = [
                "cl", "/nologo", "/std:c++17", "/EHsc", "/W4", "/WX",
                f"/{optimization}", "/DNDEBUG", f"/I{output}",
                str(root / "tests/test_buffer_growth.cpp"),
                f"/Fe:{target}.exe", f"/Fo:{target}.obj",
            ]
            if mode == "throw":
                command.append("/DTEST_THROW_ALLOCATION")
            subprocess.run(command, cwd=root, check=True)
            subprocess.run([str(target) + ".exe"], cwd=root, check=True)


if __name__ == "__main__":
    main()
