#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Build and run the MetaFetch receive regressions.

On Windows run from a Visual Studio Native Tools prompt (cl). Elsewhere the
C++ compiler named by CXX (default c++) builds the same source against the
minimal Win32 type shim in tests/shim.
"""

from pathlib import Path
import os
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parent.parent
    output = (root / ".local" / "metafetch-receive"
              / os.environ.get("VSCMD_ARG_TGT_ARCH", "native")
              / os.environ.get("ENVY_METAFETCH_CONFIGURATION", "standalone"))
    output.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [sys.executable, str(root / "tests/extract_metafetch_receive_methods.py"),
         "--output", str(output / "metafetch_receive_methods.inc")], check=True,
    )
    source = str(root / "tests/test_metafetch_receive.cpp")
    for optimization in ("Od", "O2"):
        target = output / f"metafetch-{optimization}"
        if os.name == "nt":
            command = [
                "cl", "/nologo", "/std:c++17", "/EHsc", "/W4", "/WX",
                f"/{optimization}", "/DNDEBUG", "/DUNICODE", "/D_UNICODE",
                f"/I{output}", source, f"/Fe:{target}.exe", f"/Fo:{target}.obj",
            ]
            executable = f"{target}.exe"
        else:
            level = "-O0" if optimization == "Od" else "-O2"
            # Production switch statements fall through by design.
            command = [
                os.environ.get("CXX", "c++"), "-std=c++17", "-Wall", "-Wextra",
                "-Werror", "-Wno-implicit-fallthrough", level, "-DNDEBUG", f"-I{root / 'tests/shim'}",
                f"-I{output}", source, "-o", str(target),
            ] + os.environ.get("ENVY_TEST_CXXFLAGS", "").split()
            executable = str(target)
        subprocess.run(command, cwd=root, check=True)
        subprocess.run([executable], cwd=root, check=True)


if __name__ == "__main__":
    main()
