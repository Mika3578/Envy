#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Extract the unchanged MetaFetch receive methods for the isolated harness."""

import argparse
from pathlib import Path

from extract_thex_test_methods import extract


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    methods = {
        "Envy/DownloadTransferHTTP.cpp": [
            "BOOL CDownloadTransferHTTP::ReadInput()",
            "BOOL CDownloadTransferHTTP::ReceiveMetadataInput()",
            "BOOL CDownloadTransferHTTP::ReadMetadata(bool bDropped)",
        ],
    }
    output = ["// Extracted unchanged from the current checkout; do not edit.\n"]
    for path, signatures in methods.items():
        source = (root / path).read_bytes().replace(b"\r\n", b"\n").decode("latin1")
        for signature in signatures:
            body, line = extract(source, signature)
            output.append(f'#line {line} "{path}"\n{body}\n')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes("".join(output).encode("latin1"))


if __name__ == "__main__":
    main()
