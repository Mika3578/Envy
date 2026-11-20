#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Extract unchanged buffer methods for the isolated allocation-failure harness."""

import argparse
from pathlib import Path

from extract_thex_test_methods import extract


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    methods = {
        "Envy/HashDatabase.cpp": [
            "HASHDB_INDEX* CHashDatabase::Lookup(",
            "HASHDB_INDEX* CHashDatabase::PrepareToStore(",
        ],
        "Envy/HubHorizon.cpp": [
            "BOOL CHubHorizonPool::CanAdd(",
            "CHubHorizonHub* CHubHorizonPool::Add(",
            "void CHubHorizonPool::Remove(",
            "CHubHorizonHub* CHubHorizonPool::Find(",
            "void CHubHorizonGroup::Add(",
            "void CHubHorizonGroup::Clear(",
        ],
        "Envy/CtrlSearchDetailPanel.cpp": [
            "BOOL CSearchDetailPanel::CachePreviewImage(",
        ],
        "Envy/CtrlBrowseTree.cpp": ["void CBrowseTreeItem::AddFileIndex("],
    }
    output = ["// Extracted unchanged from the current checkout.\n"]
    for path, signatures in methods.items():
        source = (root / path).read_bytes().replace(b"\r\n", b"\n").decode("latin1")
        for signature in signatures:
            body, line = extract(source, signature)
            output.append(f'#line {line} "{path}"\n{body}\n')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes("".join(output).encode("latin1"))


if __name__ == "__main__":
    main()
