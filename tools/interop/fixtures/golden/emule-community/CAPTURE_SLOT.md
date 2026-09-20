# Empty on purpose — waiting for a reviewed Windows capture.

Do **not** invent eMule Community Hello / HelloAnswer / MuleInfo bytes in CI or
Cursor Cloud. Populate only after a local operator run with:

| Field | Required |
| --- | --- |
| `reference_client` | `emule-community` |
| `reference_version` | exact build string |
| `packet_direction` | `send` or `recv` |
| `protocol` / `opcode` | e.g. 0xE3 / 0x01 |
| `capture_date` | ISO date |
| `normalization` | what was zeroed |
| `provenance` | how/where captured (notes) |

Ingest candidate:

```text
python3 tools/interop/run.py --ingest-hello capture.hex --reference-client emule-community --reference-version <exact>
```

See parent `README.md` and GitHub issue #160.
