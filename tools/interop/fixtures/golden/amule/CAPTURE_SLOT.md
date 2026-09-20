# Empty on purpose — waiting for a reviewed Windows capture.

Do **not** invent aMule Hello / HelloAnswer / MuleInfo bytes in CI or Cursor
Cloud. Populate only after a local operator run with full provenance (client,
exact version, direction, opcode, capture date, normalization).

```text
python3 tools/interop/run.py --ingest-hello capture.hex --reference-client amule --reference-version <exact>
```

See parent `README.md` and GitHub issue #160.
