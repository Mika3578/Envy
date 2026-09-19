# Reference Hello capture slots

Committed golden vectors are allowed only when:

- origin (eMule Community or aMule) is documented
- exact client version is recorded
- packet direction (send/recv) is recorded
- protocol/opcode are recorded
- capture date is recorded
- volatile fields are normalized or explicitly represented
- privacy-sensitive values are removed (userhash, public IPs, profile paths, nicks)

These directories stay empty until a reviewed capture exists. Do not invent bytes.

Use:

```text
python3 tools/interop/run.py --ingest-hello capture.hex --reference-client emule-community --reference-version 0.70a
```

That writes a sanitized *candidate* under the run artifact directory. Copy into
`emule-community/` or `amule/` only after human review. Keep raw pcaps out of git.
