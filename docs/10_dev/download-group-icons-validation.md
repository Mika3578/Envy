# Download-group icon validation

The automated schema-icon regressions in `tests/test_schema_icon_resources.cpp`
retain the descriptor-resource check and exercise the same portable policies
used by `CSchema::Load`, `CSchema::LoadIcon` and `CShellIcons::Draw`:

- Missing `.Skin.ico`, optional `.Alt.ico`, descriptor default and `.Safe.ico`
  candidates, with alternate icons enabled and disabled, and early stopping.
- Missing 16px frames, per-size insertion failures, preservation of earlier
  valid entries and generic fallback when all candidates fail.
- Negative and out-of-range draw indices, empty/unavailable lists and an
  unavailable generic entry.

Resource/frame availability and image-list insertion results are supplied by
fixtures at the OS boundary. Separate Windows tests load every shipped
`Schemas/*.ico` through `ExtractIconEx` and `PrivateExtractIcons` (16px and
48px frames required) and check that absent, empty, truncated and non-icon
files yield no handle. They do not exercise MFC image-list creation or actual
painting; the visual matrix below remains necessary. Windows `EnvyTests` (`tests/EnvyTests.vcxproj`) registers the module
via `register_schema_icon_resource_tests` in `test_main.cpp`; run from the
repository root so it can locate `Schemas/`.

## Resource root

`CSchemaCache::Load` reads `Schemas/` from the executable's folder when it
holds schema definitions, and otherwise from the persisted `General.Path`
(`SelectSchemaRoot`). `General.Path` is only reset when empty or missing, so a
development build could previously load older installed `Schemas/*.xml` and
`*.ico` while the checked-in set was correct. The Envy project now stages
`Schemas/` (`*.xsd`, `*.xml`, `*.ico`) next to every output (`StageSchemas`).
An installed copy is unchanged: its executable folder is `General.Path`.
`General.Path` and user data are never rewritten. A debug-level log line
reports the substitution without printing paths. `Vendors.xml` still follows
`General.Path`, and `Flags.png`/missing-string diagnostics are unrelated to
schema icons.

Manual UI checks for the maintainer:

1. Start Envy with the default skin and open Downloads. Confirm the default,
   schema-backed, and custom download groups show a 16px icon without clipping.
2. Hover and select each group. Confirm the icon remains aligned and follows
   the skin's hover/active/disabled background states.
3. Enable alternate icons, restart, and repeat the group and schema combo
   checks. Disable alternate icons and confirm the normal/default icon returns.
4. Test at 100%, 125%, 150%, and 200% display scaling. Confirm the icon stays
   centered in the group tab and schema combo row.
5. Where other shell-icon consumers request larger entries, verify the 16px,
   32px, and 48px image-list entries each render the matching icon without
   substituting a different size or clipping it.
6. In a private test copy, temporarily remove or rename every icon fallback
   candidate for one schema (`.Skin.ico`, optional `.Alt.ico`, the descriptor
   `.ico`, and `.Safe.ico`). Confirm the group and combo show the generic file
   icon and do not assert or display a blank/invalid image. Removing a single
   candidate should instead show the next fallback icon, never a blank image.
