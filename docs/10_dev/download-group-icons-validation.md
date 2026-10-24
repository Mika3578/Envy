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

`StageSchemas` (`Envy.vcxproj`) copies `Schemas/*.xsd`, `*.xml` and `*.ico` into
`<output>\Schemas\` and then writes `Schemas.manifest`, listing exactly the
files it staged. On the next build, files listed by the previous manifest but no
longer in the repository are deleted from the output. Only manifest-recorded
names are removed, only inside that output folder, and only their file-name part
is used. Unlisted files, user folders and installed copies are never touched.
Output folders staged before the manifest existed have no record, so delete a
stale `<output>\Schemas\` folder once by hand.

`CSchemaCache::Load` only selects the root (`SelectSchemaRoot`); the icon and
descriptor lookup itself stays in `CSchema::Load` (`Schema.cpp`). It uses the executable's `Schemas/`
folder only when `Schemas.manifest` is present, valid, and every file it lists
exists. A partial copy (an interrupted build, a missing icon or descriptor) or a
folder without a manifest is not trusted: `General.Path` is used when it has
`*.xsd` files, so an installed copy, where both folders are the same, behaves as
before. A partial executable folder is only a last resort when `General.Path`
has no schemas at all. Unlisted extra files do not make a folder incomplete; the
build, not the runtime, removes them. `General.Path` is only reset when empty
or missing and is never rewritten. A debug-level log line reports the
substitution without printing paths.

Only the choice of the `Schemas/` root changed. Every other consumer keeps its
own lookup: `Schemas\WindowsLibrary.ico` (`LibraryFolders.cpp`) still reads
`General.Path`, `Vendors.xml` still tries `General.DataPath` first and then
`General.Path\Data` (`VendorCache.cpp`), and `Flags.png`/missing-string
diagnostics are unrelated to schema icons.

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
7. Resource root, in a private test copy of a build output: (a) rename one
   `<output>\Schemas\*.ico` listed in `Schemas.manifest`, start Envy, and confirm
   the schema icons still appear (loaded from `General.Path`) with no blank
   entries; (b) restore it and confirm the output folder is used again; (c) delete
   a schema from the repository set (or simulate with a manifest entry), rebuild,
   and confirm the stale file is removed from the output while unrelated files in
   that folder remain; (d) set `General.Path` to another install and confirm a
   complete output folder still wins and the other install is unchanged.
