# Buffer growth regression validation

From a Visual Studio 2026 **x64 Native Tools** prompt at the repository root:

```cmd
python tests\run_buffer_growth_tests.py
```

Repeat from an **x86 Native Tools** prompt for Win32 coverage. The runner
extracts the current production method bodies, compiles a standalone harness
with MSVC at `/Od` and `/O2`, and runs both nullable and throwing allocation
variants. Assertions remain active even with `NDEBUG`. Generated files stay
under ignored `.local/buffer-growth/`; no MFC application build is required.

The harness exercises `CHashDatabase::PrepareToStore`, the hub pool and group
methods, `CSearchDetailPanel::CachePreviewImage`, and
`CBrowseTreeItem::AddFileIndex` without copying their implementations into tests.
Allocation overloads inject failure only into the extracted methods. Fixtures
replace surrounding MFC services and expose storage fields; the preview lock
and matches lookup are stubs, so this does not validate synchronization or UI
integration. The standalone executable remains separate from the EnvyTests
process so its fault-injecting allocator cannot affect unrelated tests.

Coverage checks:

- A failed hash replacement preserves the old entry, buffer, capacity, count,
  and data offset. A later successful replacement retires the old record,
  releases the old array once, and preserves best-fit reuse of free records.
- Failed initial and populated hub-list growth acquires no pool reference and
  preserves existing list ownership. Exhaustion skips allocation for a new hub;
  existing hubs can still be shared, and failed sharing acquires no reference.
  Clearing both groups returns the reference counts and active count to zero.
- Failed preview replacement preserves the old bytes and length. Successful
  replacement supports an input buffer aliasing the old preview and releases
  that preview exactly once. An absent matches entry skips allocation.
- Failed browse growth preserves entries, count, pointer, and capacity.
  Successful growth retains the entries and frees the old array once;
  capacity wrap-around and element-byte-size overflow skip allocation and append.

`EnvyTests.vcxproj` runs the same suite before C++ compilation, using the
project platform to initialize the Native Tools environment. A failing harness
command fails the project build, so both required Release platform checks
enforce this coverage. Python 3 and the selected Visual Studio toolset must be
available when building EnvyTests.

These are allocation and ownership regressions, not evidence of a full Windows
application build, live runtime testing, or closure of CodeQL alerts on
`develop`. Required x64/Win32 Release CI and maintainer runtime assessment
remain separate gates. The hash capacity-limit guard is inspected in source;
the harness does not allocate a multi-gigabyte index to exercise that boundary.
