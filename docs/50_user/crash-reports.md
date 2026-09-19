# Crash reports (users)

If ENVY closes unexpectedly, the next launch may show a **crash report**
dialog. ENVY stores reports on your computer only. It does **not** send dumps,
logs, or telemetry automatically. A GitHub account is **not** required to keep
using ENVY.

## Where reports are stored

`%LOCALAPPDATA%\Envy\CrashReports\`

Typical expansion:

`C:\Users\<you>\AppData\Local\Envy\CrashReports\`

Each crash is a pair of files with the same base name:

- `.dmp` — Windows minidump (may contain fragments of memory from the crashed
  process, including private data)
- `.txt` — short sanitized summary (version, architecture, exception code,
  timestamp, dump file name)

Filenames do not include your Windows user name, download names, search terms,
or peer addresses.

## What a dump may contain

A minidump is **not anonymous** and is **not** a privacy-safe log. Even this
smaller dump type can include snippets of memory (paths, names, or other data
that happened to be on a thread stack).

Do not email or upload a `.dmp` unless you intend to share that information
with maintainers.

ENVY does **not** attach registry exports, shared-file lists, or download
names to crash reports.

## How to report a crash

1. Let ENVY start again. If a previous crash was detected, read the dialog.
2. Use **Copy sanitized report** and paste that text into a GitHub issue if
   you want help.
3. Use **Open crash-report folder** to see the files.
4. Use **Open GitHub issue page** if you want the tracker. Paste the copied
   text. Attach the `.dmp` **only if you choose to**.
5. Continue using ENVY without a GitHub account if you prefer.

Issue tracker: [Mika3578/Envy issues](https://github.com/Mika3578/Envy/issues/new)

## Retention

ENVY keeps a small number of recent reports (about eight, or about 50 MB) so
the folder cannot grow without bound. The newest report is not deleted before
you have had a chance to see it on the next launch.

## If dump creation fails

ENVY still exits (or Windows Error Reporting still runs). A missing dump does
not prevent ENVY from starting later.
