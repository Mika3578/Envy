# Legacy Internet Explorer WebHook

`WebHook32.dll` (Win32) and `WebHook64.dll` (x64) are a **legacy Internet Explorer**
Browser Helper Object (BHO). The historical filename `WebHook.dll` is still recognized
for startup skip. They are **not** an HTTP/API "webhook".

## What it does

1. Attaches to IE `DWebBrowserEvents2`.
2. When navigation targets a file whose extension is listed in
   `Downloads.WebHookExtensions`, remembers the URL.
3. On `DISPID_FILEDOWNLOAD`, cancels IE's download and launches
   `envy://url:<URL>` so Envy's download manager takes over.
4. Adds an IE context-menu entry **Download with Envy** via
   `HKCU\...\Internet Explorer\MenuExt`.

```
Internet Explorer  -->  WebHook BHO  -->  envy://url:...  -->  Envy downloads
```

## What it does not do

- Edge Chromium, Chrome, and Firefox **do not** load this BHO.
- It does not provide modern browser download interception.

## Registration (Envy 4.x+)

| Condition | Behavior |
| --- | --- |
| `Downloads.WebHookEnable` = false (default) | Neither `WebHook32.dll` nor `WebHook64.dll` (nor historical `WebHook.dll`) is registered at Envy startup |
| Enabled + non-admin / per-user | `DllInstall(..., "user")`; COM under per-user HKCR; BHO key under **HKCU** |
| Enabled + machine-wide `DllRegisterServer` | COM machine-wide; BHO key under **HKLM** |

Shared CLSID (x86 and x64): `{C0283C00-AA11-43E4-8C1D-8D28A0C86042}`.

Normal non-elevated Envy startup must not require administrator rights for this
component.

## Modernization direction

- Keep the `envy://url:` handoff (useful for any future browser integration).
- Treat the IE BHO / MenuExt as removal candidates.
- Prefer an optional Chrome/Edge/Firefox extension (Native Messaging or a
  registered protocol) for "Download with Envy" on modern browsers.
