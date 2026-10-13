# 🔒 P0.1 Security Fixes Summary - Secure Remote HTTP

**Date:** January 16, 2026
**Priority:** P0 (Critical)
**Status:** ✅ Implemented

> **Historical note (2026-09):** Early P0.1 text described `BindAddress` as an “IP to bind.” Current behavior (D-017 / #392) treats `Settings.Remote.BindAddress` as a **localhost-only access-policy gate**, not a socket bind address. Prefer `docs/20_arch/remote-api.md` and `docs/50_user/reference/COMPLETE_SETTINGS_REFERENCE.md` for the live contract.


---

## 📋 Changes Made

### 1. Added Security Parameters in Settings

**File:** `Envy/Settings.h:693-701`

```cpp
struct sRemote
{
    bool        Enable;
    CString     Username;
    CString     Password;
    CString     BindAddress;            // Access-policy gate: localhost-only when set to loopback (D-017; not a socket bind)
    bool        AllowExternal;          // New: External access (default: false)
    DWORD       RateLimitRequests;      // New: Max requests/minute (default: 10)
    DWORD       RateLimitWindow;        // New: Window in ms (default: 60000)
} Remote;
```

**File:** `Envy/Settings.cpp:662-667`

Default values added:
- `BindAddress = "127.0.0.1"` (localhost-only access policy by default; not a listen bind)
- `AllowExternal = false` (no external access)
- `RateLimitRequests = 10` (10 requests per minute)
- `RateLimitWindow = 60000` (60 second window)

---

### 2. Source Address Verification

**File:** `Envy/UploadTransferHTTP.cpp:456-500`

**Before:**
```cpp
else if ( ::StartsWith( m_sRequest, _P( L"/remote" ) ) )
{
    if ( Settings.Remote.Enable )
    {
        Prefix( _P("GET /remote/ HTTP/1.1\r\n\r\n") );
        new CRemote( this );
        Remove( FALSE );
        return FALSE;
    }
}
```

**After:**
- Verification that source address is localhost (127.0.0.1) by default
- When `Settings.Remote.BindAddress` is a loopback/localhost value, only loopback clients are admitted (policy gate; the HTTP listener bind path is separate)
- Rejection if `AllowExternal = false` and IP not authorized
- Error message logged for unauthorized access attempts

**Impact:** Remote interface not accessible from external network by default

---

### 3. Rate Limiting

**File:** `Envy/Remote.cpp:113-200`

**Added:**
- `RemoteRateLimitInfo` structure for per-IP tracking
- Static map `m_pRateLimits` (IP → Rate limit info)
- Critical section `m_pRateLimitSection` for thread-safety
- Verification in `OnRead()` before request processing

**Behavior:**
- Limit: 10 requests per minute per IP (configurable)
- Automatic cleanup of expired entries (> 2x window)
- Rejection with error message if limit exceeded

**Impact:** Protection against brute force and DoS

---

### 4. CSRF Protection

**Files:** `Envy/Remote.h`, `Envy/Remote.cpp`

**Added:**
- Static map `m_pCSRFTokens` (Cookie ID → CSRF token)
- Critical section `m_pCSRFTokenSection` for thread-safety
- `GetCSRFToken()` function to retrieve session token
- Cryptographic token generation in `PageLogin()`
- Verification in `CheckCookie()` for state-changing operations

**CSRF Token:**
- Generated with CSPRNG / session store (`CRemoteSecurity`)
- Required for known mutating path segments (`newsearch`, `newdownload`, `modify`, `drop`)
- Also required for mutating **query keys** on otherwise-read pages (`connect`, `disconnect`, `filter_set`, `group_select`/`deselect`/`exclusive`, `queue_expand`/`collapse`) — closes #77 path-only blind spot
- Non-empty `_method` overrides require CSRF (must not bypass checks)
- Classic Remote HTML links/forms include `csrf_token` for those actions
- Stored per session; verified in `CheckCookie()` before page handlers mutate state

**Impact:** Protection against cross-origin CSRF attacks

---

## 🔍 Validation Points

### Validation Tests

1. **Test Localhost Access Policy:**
   ```bash
   # With BindAddress=127.0.0.1 (default), non-loopback clients are rejected by the Remote allow gate
   # (listener may still accept the TCP connection; authorization fails)
   curl http://<EXTERNAL_IP>:<PORT>/remote/
   # Expected: unauthorized / access denied (not treated as localhost)
   ```

2. **Test Rate Limiting:**
   ```bash
   # Send 15 rapid requests from localhost
   for i in {1..15}; do curl http://localhost:<PORT>/remote/; done
   # Expected: First 10 succeed, last 5 are rejected
   ```

3. **Test CSRF:**
   ```bash
   # Attempt operation without CSRF token
   curl "http://localhost:<PORT>/remote/newdownload?uri=magnet:..."
   # Expected: Redirect to /remote/ (login)
   ```

---

## 📝 Modified Files

1. `Envy/Settings.h` - Added Remote parameters
2. `Envy/Settings.cpp` - Default values initialization
3. `Envy/Remote.h` - Added rate limiting and CSRF structures
4. `Envy/Remote.cpp` - Rate limiting and CSRF implementation
5. `Envy/UploadTransferHTTP.cpp` - Source address verification

---

## ✅ Acceptance Criteria

- [x] Remote access defaults to localhost-only policy via `BindAddress` (not a socket bind)
- [x] Option for external access via `AllowExternal` (disabled by default; not a socket bind)
- [x] Rate limiting: 10 requests/minute per IP
- [x] CSRF protection with cryptographic tokens
- [x] Tests: Remote HTML authorization denies non-loopback clients by default (listener may still accept the TCP connection)

---

## 🚀 Next Steps

1. **Test compilation** - Verify everything compiles without errors
2. **Functional tests** - Verify Remote works from localhost
3. **Security tests** - Verify rate limiting and CSRF
4. **User documentation** - Explain how to enable external access (if needed)

---

## ⚠️ Important Notes

- **By default:** Remote admits **ONLY** localhost/loopback clients when `BindAddress` is a loopback policy value
- **External access:** Requires explicit configuration (`AllowExternal = true`)
- **Rate limiting:** Can be adjusted in Settings if necessary
- **CSRF:** Tokens generated automatically, transparent to user

---

**Référence:** `SECURITY_AUDIT.md` - Risque #1 (P0)
