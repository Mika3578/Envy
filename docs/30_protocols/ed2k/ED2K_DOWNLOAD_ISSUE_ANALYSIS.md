# ED2K Download Start Issue Analysis

**Date:** January 18, 2026  
**Issue:** Downloads don't start on ED2K network  
**Status:** Analysis in progress

---

## Problem Description

Users report that ED2K downloads initiate (connections are established) but never actually start transferring data. Downloads appear to be stuck in an early state.

## Investigation Findings

### 1. Download Initiation Flow (Normal)

```
CDownloadTransferED2K::Initiate()
├── EDClients.Connect() - establishes client connection
├── CEDClient::AttachDownload() - attaches download to client
├── CEDClient::OnConnected() - sends HELLO
├── CEDClient::OnLoggedIn() - handshake complete
└── CDownloadTransferED2K::OnConnected() - calls SendPrimaryRequest()
```

### 2. Primary Request Phase

```cpp
SendPrimaryRequest() sends:
- ED2K_C2C_FILEREQUEST (with file hash)
- ED2K_C2C_FILESTATUSREQUEST (with file hash)
```

Expected responses:
- `ED2K_C2C_FILEREQANSWER` → `OnFileReqAnswer()`
- `ED2K_C2C_FILESTATUS` → `OnFileStatus()`

### 3. Secondary Request Phase

After receiving responses, `SendSecondaryRequest()` should:
- Request hashset if needed
- Send queue request for download slot
- Set state to `dtsEnqueue` or `dtsHashset`

### 4. Fragment Request Phase

Once queued/downloading, `SendFragmentRequests()` should:
- Request actual file parts
- Set state to `dtsDownloading`

## Potential Root Causes

### Issue #1: UDP Packet Parsing Regression

**Hypothesis:** My UDP packet parsing fix may have introduced a regression affecting TCP packet processing.

**Evidence:**
- UDP fix was in `EDClients.cpp::OnServerSearchResultRaw()` - handles server UDP responses
- TCP downloads use client-to-client connections, not server UDP responses
- **However:** The fix involved packet inflation and position tracking

**Test:** Check if downloads work when ED2K UDP search is disabled.

### Issue #2: Packet Format/Hash Issues

**Potential Problems:**
- File hash format incorrect in requests
- Extended request flags not compatible
- Client doesn't recognize file

**Evidence:**
- `SendPrimaryRequest()` sends ED2K hash correctly
- Extended request logic looks correct
- Hash validation in responses appears proper

### Issue #3: Client Response Handling

**Potential Problems:**
- Clients don't respond to requests (timeout)
- Responses are malformed
- Packet routing fails

**Evidence:**
- Packet routing in `CEDClient::OnPacket()` looks correct
- Timeout handling exists (30 second timeouts)
- Exception handling in place

### Issue #4: State Machine Issues

**Potential Problems:**
- Download stays in wrong state
- State transitions fail
- `OnRun()` logic doesn't advance state

**Evidence:**
- State machine looks correct
- `OnRun()` calls appropriate handlers
- Timeouts should catch stuck states

## Current Investigation Status

### What I've Checked:
✅ Connection establishment works (downloads show as connecting)
✅ Client creation and attachment works
✅ Primary request sending works
❓ Client responses may not be received/processed
❓ Secondary request phase may not execute

### Debug Logging Added

I've added comprehensive debug logging to track the download flow:

#### Primary Request Phase
- `SendPrimaryRequest()` - Logs when requests are sent
- `OnFileReqAnswer()` - Logs when FILEREQANSWER is received
- `OnFileStatus()` - Logs when FILESTATUS is received
- `OnFileNotFound()` - Logs when file is not found

#### Secondary Request Phase
- `SendSecondaryRequest()` - Logs hashset requests, queue requests, or closures
- `OnHashsetAnswer()` - Logs hashset validation and processing

#### Download Phase
- `OnStartUpload()` - Logs transition to DOWNLOADING state
- `OnQueueRank()` - Logs queue position updates
- `SendFragmentRequests()` - Logs fragment request sending
- `OnRunEx()` - Logs state timeouts and transitions

#### State Changes
- All `SetState()` calls now log state transitions

### Next Steps:

1. **Test with Debug Logging:** Run downloads and check debug output
2. **Identify Stuck Point:** Find where downloads stop progressing
3. **Check Response Handling:** Verify client responses are being parsed
4. **Test Different File Types:** Small vs large files, available vs unavailable
5. **Isolate UDP Fix Impact:** Test with UDP search disabled if needed

## Debug Logging Plan

Add logging to:
- `SendPrimaryRequest()` - confirm requests sent
- `OnFileReqAnswer()` - confirm responses received
- `OnFileStatus()` - confirm status received  
- `SendSecondaryRequest()` - confirm secondary phase starts
- `SendFragmentRequests()` - confirm fragment requests sent

## Test Cases

1. **Small File Download:** Should work immediately (no queuing)
2. **Large File Download:** Goes through full queue process
3. **UDP Search Disabled:** Isolates UDP parsing issues
4. **Fresh Client Connection:** Rules out cached state issues

---

**Analysis in Progress:** Need to add debug logging to isolate where downloads get stuck.
