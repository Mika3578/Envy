# ED2K Download Debug Guide

**Date:** January 18, 2026
**Purpose:** Guide for debugging ED2K download issues using added logging

---

## Debug Logging Overview

Comprehensive debug logging has been added to track ED2K download progression. Look for messages starting with `[ED2K]` in the debug output.

## Normal Download Flow

### 1. Connection Phase
```
[ED2K] client_ip: Sending primary request for filename.ext
[ED2K] client_ip: Sent FILESTATUSREQUEST for large file (size bytes)
[ED2K] client_ip: Primary request sent, waiting for responses
```

### 2. Response Phase
```
[ED2K] client_ip: Received FILEREQANSWER
[ED2K] client_ip: Large file, waiting for FILESTATUS response
[ED2K] client_ip: File status received, calling SendSecondaryRequest()
```

### 3. Secondary Request Phase
```
[ED2K] client_ip: SendSecondaryRequest() called, state=3
[ED2K] client_ip: Requesting hashset
[ED2K] client_ip: Sending queue request
```

### 4. Queue/Download Phase
```
[ED2K] client_ip: Received QUEUERANK 5, setting state to QUEUED
[ED2K] client_ip: Received STARTUPLOAD, transitioning to DOWNLOADING
[ED2K] client_ip: State changed to DOWNLOADING
[ED2K] client_ip: Fragment requests sent successfully (3 pending)
```

## Common Failure Patterns

### Pattern 1: No Responses Received
**Symptoms:**
- Primary request sent but no FILEREQANSWER or FILESTATUS responses
- Download times out in REQUESTING state

**Possible Causes:**
- Client doesn't have the file
- Network connectivity issues
- Packet filtering/firewall issues
- Client compatibility issues

### Pattern 2: File Not Available
**Symptoms:**
```
[ED2K] client_ip: Received FILEREQANSWER
[ED2K] client_ip: File not found on client, closing
```

**Expected:** Download closes with "File not found" message.

### Pattern 3: Stuck in Queue
**Symptoms:**
- Queue position received but no STARTUPLOAD
- Stays in QUEUED state indefinitely

**Possible Causes:**
- Queue not advancing (client busy)
- Upload slot not available
- Client disconnected/reconnected

### Pattern 4: Hashset Issues
**Symptoms:**
```
[ED2K] client_ip: Received HASHSETANSWER
[ED2K] client_ip: Hashset hash mismatch
```

**Possible Causes:**
- Corrupted hashset data
- File hash mismatch
- Protocol version incompatibility

### Pattern 5: Fragment Request Failures
**Symptoms:**
```
[ED2K] client_ip: SendFragmentRequests() called but state=2 (not downloading)
[ED2K] client_ip: No fragments to request, sending QUEUERELEASE
```

**Possible Causes:**
- Download paused/cancelled
- File already complete
- No available ranges to request

## Timeout Messages

### Connection Timeout
```
[ED2K] client_ip: Connection timeout in CONNECTING state
```

### Handshake Timeout
```
[ED2K] client_ip: Handshake timeout in REQUESTING/ENQUEUE state
```

### Traffic Timeout
```
[ED2K] client_ip: Traffic timeout in DOWNLOADING/HASHSET state
```

## Debug Checklist

When investigating download issues:

1. **Check Network Connection**
   - Verify ED2K network is connected
   - Check server list and connections

2. **Verify Source Availability**
   - Confirm sources exist for the file
   - Check source client versions/compatibility

3. **Monitor State Progression**
   - Watch for state transitions in debug log
   - Identify where progression stops

4. **Check Client Responses**
   - Look for FILEREQANSWER/FILESTATUS responses
   - Verify hashset processing if needed

5. **Test Different Scenarios**
   - Small vs large files
   - Files with many vs few sources
   - Different client software

## Common Fixes

### For No Responses:
- Check firewall/antivirus settings
- Try different ED2K servers
- Update client software

### For Queue Issues:
- Wait for queue to advance naturally
- Try downloads with fewer sources
- Check client upload settings

### For Hashset Issues:
- Clear download and restart
- Check file integrity
- Try different sources

## Log Analysis Tips

- Filter logs for specific client IP: `grep "client_ip" debug.log`
- Look for state progression: `grep "state.*to\|State changed" debug.log`
- Check for errors: `grep "ERROR\|timeout\|failed\|mismatch" debug.log`
- Monitor packet flow: `grep "Received\|Sent\|sending" debug.log`

---

**Debug logging added to:** `CDownloadTransferED2K` methods
**Log level:** `MSG_DEBUG` with `[ED2K]` prefix
**Enable debug logging:** Set debug level to include MSG_DEBUG
