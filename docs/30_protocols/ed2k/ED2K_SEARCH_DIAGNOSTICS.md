# ED2K Search Results Diagnostic Guide

## Issue: Cannot Get Search Results

### Problem Analysis

The ED2K search functionality relies on GUID tracking between search requests and responses. Search results are matched to active searches using the `m_oSearchID` GUID in query hits.

### Code Flow

1. **Search Request Sent**: `EDNeighbour::SendQuery()` (line 824)
   - Adds search GUID to `m_pQueries` queue: `m_pQueries.AddTail(pSearch->m_oGUID)`
   - Sends search packet to server

2. **Search Results Received**: `EDNeighbour::OnSearchResults()` (line 583)
   - Removes GUID from queue: `oGUID = m_pQueries.RemoveHead()`
   - Creates QueryHit with this GUID: `CQueryHit::FromEDPacket(..., oSearchID)`
   - Routes to search window: `Network.OnQueryHits(pHits)`

3. **Search Window Matching**: `WndSearch::OnQueryHits()` (line 786)
   - Matches hits to search: `(*pManaged)->IsEqualGUID(pHits->m_oSearchID)`
   - Falls back for empty GUID: `(!pHits->m_oSearchID && (*pManaged)->IsLastSearch())`

### Potential Issues

#### Issue 1: Query Queue Empty
**Symptom**: `m_pQueries.GetCount() == 0` when results arrive

**Causes**:
- Search GUID not added to queue (SendQuery not called)
- GUID removed too early (results arrive out of order)
- Multiple searches sent but responses delayed

**Location**: `EDNeighbour::OnSearchResults()` line 589

**Impact**: Results have empty GUID, only match if search is "last search"

#### Issue 2: Search Not Connected to Server
**Symptom**: Search queries not being sent

**Check**: 
- Server connection status: `m_nState == nrsConnected`
- Client ID assigned: `m_nClientID != 0`
- Server stable: `tTicks >= pNeighbour->m_tConnected + 15000`

**Location**: `ManagedSearch::ExecuteNeighbours()` line 248-253

#### Issue 3: UDP Search Results Not Matched
**Symptom**: UDP search results received but not displayed

**Issue**: UDP results in `EDClients::OnServerSearchResult()` use empty GUID
- No GUID tracking for UDP searches
- Results may not match any active search

**Location**: `EDClients::OnServerSearchResult()` line 630

### Diagnostic Steps

#### Step 1: Verify Search is Being Sent
Add debug logging in `EDNeighbour::SendQuery()`:
```cpp
theApp.Message(MSG_DEBUG, L"ED2K: Sending search query, GUID=%s, Queue size=%d", 
    pSearch->m_oGUID.toString().GetString(), m_pQueries.GetCount());
```

#### Step 2: Verify Results Are Received
Add debug logging in `EDNeighbour::OnSearchResults()`:
```cpp
theApp.Message(MSG_DEBUG, L"ED2K: Received search results, Queue size=%d, GUID=%s, HasValidGUID=%d", 
    m_pQueries.GetCount(), oGUID.toString().GetString(), bHasValidGUID ? 1 : 0);
```

#### Step 3: Verify GUID Matching
Add debug logging in `WndSearch::OnQueryHits()`:
```cpp
theApp.Message(MSG_DEBUG, L"ED2K: Matching hit GUID=%s to search GUID=%s, Match=%d", 
    pHits->m_oSearchID.toString().GetString(), 
    (*pManaged)->GetSearch()->m_oGUID.toString().GetString(),
    (*pManaged)->IsEqualGUID(pHits->m_oSearchID) ? 1 : 0);
```

#### Step 4: Check Server Connection
Verify ED2K server is connected:
- Check server status in Neighbours list
- Verify `m_nClientID != 0`
- Check server stability (connected > 15 seconds)

### Recommended Fixes

#### Fix 1: Improve GUID Tracking (TCP Searches)
**Problem**: Query queue can become empty if results arrive out of order

**Solution**: Use a GUID lookup map instead of queue for better tracking

**Implementation**: Replace `CList<Hashes::Guid> m_pQueries` with `CMap<Hashes::Guid, Hashes::Guid, DWORD, DWORD>` to track query timestamps

#### Fix 2: Add GUID Tracking for UDP Searches
**Problem**: UDP search results don't have search GUID

**Solution**: Track UDP search requests with server address + timestamp

**Location**: `EDClients::OnServerSearchResult()` needs search GUID association

#### Fix 3: Fallback to Last Search for Empty GUID
**Current**: Only works if search is "last search"

**Enhancement**: Try to match empty GUID to most recent matching search based on search terms

### Quick Test

1. **Enable Debug Logging**:
   - Check "Show Debug Messages" in settings
   - Filter for "ED2K" messages

2. **Perform Search**:
   - Search for a common term (e.g., "test")
   - Watch for debug messages showing:
     - Query being sent
     - Results being received
     - GUID matching attempts

3. **Check Queue Status**:
   - After sending search, check `m_pQueries.GetCount()`
   - Should be > 0 immediately after sending

4. **Verify Results Arrive**:
   - After receiving results, check if GUID matched
   - Empty GUID should fall back to "last search"

### Temporary Workaround

If search results are not appearing:

1. **Use Text Searches Only**: Text searches (not hash searches) work better with empty GUID fallback
2. **Wait for Server Stability**: Ensure server is connected > 15 seconds before searching
3. **Use Single Search**: Don't send multiple searches simultaneously (can cause queue confusion)

### Long-Term Solution

Implement proper GUID tracking using a timestamped map instead of a queue:

```cpp
// In EDNeighbour.h
CMap<Hashes::Guid, Hashes::Guid, DWORD, DWORD> m_mapQueries;  // GUID -> timestamp

// In SendQuery()
m_mapQueries.SetAt(pSearch->m_oGUID, GetTickCount());

// In OnSearchResults()
// Find GUID that matches based on timestamp or use first available
// Remove GUID after matching or timeout (30 seconds)
```

This would handle out-of-order responses better and provide timeout cleanup.

---

**Last Updated**: January 16, 2026  
**Status**: Diagnostic Guide - Pending Implementation
