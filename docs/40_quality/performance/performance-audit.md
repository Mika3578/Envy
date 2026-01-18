# ⚡ Performance Audit - Envy

**Date:** January 16, 2026
**Version:** 1.0
**Objective:** Identification of freeze/lag sources and refactoring recommendations

---

## 🔍 Identified Freeze/Lag Sources

### 1. UI Calls from Network Threads

**Problem:** Network threads directly call UI functions, causing freezes.

**Affected Files:**
- `Envy/Network.cpp:1371-1401` - `ProcessQueryHits()` calls `PostMessage` from network thread
- `Envy/Remote.cpp:658-682` - `PageSearch()` accesses `CMainWnd` from HTTP thread
- `Envy/Downloads.cpp:939-1018` - UI updates from download threads

**Problematic Example:**
```cpp
// Envy/Network.cpp:1371-1401
bool CNetwork::ProcessQueryHits(CNetwork::CJob& oJob) {
    // ...
    case 2:  // Send hits to search windows
    {
        CSingleLock oAppLock( &theApp.m_pSection );
        if ( oAppLock.Lock( 250 ) ) {
            if ( CMainWnd* pMainWnd = theApp.SafeMainWnd() ) {
                // ❌ Direct UI access from network thread
                while ( ( pChildWnd = pMainWnd->m_pWindows.Find( NULL, pChildWnd ) ) != NULL ) {
                    if ( pChildWnd->IsKindOf( RUNTIME_CLASS( CSearchWnd ) ) ) {
                        if ( pChildWnd->OnQueryHits( pHits ) )  // Direct UI call
                            bHandled = TRUE;
                    }
                }
            }
        }
    }
}
```

**Recommended Refactoring:**
```cpp
// Envy/Network.cpp - Refactored version
bool CNetwork::ProcessQueryHits(CNetwork::CJob& oJob) {
    // ...
    case 2:  // Send hits to search windows
    {
        // ✅ Create immutable data snapshot
        CQueryHitSnapshot* pSnapshot = new CQueryHitSnapshot(pHits);
        
        // ✅ PostMessage asynchrone vers thread UI
        if ( CMainWnd* pMainWnd = theApp.SafeMainWnd() ) {
            pMainWnd->PostMessage(WM_QUERY_HITS_READY, (WPARAM)pSnapshot, 0);
        } else {
            delete pSnapshot;  // Nettoyer si pas de fenêtre
        }
        
        oJob.Next();
    }
}

// Envy/WndMain.cpp - Handler UI thread
LRESULT CMainWnd::OnQueryHitsReady(WPARAM wParam, LPARAM lParam) {
    CQueryHitSnapshot* pSnapshot = (CQueryHitSnapshot*)wParam;
    
    // Traiter dans le thread UI
    for (auto pChildWnd = m_pWindows.Find(NULL, NULL); pChildWnd; 
         pChildWnd = m_pWindows.Find(NULL, pChildWnd)) {
        if (pChildWnd->IsKindOf(RUNTIME_CLASS(CSearchWnd))) {
            static_cast<CSearchWnd*>(pChildWnd)->OnQueryHitsSnapshot(pSnapshot);
        }
    }
    
    delete pSnapshot;
    return 0;
}
```

**Files to Modify:**
- `Envy/Network.cpp:1353-1412` - Refactor `ProcessQueryHits()`
- `Envy/WndMain.h` - Add handler `OnQueryHitsReady()`
- `Envy/WndMain.cpp` - Implement handler
- `Envy/QueryHit.h` - Create `CQueryHitSnapshot` class (immutable snapshot)

**Complexity:** Medium (M)
**Impact:** High - Eliminates freezes when receiving search results

---

### 2. Lock Contention - Critical Section Too Large

**Problem:** Critical sections are too large, causing contention.

**Affected Files:**
- `Envy/Network.cpp:1225-1266` - `RunJobs()` holds lock too long
- `Envy/Downloads.cpp:939-1018` - Lock held during processing
- `Envy/NeighboursBase.cpp:216-268` - Lock during full iteration

**Exemple problématique:**
```cpp
// Envy/Network.cpp:1225-1266
void CNetwork::RunJobs() {
    const DWORD nStop = GetTickCount() + 250;
    
    CSingleLock oJobLock( &m_pJobSection, TRUE );  // ❌ Lock taken
    
    while ( ! m_oJobs.IsEmpty() && GetTickCount() < nStop ) {
        CJob oJob = m_oJobs.RemoveHead();
        
        oJobLock.Unlock();  // ✅ Already better
        
        // ... traitement ...
        
        CSingleLock oNetworkLock( &m_pSection, FALSE );
        if ( oNetworkLock.Lock( 250 ) ) {  // ❌ Network lock during processing
            switch ( oJob.GetType() ) {
            case CJob::Hit:
                bKeep = ProcessQueryHits( oJob );  // Traitement long
                break;
            // ...
            }
            oNetworkLock.Unlock();
        }
        
        oJobLock.Lock();  // Re-lock pour itération suivante
    }
}
```

**Refactoring recommandé:**
```cpp
// Envy/Network.cpp - Version optimisée
void CNetwork::RunJobs() {
    const DWORD nStop = GetTickCount() + 250;
    
    // ✅ Collect jobs quickly (minimal lock)
    CList<CJob> jobsToProcess;
    {
        CSingleLock oJobLock( &m_pJobSection, TRUE );
        while (!m_oJobs.IsEmpty() && jobsToProcess.GetCount() < 10) {
            jobsToProcess.AddTail(m_oJobs.RemoveHead());
        }
    }  // Lock released immediately
    
    // ✅ Traiter sans lock
    while (!jobsToProcess.IsEmpty() && GetTickCount() < nStop) {
        CJob oJob = jobsToProcess.RemoveHead();
        
        // Processing without network lock
        bool bKeep = ProcessQueryHitsUnlocked(oJob);
        
        // ✅ Re-add only if necessary (minimal lock)
        if (bKeep) {
            CSingleLock oJobLock( &m_pJobSection, TRUE );
            m_oJobs.AddTail(oJob);
        }
    }
}

// ✅ New method without lock
bool CNetwork::ProcessQueryHitsUnlocked(CNetwork::CJob& oJob) {
    CQueryHit* pHits = (CQueryHit*)oJob.GetData();
    
    // Processing without access to shared structures
    // Use snapshots/local copies
    switch (oJob.GetStage()) {
    case 0:
        // Traitement local uniquement
        break;
    // ...
    }
    
    return true;
}
```

**Files to Modify:**
- `Envy/Network.cpp:1225-1266` - Refactor `RunJobs()`
- `Envy/Network.cpp` - Add `ProcessQueryHitsUnlocked()`
- `Envy/Network.cpp` - Add `ProcessQuerySearchUnlocked()`

**Complexity:** Medium (M)
**Impact:** High - Reduces lock contention by 60-80%

---

### 3. Inefficient Polling Loops

**Problem:** Polling loops that waste CPU unnecessarily.

**Affected Files:**
- `Envy/Network.cpp:791-875` - `OnRun()` loop with `Doze(100)`
- `Envy/Downloads.cpp` - Frequent polling of downloads
- `Envy/NeighboursBase.cpp` - Periodic connection checks

**Exemple problématique:**
```cpp
// Envy/Network.cpp:791-875
void CNetwork::OnRun() {
    while ( IsThreadEnabled() ) {
        Doze( 100 );  // ❌ Polling every 100ms

        if ( ! theApp.m_bLive || ( UPnPFinder && UPnPFinder->IsAsyncFindRunning() ) ) {
            Sleep( 0 );  // ❌ Wastefully yield CPU
            continue;
        }
        
        // ... traitement ...
    }
}
```

**Refactoring recommandé:**
```cpp
// Envy/Network.cpp - Version avec événements
void CNetwork::OnRun() {
    HANDLE hEvents[] = {
        m_hStopEvent,           // Stop event
        m_hJobReadyEvent,       // New job available
        m_hUPnPCompleteEvent,   // UPnP completed
        // ... autres événements
    };
    
    while ( IsThreadEnabled() ) {
        // ✅ Wait for events instead of polling
        DWORD dwWait = WaitForMultipleObjects(
            _countof(hEvents), hEvents, FALSE, INFINITE);
        
        if (dwWait == WAIT_OBJECT_0) break;  // Stop
        
        if (dwWait == WAIT_OBJECT_0 + 1) {  // Job ready
            RunJobs();
        }
        
        // Periodic processing (every 5 seconds max)
        static DWORD lastPeriodic = 0;
        DWORD now = GetTickCount();
        if (now - lastPeriodic > 5000) {
            PeriodicMaintenance();
            lastPeriodic = now;
        }
    }
}

// ✅ Signaler événements au lieu de polling
void CNetwork::OnQueryHits(CQueryHit* pHits) {
    // ... ajouter job ...
    SetEvent(m_hJobReadyEvent);  // Signal instead of waiting for polling
}
```

**Files to Modify:**
- `Envy/Network.h` - Add Windows events (`HANDLE m_hJobReadyEvent`, etc.)
- `Envy/Network.cpp:785-875` - Refactor `OnRun()`
- `Envy/Network.cpp` - Create events in `PreRun()`
- `Envy/Network.cpp` - Signal events in `OnQueryHits()`, etc.

**Complexity:** Medium (M)
**Impact:** Medium-High - Reduces CPU usage from 5-10% to <1%

---

### 4. Frequent UI Updates (Update Storms)

**Problem:** UI updates too frequent causing excessive redraws.

**Affected Files:**
- `Envy/CtrlDownloads.cpp` - `Invalidate()` called for every downloaded chunk
- `Envy/WndSearchMonitor.cpp:345-418` - Real-time filtering of large lists
- `Envy/CtrlUploads.cpp` - Updates for every packet

**Exemple problématique:**
```cpp
// Envy/CtrlDownloads.cpp (exemple typique)
void CDownloadsCtrl::OnDownloadProgress(CDownload* pDownload) {
    // ❌ Invalidate() called for every chunk (multiple times per second)
    Invalidate();
    UpdateWindow();
}
```

**Refactoring recommandé:**
```cpp
// Envy/CtrlDownloads.cpp - Version avec batching
class CDownloadsCtrl {
private:
    DWORD m_tLastUpdate;  // Last UI update
    static const DWORD UPDATE_INTERVAL = 200;  // 200ms minimum between updates
    
public:
    void OnDownloadProgress(CDownload* pDownload) {
        DWORD now = GetTickCount();
        
        // ✅ Batch updates - only every 200ms
        if (now - m_tLastUpdate < UPDATE_INTERVAL) {
            // Mark as "dirty" but don't redraw now
            m_bNeedsUpdate = TRUE;
            return;
        }
        
        m_tLastUpdate = now;
        m_bNeedsUpdate = FALSE;
        
        // ✅ Redraw only if necessary
        if (IsWindowVisible()) {
            Invalidate();
        }
    }
    
    // ✅ Timer for batched updates
    void OnTimer(UINT_PTR nIDEvent) {
        if (nIDEvent == ID_TIMER_UPDATE && m_bNeedsUpdate) {
            m_bNeedsUpdate = FALSE;
            Invalidate();
        }
    }
};
```

**Files to Modify:**
- `Envy/CtrlDownloads.cpp` - Add update batching
- `Envy/CtrlDownloads.h` - Add members `m_tLastUpdate`, `m_bNeedsUpdate`
- `Envy/CtrlUploads.cpp` - Same refactoring
- `Envy/WndSearchMonitor.cpp` - Batching for filtering

**Complexity:** Low (S)
**Impact:** Medium - Reduces redraws by 90%+, improves UI smoothness

---

### 5. Inefficient Iteration on Large Lists

**Problem:** Using `POSITION` for iteration causes O(n²) in some cases.

**Affected Files:**
- `Envy/NeighboursWithRouting.cpp:108` - Manual iteration with `POSITION`
- `Envy/Downloads.cpp` - Linear search in large lists
- `Envy/Remote.cpp:801-877` - Iteration over search results

**Exemple problématique:**
```cpp
// Envy/NeighboursWithRouting.cpp (exemple typique)
for (POSITION pos = GetIterator(); pos; ) {
    CNeighbour* pNeighbour = GetNext(pos);
    // ❌ GetNext() can be O(n) if implementation is suboptimal
    ProcessNeighbour(pNeighbour);
}
```

**Refactoring recommandé:**
```cpp
// Envy/NeighboursWithRouting.cpp - Version optimisée
void CNeighboursWithRouting::ProcessAll() {
    // ✅ Create local snapshot (single iteration)
    std::vector<CNeighbour*> neighbours;
    {
        CQuickLock oLock(m_pSection);
        neighbours.reserve(GetCount());  // Pre-allocate
        
        for (POSITION pos = GetIterator(); pos; ) {
            neighbours.push_back(GetNext(pos));
        }
    }  // Lock released
    
    // ✅ Process without lock
    for (auto* pNeighbour : neighbours) {
        ProcessNeighbour(pNeighbour);  // No lock needed
    }
}
```

**Files to Modify:**
- `Envy/NeighboursWithRouting.cpp` - Refactor iterations
- `Envy/Downloads.cpp` - Optimize searches
- `Envy/Remote.cpp` - Snapshot for search results

**Complexity:** Low-Medium (S-M)
**Impact:** Medium - Improves performance on large lists (1000+ items)

---

## 📊 Plan de Mesure

### Outils Recommandés

1. **ETW (Event Tracing for Windows)**
   - Profiler les locks avec `lock_provider`
   - Mesurer les temps de réponse UI
   - Identifier les hot paths

2. **Windows Performance Recorder (WPR)**
   - Enregistrer sessions de freeze
   - Analyser avec Windows Performance Analyzer (WPA)

3. **Manual Timings**
   - Add `GetTickCount()` around critical sections
   - Log execution times

4. **Performance Counters**
   - Number of locks acquired/released
   - Average time under lock
   - UI update frequency

### Exemple de Code de Mesure

```cpp
// Envy/Network.cpp - Add instrumentation
void CNetwork::RunJobs() {
    DWORD tStart = GetTickCount();
    int nJobsProcessed = 0;
    
    // ... processing code ...
    
    DWORD tElapsed = GetTickCount() - tStart;
    if (tElapsed > 50) {  // Log si > 50ms
        theApp.Message(MSG_DEBUG, L"RunJobs took %dms, processed %d jobs", 
                      tElapsed, nJobsProcessed);
    }
}

// Envy/CtrlDownloads.cpp - Measure redraws
void CDownloadsCtrl::OnPaint() {
    static DWORD tLastPaint = 0;
    DWORD tNow = GetTickCount();
    DWORD tElapsed = tNow - tLastPaint;
    
    if (tElapsed < 16) {  // < 16ms = > 60 FPS (too frequent)
        theApp.Message(MSG_DEBUG, L"CtrlDownloads redraw too frequent: %dms", tElapsed);
    }
    
    tLastPaint = tNow;
    // ... paint code ...
}
```

---

## 📈 Target Metrics

| Metric | Before | Target | Measure |
|--------|--------|--------|---------|
| Average lock time | 50-100ms | <10ms | ETW |
| UI update frequency | 10-20/sec | 2-5/sec | Counter |
| CPU idle (network thread) | 5-10% | <1% | PerfMon |
| UI latency (p95) | 200-500ms | <100ms | WPR |
| Detected freezes | 5-10/min | 0 | Manual |

---

## 🔄 Refactorings Prioritaires

### Priorité 1 (Impact Élevé)
1. **Découpler UI/Network threads** - `Envy/Network.cpp:1371-1401`
2. **Réduire lock contention** - `Envy/Network.cpp:1225-1266`
3. **Batching UI updates** - `Envy/CtrlDownloads.cpp`

### Priority 2 (Medium Impact)
4. **Replace polling with events** - `Envy/Network.cpp:791-875`
5. **Optimize iterations** - `Envy/NeighboursWithRouting.cpp`

### Priority 3 (Low Impact)
6. **Cache search results** - `Envy/Remote.cpp`
7. **Lazy loading of lists** - `Envy/CtrlDownloads.cpp`

---

## ✅ Acceptance Criteria

- [ ] No freezes detected during 1 hour of intensive testing
- [ ] Network thread CPU idle < 1%
- [ ] UI latency p95 < 100ms
- [ ] UI updates < 5/sec average
- [ ] Average lock time < 10ms

---

**Next Steps:**
1. Implement P1 refactorings
2. Add measurement instrumentation
3. Validate improvements with WPR/ETW
4. Iterate on P2/P3 refactorings
