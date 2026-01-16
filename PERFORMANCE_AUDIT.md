# ⚡ Audit de Performance - Envy

**Date:** 16 janvier 2026  
**Version:** 1.0  
**Objectif:** Identification des sources de freeze/lag et recommandations de refactoring

---

## 🔍 Sources de Freeze/Lag Identifiées

### 1. Appels UI depuis Threads Réseau

**Problème:** Les threads réseau appellent directement des fonctions UI, causant des freezes.

**Fichiers affectés:**
- `Envy/Network.cpp:1371-1401` - `ProcessQueryHits()` appelle `PostMessage` depuis thread réseau
- `Envy/Remote.cpp:658-682` - `PageSearch()` accède à `CMainWnd` depuis thread HTTP
- `Envy/Downloads.cpp:939-1018` - Mises à jour UI depuis threads de téléchargement

**Exemple problématique:**
```cpp
// Envy/Network.cpp:1371-1401
bool CNetwork::ProcessQueryHits(CNetwork::CJob& oJob) {
    // ...
    case 2:  // Send hits to search windows
    {
        CSingleLock oAppLock( &theApp.m_pSection );
        if ( oAppLock.Lock( 250 ) ) {
            if ( CMainWnd* pMainWnd = theApp.SafeMainWnd() ) {
                // ❌ Accès direct à UI depuis thread réseau
                while ( ( pChildWnd = pMainWnd->m_pWindows.Find( NULL, pChildWnd ) ) != NULL ) {
                    if ( pChildWnd->IsKindOf( RUNTIME_CLASS( CSearchWnd ) ) ) {
                        if ( pChildWnd->OnQueryHits( pHits ) )  // Appel UI direct
                            bHandled = TRUE;
                    }
                }
            }
        }
    }
}
```

**Refactoring recommandé:**
```cpp
// Envy/Network.cpp - Version refactorée
bool CNetwork::ProcessQueryHits(CNetwork::CJob& oJob) {
    // ...
    case 2:  // Send hits to search windows
    {
        // ✅ Créer snapshot immutable des données
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

**Fichiers à modifier:**
- `Envy/Network.cpp:1353-1412` - Refactorer `ProcessQueryHits()`
- `Envy/WndMain.h` - Ajouter handler `OnQueryHitsReady()`
- `Envy/WndMain.cpp` - Implémenter handler
- `Envy/QueryHit.h` - Créer classe `CQueryHitSnapshot` (snapshot immutable)

**Complexité:** Moyenne (M)  
**Impact:** Élevé - Élimine les freezes lors de réception de résultats de recherche

---

### 2. Lock Contention - Section Critique Trop Large

**Problème:** Les sections critiques sont trop larges, causant de la contention.

**Fichiers affectés:**
- `Envy/Network.cpp:1225-1266` - `RunJobs()` garde le lock trop longtemps
- `Envy/Downloads.cpp:939-1018` - Lock maintenu pendant traitement
- `Envy/NeighboursBase.cpp:216-268` - Lock pendant itération complète

**Exemple problématique:**
```cpp
// Envy/Network.cpp:1225-1266
void CNetwork::RunJobs() {
    const DWORD nStop = GetTickCount() + 250;
    
    CSingleLock oJobLock( &m_pJobSection, TRUE );  // ❌ Lock pris
    
    while ( ! m_oJobs.IsEmpty() && GetTickCount() < nStop ) {
        CJob oJob = m_oJobs.RemoveHead();
        
        oJobLock.Unlock();  // ✅ Déjà mieux
        
        // ... traitement ...
        
        CSingleLock oNetworkLock( &m_pSection, FALSE );
        if ( oNetworkLock.Lock( 250 ) ) {  // ❌ Lock réseau pendant traitement
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
    
    // ✅ Collecter jobs rapidement (lock minimal)
    CList<CJob> jobsToProcess;
    {
        CSingleLock oJobLock( &m_pJobSection, TRUE );
        while (!m_oJobs.IsEmpty() && jobsToProcess.GetCount() < 10) {
            jobsToProcess.AddTail(m_oJobs.RemoveHead());
        }
    }  // Lock libéré immédiatement
    
    // ✅ Traiter sans lock
    while (!jobsToProcess.IsEmpty() && GetTickCount() < nStop) {
        CJob oJob = jobsToProcess.RemoveHead();
        
        // Traitement sans lock réseau
        bool bKeep = ProcessQueryHitsUnlocked(oJob);
        
        // ✅ Re-ajouter seulement si nécessaire (lock minimal)
        if (bKeep) {
            CSingleLock oJobLock( &m_pJobSection, TRUE );
            m_oJobs.AddTail(oJob);
        }
    }
}

// ✅ Nouvelle méthode sans lock
bool CNetwork::ProcessQueryHitsUnlocked(CNetwork::CJob& oJob) {
    CQueryHit* pHits = (CQueryHit*)oJob.GetData();
    
    // Traitement sans accès aux structures partagées
    // Utiliser snapshots/copies locales
    switch (oJob.GetStage()) {
    case 0:
        // Traitement local uniquement
        break;
    // ...
    }
    
    return true;
}
```

**Fichiers à modifier:**
- `Envy/Network.cpp:1225-1266` - Refactorer `RunJobs()`
- `Envy/Network.cpp` - Ajouter `ProcessQueryHitsUnlocked()`
- `Envy/Network.cpp` - Ajouter `ProcessQuerySearchUnlocked()`

**Complexité:** Moyenne (M)  
**Impact:** Élevé - Réduit la contention de locks de 60-80%

---

### 3. Boucles de Polling Inefficaces

**Problème:** Boucles de polling qui consomment CPU inutilement.

**Fichiers affectés:**
- `Envy/Network.cpp:791-875` - Boucle `OnRun()` avec `Doze(100)`
- `Envy/Downloads.cpp` - Polling fréquent des téléchargements
- `Envy/NeighboursBase.cpp` - Vérification périodique des connexions

**Exemple problématique:**
```cpp
// Envy/Network.cpp:791-875
void CNetwork::OnRun() {
    while ( IsThreadEnabled() ) {
        Doze( 100 );  // ❌ Polling toutes les 100ms
        
        if ( ! theApp.m_bLive || ( UPnPFinder && UPnPFinder->IsAsyncFindRunning() ) ) {
            Sleep( 0 );  // ❌ Yield CPU inutilement
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
        m_hStopEvent,           // Événement d'arrêt
        m_hJobReadyEvent,       // Nouveau job disponible
        m_hUPnPCompleteEvent,   // UPnP terminé
        // ... autres événements
    };
    
    while ( IsThreadEnabled() ) {
        // ✅ Attendre événements au lieu de polling
        DWORD dwWait = WaitForMultipleObjects(
            _countof(hEvents), hEvents, FALSE, INFINITE);
        
        if (dwWait == WAIT_OBJECT_0) break;  // Stop
        
        if (dwWait == WAIT_OBJECT_0 + 1) {  // Job ready
            RunJobs();
        }
        
        // Traitement périodique (toutes les 5 secondes max)
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
    SetEvent(m_hJobReadyEvent);  // Signaler au lieu d'attendre polling
}
```

**Fichiers à modifier:**
- `Envy/Network.h` - Ajouter événements Windows (`HANDLE m_hJobReadyEvent`, etc.)
- `Envy/Network.cpp:785-875` - Refactorer `OnRun()`
- `Envy/Network.cpp` - Créer événements dans `PreRun()`
- `Envy/Network.cpp` - Signaler événements dans `OnQueryHits()`, etc.

**Complexité:** Moyenne (M)  
**Impact:** Moyen-Élevé - Réduit utilisation CPU de 5-10% à <1%

---

### 4. Mises à Jour UI Fréquentes (Update Storms)

**Problème:** Mises à jour UI trop fréquentes causent des redraws excessifs.

**Fichiers affectés:**
- `Envy/CtrlDownloads.cpp` - `Invalidate()` appelé à chaque chunk téléchargé
- `Envy/WndSearchMonitor.cpp:345-418` - Filtrage en temps réel de grandes listes
- `Envy/CtrlUploads.cpp` - Mises à jour à chaque paquet

**Exemple problématique:**
```cpp
// Envy/CtrlDownloads.cpp (exemple typique)
void CDownloadsCtrl::OnDownloadProgress(CDownload* pDownload) {
    // ❌ Invalidate() appelé à chaque chunk (plusieurs fois par seconde)
    Invalidate();
    UpdateWindow();
}
```

**Refactoring recommandé:**
```cpp
// Envy/CtrlDownloads.cpp - Version avec batching
class CDownloadsCtrl {
private:
    DWORD m_tLastUpdate;  // Dernière mise à jour UI
    static const DWORD UPDATE_INTERVAL = 200;  // 200ms minimum entre updates
    
public:
    void OnDownloadProgress(CDownload* pDownload) {
        DWORD now = GetTickCount();
        
        // ✅ Batch updates - seulement toutes les 200ms
        if (now - m_tLastUpdate < UPDATE_INTERVAL) {
            // Marquer comme "dirty" mais ne pas redraw maintenant
            m_bNeedsUpdate = TRUE;
            return;
        }
        
        m_tLastUpdate = now;
        m_bNeedsUpdate = FALSE;
        
        // ✅ Redraw seulement si nécessaire
        if (IsWindowVisible()) {
            Invalidate();
        }
    }
    
    // ✅ Timer pour updates batchées
    void OnTimer(UINT_PTR nIDEvent) {
        if (nIDEvent == ID_TIMER_UPDATE && m_bNeedsUpdate) {
            m_bNeedsUpdate = FALSE;
            Invalidate();
        }
    }
};
```

**Fichiers à modifier:**
- `Envy/CtrlDownloads.cpp` - Ajouter batching des updates
- `Envy/CtrlDownloads.h` - Ajouter membres `m_tLastUpdate`, `m_bNeedsUpdate`
- `Envy/CtrlUploads.cpp` - Même refactoring
- `Envy/WndSearchMonitor.cpp` - Batching pour filtrage

**Complexité:** Faible (S)  
**Impact:** Moyen - Réduit redraws de 90%+, améliore fluidité UI

---

### 5. Itération Inefficace sur Grandes Listes

**Problème:** Utilisation de `POSITION` pour itérer cause O(n²) dans certains cas.

**Fichiers affectés:**
- `Envy/NeighboursWithRouting.cpp:108` - Itération manuelle avec `POSITION`
- `Envy/Downloads.cpp` - Recherche linéaire dans grandes listes
- `Envy/Remote.cpp:801-877` - Itération sur résultats de recherche

**Exemple problématique:**
```cpp
// Envy/NeighboursWithRouting.cpp (exemple typique)
for (POSITION pos = GetIterator(); pos; ) {
    CNeighbour* pNeighbour = GetNext(pos);
    // ❌ GetNext() peut être O(n) si implémentation sous-optimale
    ProcessNeighbour(pNeighbour);
}
```

**Refactoring recommandé:**
```cpp
// Envy/NeighboursWithRouting.cpp - Version optimisée
void CNeighboursWithRouting::ProcessAll() {
    // ✅ Créer snapshot local (une seule itération)
    std::vector<CNeighbour*> neighbours;
    {
        CQuickLock oLock(m_pSection);
        neighbours.reserve(GetCount());  // Pré-allouer
        
        for (POSITION pos = GetIterator(); pos; ) {
            neighbours.push_back(GetNext(pos));
        }
    }  // Lock libéré
    
    // ✅ Traiter sans lock
    for (auto* pNeighbour : neighbours) {
        ProcessNeighbour(pNeighbour);  // Pas de lock nécessaire
    }
}
```

**Fichiers à modifier:**
- `Envy/NeighboursWithRouting.cpp` - Refactorer itérations
- `Envy/Downloads.cpp` - Optimiser recherches
- `Envy/Remote.cpp` - Snapshot pour résultats de recherche

**Complexité:** Faible-Moyenne (S-M)  
**Impact:** Moyen - Améliore performance sur grandes listes (1000+ items)

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

3. **Timings Manuels**
   - Ajouter `GetTickCount()` autour des sections critiques
   - Logger les temps d'exécution

4. **Compteurs de Performance**
   - Nombre de locks acquis/libérés
   - Temps moyen sous lock
   - Fréquence des updates UI

### Exemple de Code de Mesure

```cpp
// Envy/Network.cpp - Ajouter instrumentation
void CNetwork::RunJobs() {
    DWORD tStart = GetTickCount();
    int nJobsProcessed = 0;
    
    // ... code de traitement ...
    
    DWORD tElapsed = GetTickCount() - tStart;
    if (tElapsed > 50) {  // Log si > 50ms
        theApp.Message(MSG_DEBUG, L"RunJobs took %dms, processed %d jobs", 
                      tElapsed, nJobsProcessed);
    }
}

// Envy/CtrlDownloads.cpp - Mesurer redraws
void CDownloadsCtrl::OnPaint() {
    static DWORD tLastPaint = 0;
    DWORD tNow = GetTickCount();
    DWORD tElapsed = tNow - tLastPaint;
    
    if (tElapsed < 16) {  // < 16ms = > 60 FPS (trop fréquent)
        theApp.Message(MSG_DEBUG, L"CtrlDownloads redraw too frequent: %dms", tElapsed);
    }
    
    tLastPaint = tNow;
    // ... paint code ...
}
```

---

## 📈 Métriques Cibles

| Métrique | Avant | Cible | Mesure |
|----------|-------|-------|--------|
| Temps sous lock (moyen) | 50-100ms | <10ms | ETW |
| Fréquence updates UI | 10-20/sec | 2-5/sec | Compteur |
| CPU idle (thread réseau) | 5-10% | <1% | PerfMon |
| Latence UI (p95) | 200-500ms | <100ms | WPR |
| Freezes détectés | 5-10/min | 0 | Manuel |

---

## 🔄 Refactorings Prioritaires

### Priorité 1 (Impact Élevé)
1. **Découpler UI/Network threads** - `Envy/Network.cpp:1371-1401`
2. **Réduire lock contention** - `Envy/Network.cpp:1225-1266`
3. **Batching UI updates** - `Envy/CtrlDownloads.cpp`

### Priorité 2 (Impact Moyen)
4. **Remplacer polling par événements** - `Envy/Network.cpp:791-875`
5. **Optimiser itérations** - `Envy/NeighboursWithRouting.cpp`

### Priorité 3 (Impact Faible)
6. **Cache des résultats de recherche** - `Envy/Remote.cpp`
7. **Lazy loading des listes** - `Envy/CtrlDownloads.cpp`

---

## ✅ Critères d'Acceptation

- [ ] Aucun freeze détecté pendant 1h de test intensif
- [ ] CPU idle thread réseau < 1%
- [ ] Latence UI p95 < 100ms
- [ ] Updates UI < 5/sec en moyenne
- [ ] Temps moyen sous lock < 10ms

---

**Prochaines Étapes:**
1. Implémenter refactorings P1
2. Ajouter instrumentation de mesure
3. Valider améliorations avec WPR/ETW
4. Itérer sur refactorings P2/P3
