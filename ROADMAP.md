# 🗺️ Roadmap de Modernisation - Envy

**Date:** 16 janvier 2026  
**Version:** 1.0  
**Objectif:** Backlog priorisé (P0/P1/P2) pour modernisation, sécurité et performance

---

## 📊 Vue d'Ensemble

| Priorité | Items | Complexité Moyenne | Durée Estimée |
|----------|-------|-------------------|---------------|
| **P0** | 3 | M | 2-3 semaines |
| **P1** | 8 | M | 6-8 semaines |
| **P2** | 6 | M-L | 8-12 semaines |

**Total estimé:** 16-23 semaines (4-6 mois)

---

## 🚨 P0: Corrections Critiques de Sécurité

### P0.1: Remote HTTP - Binding Localhost par Défaut

**Owner:** Core/Network  
**Complexité:** Moyenne (M)  
**Durée:** 3-5 jours

**Description:**
L'interface Remote HTTP écoute sur toutes les interfaces (`0.0.0.0`) par défaut, exposant l'application à des attaques réseau.

**Fichiers touchés:**
- `Envy/Network.cpp` - Modifier binding par défaut
- `Envy/PageSettingsRemote.cpp` - Ajouter option binding
- `Envy/Remote.cpp` - Ajouter rate limiting
- `Envy/Remote.cpp` - Ajouter protection CSRF

**Acceptance Criteria:**
- [ ] Interface Remote bind sur `127.0.0.1` par défaut
- [ ] Option pour binding externe (désactivée par défaut)
- [ ] Rate limiting: 10 requêtes/minute par IP
- [ ] Protection CSRF avec tokens
- [ ] Tests: Interface non accessible depuis réseau externe par défaut

**Références:**
- `SECURITY_AUDIT.md` - Risque #1
- `Envy/UploadTransferHTTP.cpp:456-467`
- `Envy/Network.cpp:135`

---

### P0.2: Remplacer RNG Faible (Kademlia/ED2K)

**Owner:** Network/Crypto  
**Complexité:** Faible (S)  
**Durée:** 2-3 jours

**Description:**
Remplacer `rand()`/`srand()` par `BCryptGenRandom` (Windows CNG) pour génération d'IDs Kademlia et SecureID ED2K.

**Fichiers touchés:**
- `Envy/Kademlia.cpp:234-247` - `GenerateOwnKadId()`
- `Envy/Kademlia.cpp:338-341` - Génération ID cible
- `Envy/EDClient.cpp:69` - SecureID challenge
- `Envy/KademliaPlatform.cpp:95-118` - `kad_random_bytes()`

**Acceptance Criteria:**
- [ ] `BCryptGenRandom` utilisé partout (pas de fallback `rand()`)
- [ ] IDs Kademlia non prévisibles (test entropie)
- [ ] SecureID ED2K utilise RNG cryptographique
- [ ] Tests: Vérifier entropie des IDs générés

**Références:**
- `SECURITY_AUDIT.md` - Risque #2
- `Envy/Kademlia.cpp:242-244`

---

### P0.3: Remplacer Hash Non Cryptographique (Kademlia)

**Owner:** Network/Crypto  
**Complexité:** Faible (S)  
**Durée:** 1-2 jours

**Description:**
Remplacer djb2 hash par SHA-1 dans `kad_hash()` pour compatibilité eMule et sécurité.

**Fichiers touchés:**
- `Envy/KademliaPlatform.cpp:54-92` - `kad_hash()`

**Acceptance Criteria:**
- [ ] SHA-1 utilisé au lieu de djb2
- [ ] Compatibilité avec eMule vérifiée
- [ ] Tests: Hashs résistants aux collisions

**Références:**
- `SECURITY_AUDIT.md` - Risque #3
- `Envy/KademliaPlatform.cpp:77-80`

---

## ⚠️ P1: Performance et Stabilité

### P1.1: Découpler UI/Network Threads

**Owner:** Core/UI  
**Complexité:** Moyenne (M)  
**Durée:** 1-2 semaines

**Description:**
Éliminer les appels UI directs depuis threads réseau en utilisant message passing et snapshots immutables.

**Fichiers touchés:**
- `Envy/Network.cpp:1371-1401` - `ProcessQueryHits()`
- `Envy/WndMain.h` - Ajouter handlers UI
- `Envy/WndMain.cpp` - Implémenter handlers
- `Envy/QueryHit.h` - Créer `CQueryHitSnapshot`

**Acceptance Criteria:**
- [ ] Aucun appel UI direct depuis threads réseau
- [ ] `PostMessage` utilisé pour communication asynchrone
- [ ] Snapshots immutables pour données partagées
- [ ] Tests: Aucun freeze pendant réception résultats recherche

**Références:**
- `PERFORMANCE_AUDIT.md` - Section #1
- `Envy/Network.cpp:1374-1396`

---

### P1.2: Réduire Lock Contention

**Owner:** Core  
**Complexité:** Moyenne (M)  
**Durée:** 1 semaine

**Description:**
Réduire le temps sous lock en collectant les jobs rapidement et traitant sans lock.

**Fichiers touchés:**
- `Envy/Network.cpp:1225-1266` - `RunJobs()`
- `Envy/Network.cpp` - Ajouter `ProcessQueryHitsUnlocked()`
- `Envy/Network.cpp` - Ajouter `ProcessQuerySearchUnlocked()`

**Acceptance Criteria:**
- [ ] Temps moyen sous lock < 10ms (mesuré avec ETW)
- [ ] Jobs collectés rapidement (lock minimal)
- [ ] Traitement sans lock réseau
- [ ] Tests: Contention réduite de 60-80%

**Références:**
- `PERFORMANCE_AUDIT.md` - Section #2
- `Envy/Network.cpp:1230-1265`

---

### P1.3: Batching UI Updates

**Owner:** UI  
**Complexité:** Faible (S)  
**Durée:** 3-5 jours

**Description:**
Réduire la fréquence des redraws UI en batchant les updates (minimum 200ms entre updates).

**Fichiers touchés:**
- `Envy/CtrlDownloads.cpp` - Ajouter batching
- `Envy/CtrlDownloads.h` - Ajouter membres `m_tLastUpdate`, `m_bNeedsUpdate`
- `Envy/CtrlUploads.cpp` - Même refactoring
- `Envy/WndSearchMonitor.cpp` - Batching pour filtrage

**Acceptance Criteria:**
- [ ] Updates UI < 5/sec en moyenne
- [ ] Timer pour updates batchées
- [ ] Tests: Redraws réduits de 90%+

**Références:**
- `PERFORMANCE_AUDIT.md` - Section #4
- `Envy/CtrlDownloads.cpp` (exemple typique)

---

### P1.4: Mise à Jour Dépendances Critiques

**Owner:** Core/Dependencies  
**Complexité:** Faible-Moyenne (S-M)  
**Durée:** 1-2 semaines

**Description:**
Mettre à jour zlib, MiniUPnP, SQLite vers versions récentes pour sécurité.

**Fichiers touchés:**
- `Services/zlib/` - Mettre à jour vers 1.3.1
- `Services/MiniUPnP/` - Mettre à jour vers 2.2.6
- `Services/SQLite/` - Vérifier et mettre à jour vers 3.45.0

**Acceptance Criteria:**
- [ ] zlib 1.3.1 intégré et testé
- [ ] MiniUPnP 2.2.6 intégré et testé
- [ ] SQLite 3.45.0 intégré et testé
- [ ] Tests de régression complets

**Références:**
- `DEPENDENCIES_AUDIT.md` - Sections zlib, MiniUPnP, SQLite

---

### P1.5: Parser Hardening (Validation Stricte)

**Owner:** Network  
**Complexité:** Moyenne (M)  
**Durée:** 1-2 semaines

**Description:**
Ajouter validation stricte dans tous les parsers de paquets réseau pour prévenir buffer overflows.

**Fichiers touchés:**
- `Envy/G2Neighbour.cpp:282-358` - Parser G2
- `Envy/G1Neighbour.cpp:278-320` - Parser Gnutella
- `Envy/EDPacket.cpp` - Parser ED2K
- `Envy/Datagrams.cpp:737-880` - Détection UDP

**Acceptance Criteria:**
- [ ] Validation de toutes les longueurs de paquet
- [ ] Limites maximales strictes
- [ ] Protection contre débordements arithmétiques
- [ ] Fuzzing: Aucun crash sur paquets malformés

**Références:**
- `SECURITY_AUDIT.md` - Risque #4
- `Envy/G2Neighbour.cpp:298-303`

---

### P1.6: UnRAR → 7-Zip ou UnRAR 6.2.12

**Owner:** Core/Dependencies  
**Complexité:** Moyenne-Élevée (M-L)  
**Durée:** 1-2 semaines

**Description:**
Migrer vers 7-Zip (recommandé) ou mettre à jour UnRAR vers 6.2.12, avec validation path traversal.

**Fichiers touchés:**
- `Services/UnRAR/` - Remplacer ou mettre à jour
- `Plugins/RARBuilder/RARBuilder.cpp` - Adapter interface
- `Services/UnRAR/extract.cpp` - Ajouter validation path traversal

**Acceptance Criteria:**
- [ ] 7-Zip intégré OU UnRAR 6.2.12
- [ ] Validation path traversal (rejeter `../`)
- [ ] Tests: Extraction sécurisée
- [ ] Vérifier licence si UnRAR

**Références:**
- `DEPENDENCIES_AUDIT.md` - Section UnRAR
- `SECURITY_AUDIT.md` - Risque #5

---

### P1.7: Remplacer Polling par Événements

**Owner:** Core  
**Complexité:** Moyenne (M)  
**Durée:** 1 semaine

**Description:**
Remplacer boucles de polling (`Doze(100)`) par événements Windows pour réduire CPU.

**Fichiers touchés:**
- `Envy/Network.h` - Ajouter événements (`HANDLE m_hJobReadyEvent`, etc.)
- `Envy/Network.cpp:791-875` - Refactorer `OnRun()`
- `Envy/Network.cpp` - Créer événements dans `PreRun()`
- `Envy/Network.cpp` - Signaler événements dans `OnQueryHits()`, etc.

**Acceptance Criteria:**
- [ ] CPU idle thread réseau < 1% (mesuré)
- [ ] Événements utilisés au lieu de polling
- [ ] Tests: Performance CPU améliorée

**Références:**
- `PERFORMANCE_AUDIT.md` - Section #3
- `Envy/Network.cpp:793`

---

### P1.8: Optimiser Itérations sur Grandes Listes

**Owner:** Core  
**Complexité:** Faible-Moyenne (S-M)  
**Durée:** 3-5 jours

**Description:**
Créer snapshots locaux pour éviter itérations O(n²) et réduire temps sous lock.

**Fichiers touchés:**
- `Envy/NeighboursWithRouting.cpp` - Refactorer itérations
- `Envy/Downloads.cpp` - Optimiser recherches
- `Envy/Remote.cpp:801-877` - Snapshot pour résultats recherche

**Acceptance Criteria:**
- [ ] Snapshots locaux créés (lock minimal)
- [ ] Traitement sans lock
- [ ] Tests: Performance améliorée sur listes 1000+ items

**Références:**
- `PERFORMANCE_AUDIT.md` - Section #5
- `Envy/NeighboursWithRouting.cpp:108`

---

## 📋 P2: Modernisation Long Terme

### P2.1: Compléter Implémentation ED2K/Kademlia

**Owner:** Network/ED2K  
**Complexité:** Élevée (L)  
**Durée:** 4-6 semaines

**Description:**
Implémenter fonctionnalités manquantes ED2K/Kademlia pour parité avec eMule.

**Fichiers touchés:**
- Voir `ED2K_KAD_GAP_ANALYSIS.md` pour détails complets
- `Envy/Kademlia.cpp` - Implémenter messages manquants
- `Envy/EDClient.cpp` - Implémenter fonctionnalités avancées

**Acceptance Criteria:**
- [ ] Tous les messages Kademlia implémentés
- [ ] Compatibilité eMule vérifiée
- [ ] Tests: Interopérabilité avec eMule

**Références:**
- `ED2K_KAD_GAP_ANALYSIS.md` - Analyse complète

---

### P2.2: Authentification Remote - PBKDF2

**Owner:** Core/Security  
**Complexité:** Moyenne (M)  
**Durée:** 3-5 jours

**Description:**
Remplacer SHA-1 par PBKDF2 avec SHA-256 pour hashage de mots de passe Remote.

**Fichiers touchés:**
- `Envy/Remote.cpp:598-606` - `PageLogin()`
- `Envy/PageSettingsRemote.cpp:104-110` - Hash nouveau mot de passe

**Acceptance Criteria:**
- [ ] PBKDF2 avec 100,000 itérations
- [ ] Salt unique par mot de passe
- [ ] Migration automatique SHA-1 → PBKDF2
- [ ] Tests: Résistance aux attaques brute force

**Références:**
- `SECURITY_AUDIT.md` - Risque #7
- `Envy/Remote.cpp:598-606`

---

### P2.3: GeoIP → libmaxminddb (GeoIP2)

**Owner:** Core/Dependencies  
**Complexité:** Moyenne (M)  
**Durée:** 1 semaine

**Description:**
Migrer de GeoIP Legacy vers libmaxminddb (GeoIP2) avec base de données GeoLite2.

**Fichiers touchés:**
- `Envy/Envy.cpp:2193-2237` - `LoadCountry()`/`FreeCountry()`
- `Envy/Envy.h` - Mettre à jour types
- `Services/GeoIP/` - Remplacer par libmaxminddb

**Acceptance Criteria:**
- [ ] libmaxminddb intégré
- [ ] Format MMDB utilisé
- [ ] Base GeoLite2 téléchargée automatiquement
- [ ] Tests: Géolocalisation fonctionnelle

**Références:**
- `DEPENDENCIES_AUDIT.md` - Section GeoIP

---

### P2.4: Fuzzing Infrastructure

**Owner:** QA/Security  
**Complexité:** Moyenne (M)  
**Durée:** 1-2 semaines

**Description:**
Mettre en place infrastructure de fuzzing pour parsers réseau avec AFL/libFuzzer.

**Fichiers touchés:**
- Créer `tests/fuzzing/` - Harnesses de fuzzing
- `Envy/*Packet.cpp` - Préparer pour fuzzing (sanitizers)

**Acceptance Criteria:**
- [ ] Fuzzing configuré pour parsers principaux
- [ ] Corpus de tests initial
- [ ] CI/CD intégré
- [ ] Tests: Aucun crash trouvé

**Références:**
- `SECURITY_AUDIT.md` - Validation #4

---

### P2.5: Architecture Cleanup - Découplage

**Owner:** Core/Architecture  
**Complexité:** Élevée (L)  
**Durée:** 6-8 semaines

**Description:**
Refactorer architecture pour meilleur découplage UI/Network/Storage.

**Fichiers touchés:**
- Multiple fichiers - Refactoring progressif
- Créer couches d'abstraction

**Acceptance Criteria:**
- [ ] Couches bien définies (UI/Network/Storage)
- [ ] Interfaces claires entre couches
- [ ] Tests: Pas de régression fonctionnelle

**Références:**
- `PERFORMANCE_AUDIT.md` - Refactorings recommandés

---

### P2.6: Build System Modernization

**Owner:** Build/Infrastructure  
**Complexité:** Moyenne (M)  
**Durée:** 2-3 semaines

**Description:**
Moderniser système de build (CMake, vcpkg, etc.) pour meilleure maintenabilité.

**Fichiers touchés:**
- Créer `CMakeLists.txt`
- Migrer depuis `.vcxproj`

**Acceptance Criteria:**
- [ ] CMake fonctionnel
- [ ] vcpkg pour dépendances
- [ ] CI/CD avec builds automatiques
- [ ] Tests: Builds réussis sur Windows/Linux (Wine)

**Références:**
- Documentation build system

---

## 📈 Métriques de Succès

### Sécurité
- [ ] 0 vulnérabilités critiques (P0) non corrigées
- [ ] Tous les parsers fuzzés sans crash
- [ ] Remote HTTP sécurisé par défaut

### Performance
- [ ] 0 freezes détectés pendant 1h test intensif
- [ ] CPU idle thread réseau < 1%
- [ ] Latence UI p95 < 100ms
- [ ] Updates UI < 5/sec

### Qualité
- [ ] Toutes dépendances P1 mises à jour
- [ ] Tests de régression complets
- [ ] Documentation à jour

---

## 🔄 Stratégie de Rollout

### Phase 1: Sécurité (Semaines 1-3)
- P0.1, P0.2, P0.3
- Tests de sécurité intensifs
- Release candidate

### Phase 2: Performance (Semaines 4-8)
- P1.1, P1.2, P1.3, P1.7, P1.8
- Mesures de performance
- Validation améliorations

### Phase 3: Dépendances (Semaines 9-11)
- P1.4, P1.6
- Tests de régression
- Validation compatibilité

### Phase 4: Hardening (Semaines 12-14)
- P1.5
- Fuzzing
- Tests de pénétration

### Phase 5: Modernisation (Semaines 15+)
- P2.1-P2.6
- Itération continue

---

## 📝 Notes

- **Complexité:** S=Simple (1-3 jours), M=Moyen (1-2 semaines), L=Large (2+ semaines)
- **Owner:** Core, Network, UI, Dependencies, QA, Build
- **Dépendances:** Certains items dépendent d'autres (ex: P1.5 dépend de P1.1)

---

**Prochaines Étapes:**
1. Valider roadmap avec équipe
2. Commencer P0 immédiatement
3. Planifier sprints 2 semaines
4. Suivre métriques de succès
