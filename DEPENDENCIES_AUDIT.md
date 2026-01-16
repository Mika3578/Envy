# 📦 Audit des Dépendances - Envy

**Date:** 16 janvier 2026  
**Version:** 1.0  
**Objectif:** Inventaire des bibliothèques vendues, versions, licences et plan de mise à jour

---

## 📋 Bibliothèques Vendues (Services/)

### 1. UnRAR

**Chemin:** `Services/UnRAR/`  
**Version actuelle:** 5.3.8 (Novembre 2015)  
**Version upstream:** 6.2.12 (Décembre 2023)  
**Licence:** Freeware (voir `Services/UnRAR/License.txt`)

**Utilisation:**
- `Plugins/RARBuilder/RARBuilder.cpp` - Extraction d'archives RAR
- `Plugins/RARBuilder/Unrar.h` - Interface DLL

**Problèmes identifiés:**
1. **Version obsolète:** 8+ ans de retard, vulnérabilités de sécurité non corrigées
2. **Licence:** Freeware uniquement - usage commercial nécessite licence séparée
3. **Path traversal:** Pas de validation des chemins extraits (voir `SECURITY_AUDIT.md`)

**Risques:**
- **Sécurité:** Vulnérabilités CVE non corrigées
- **Légal:** Usage commercial peut nécessiter licence WinRAR
- **Compatibilité:** Formats RAR récents non supportés

**Plan de mise à jour:**
1. **Option A (Recommandée):** Migrer vers 7-Zip (LGPL, maintenu activement)
   - Avantages: Licence libre, maintenu, plus sécurisé
   - Inconvénients: Refactoring nécessaire
   - Complexité: Moyenne (M)

2. **Option B:** Mettre à jour vers UnRAR 6.2.12
   - Avantages: Compatibilité maximale
   - Inconvénients: Vérifier licence pour usage commercial
   - Complexité: Faible (S)

**Fichiers à modifier:**
- `Plugins/RARBuilder/RARBuilder.cpp` - Adapter interface
- `Plugins/RARBuilder/Unrar.h` - Mettre à jour signatures
- `Services/UnRAR/` - Remplacer par nouvelle version ou 7-Zip

**Priorité:** P1 (Sécurité + Compatibilité)

---

### 2. MiniUPnP

**Chemin:** `Services/MiniUPnP/`  
**Version actuelle:** 2.0 (Avril 2016)  
**Version upstream:** 2.2.6 (2023)  
**Licence:** BSD-3-Clause (voir `Services/MiniUPnP/License.txt`)

**Utilisation:**
- `Envy/UPnPFinder.cpp:709-743` - Port forwarding
- `Envy/UPnPNAT.cpp:127-188` - Mapping moderne
- `Envy/MiniUPnP.cpp` - Wrapper

**Problèmes identifiés:**
1. **Version obsolète:** 7+ ans de retard
2. **Sécurité:** Vulnérabilités de buffer overflow corrigées dans versions récentes
3. **Compatibilité:** Certains routeurs modernes non supportés

**Risques:**
- **Sécurité:** Buffer overflows potentiels
- **Fonctionnalité:** Incompatibilité avec routeurs récents

**Plan de mise à jour:**
1. Mettre à jour vers MiniUPnP 2.2.6
   - Complexité: Faible (S)
   - Impact: Sécurité + Compatibilité

**Fichiers à modifier:**
- `Services/MiniUPnP/` - Remplacer par version 2.2.6
- `Envy/MiniUPnP.cpp` - Vérifier compatibilité API

**Priorité:** P1 (Sécurité)

---

### 3. zlib

**Chemin:** `Services/zlib/`  
**Version actuelle:** 1.2.10 (Janvier 2017)  
**Version upstream:** 1.3.1 (Août 2023)  
**Licence:** zlib License (très permissive)

**Utilisation:**
- Compression/décompression générale
- Formats de fichiers (ZIP, etc.)

**Problèmes identifiés:**
1. **Version obsolète:** 6+ ans de retard
2. **Sécurité:** Vulnérabilités corrigées dans 1.2.11+ (CVE-2022-37434, etc.)

**Risques:**
- **Sécurité:** Décompression malveillante (zip bombs, etc.)

**Plan de mise à jour:**
1. Mettre à jour vers zlib 1.3.1
   - Complexité: Faible (S)
   - Impact: Sécurité

**Fichiers à modifier:**
- `Services/zlib/` - Remplacer par version 1.3.1
- Vérifier compatibilité binaire (ABI stable)

**Priorité:** P1 (Sécurité)

---

### 4. GeoIP (Legacy)

**Chemin:** `Services/GeoIP/`  
**Version actuelle:** Legacy (version non spécifiée, probablement 1.x)  
**Version upstream:** **DÉPRÉCIÉ** - MaxMind GeoIP2 recommandé  
**Licence:** LGPL/GPL (selon version)

**Utilisation:**
- `Envy/Envy.cpp:2193-2237` - Géolocalisation IP
- Chargement dynamique via `GeoIP.dll`

**Problèmes identifiés:**
1. **Déprécié:** MaxMind a arrêté le support de GeoIP Legacy
2. **Base de données:** Format `.dat` obsolète, plus de mises à jour
3. **Sécurité:** Pas de mises à jour de sécurité

**Risques:**
- **Fonctionnalité:** Données de géolocalisation obsolètes
- **Sécurité:** Pas de patches de sécurité

**Plan de mise à jour:**
1. **Option A (Recommandée):** Migrer vers libmaxminddb (GeoIP2)
   - Format MMDB moderne
   - Base de données GeoLite2 gratuite
   - Complexité: Moyenne (M)

2. **Option B:** Utiliser service externe (ipapi.co, ip-api.com)
   - Avantages: Pas de maintenance
   - Inconvénients: Dépendance réseau, limites de rate

**Fichiers à modifier:**
- `Envy/Envy.cpp:2193-2237` - Remplacer `LoadCountry()`/`FreeCountry()`
- `Envy/Envy.h` - Mettre à jour types/pointeurs
- `Services/GeoIP/` - Supprimer ou remplacer

**Priorité:** P2 (Fonctionnalité)

---

### 5. LibUTP (uTorrent Transport Protocol)

**Chemin:** `Services/LibUTP/`  
**Version actuelle:** Juin 2014 (version non spécifiée)  
**Version upstream:** **INACTIF** - Dernier commit 2014  
**Licence:** MIT (voir `Services/LibUTP/LICENSE`)

**Utilisation:**
- Protocole de transport BitTorrent (UTP)
- Alternative à TCP pour BitTorrent

**Problèmes identifiés:**
1. **Abandonné:** Projet inactif depuis 2014
2. **Sécurité:** Pas de mises à jour de sécurité
3. **Compatibilité:** Peut ne pas fonctionner avec clients BitTorrent modernes

**Risques:**
- **Sécurité:** Vulnérabilités non corrigées
- **Fonctionnalité:** Incompatibilité avec clients modernes

**Plan de mise à jour:**
1. **Option A:** Maintenir tel quel (si fonctionne)
   - Documenter risques
   - Désactiver par défaut si problèmes

2. **Option B:** Migrer vers libutp fork maintenu (si disponible)
   - Rechercher forks actifs sur GitHub

3. **Option C:** Supprimer support UTP
   - Utiliser TCP uniquement
   - Complexité: Faible (S)

**Fichiers à modifier:**
- `Services/LibUTP/` - Évaluer nécessité
- `Envy/BTClient.cpp` - Vérifier utilisation

**Priorité:** P2 (Sécurité si vulnérabilités trouvées)

---

### 6. Bzlib (bzip2)

**Chemin:** `Services/Bzlib/`  
**Version actuelle:** Non spécifiée (probablement 1.0.6)  
**Version upstream:** 1.0.8 (Juillet 2019)  
**Licence:** BSD-style (voir `Services/Bzlib/License.txt`)

**Utilisation:**
- Compression bzip2

**Problèmes identifiés:**
1. **Version potentiellement obsolète:** Vérifier version exacte
2. **Sécurité:** Vérifier CVE récentes

**Plan de mise à jour:**
1. Vérifier version actuelle
2. Mettre à jour vers 1.0.8 si nécessaire
   - Complexité: Faible (S)

**Priorité:** P2 (Maintenance)

---

### 7. BugTrap

**Chemin:** `Services/BugTrap/`  
**Version actuelle:** Non spécifiée  
**Version upstream:** **INACTIF** - Dernière version 3.x  
**Licence:** BSD-style

**Utilisation:**
- Crash reporting
- Diagnostics

**Problèmes identifiés:**
1. **Abandonné:** Projet inactif
2. **Compatibilité:** Peut ne pas fonctionner avec Windows 11/VS 2022+

**Plan de mise à jour:**
1. **Option A:** Maintenir tel quel (si fonctionne)
2. **Option B:** Migrer vers Crashpad (Google) ou Breakpad
   - Complexité: Élevée (L)
   - Avantages: Maintenu activement

**Priorité:** P2 (Maintenance)

---

### 8. SQLite

**Chemin:** `Services/SQLite/`  
**Version actuelle:** Non spécifiée (vérifier `sqlite3.h`)  
**Version upstream:** 3.45.0 (Décembre 2024)  
**Licence:** Public Domain

**Utilisation:**
- Base de données locale
- Stockage de métadonnées

**Problèmes identifiés:**
1. Vérifier version exacte
2. Mettre à jour si < 3.40.0 (sécurité)

**Plan de mise à jour:**
1. Vérifier version actuelle
2. Mettre à jour vers 3.45.0 si nécessaire
   - Complexité: Faible (S)
   - ABI stable, mise à jour simple

**Priorité:** P1 (Sécurité si version ancienne)

---

## 📊 Tableau Récapitulatif

| Bibliothèque | Version Actuelle | Version Upstream | Priorité | Complexité | Risque |
|--------------|------------------|------------------|----------|------------|--------|
| UnRAR | 5.3.8 (2015) | 6.2.12 (2023) | P1 | M | Sécurité + Licence |
| MiniUPnP | 2.0 (2016) | 2.2.6 (2023) | P1 | S | Sécurité |
| zlib | 1.2.10 (2017) | 1.3.1 (2023) | P1 | S | Sécurité |
| GeoIP | Legacy | Déprécié | P2 | M | Fonctionnalité |
| LibUTP | 2014 | Inactif | P2 | - | Sécurité |
| Bzlib | ? | 1.0.8 (2019) | P2 | S | Maintenance |
| BugTrap | ? | Inactif | P2 | L | Maintenance |
| SQLite | ? | 3.45.0 (2024) | P1 | S | Sécurité |

---

## 🔄 Plan de Mise à Jour Séquentiel

### Phase 1: Sécurité Critique (P1)
1. **zlib 1.3.1** - 1 jour
   - Mise à jour simple, ABI compatible
   - Tests: Compression/décompression

2. **MiniUPnP 2.2.6** - 2-3 jours
   - Vérifier compatibilité API
   - Tests: Port forwarding sur différents routeurs

3. **SQLite 3.45.0** - 1 jour
   - Vérifier version actuelle d'abord
   - Tests: Migration de base de données (si nécessaire)

### Phase 2: Sécurité + Compatibilité (P1)
4. **UnRAR → 7-Zip ou UnRAR 6.2.12** - 1-2 semaines
   - Décision: 7-Zip (recommandé) ou UnRAR 6.2.12
   - Tests: Extraction de divers formats RAR
   - Vérifier licence si UnRAR

### Phase 3: Maintenance (P2)
5. **GeoIP → libmaxminddb** - 1 semaine
   - Migration vers GeoIP2
   - Tests: Géolocalisation IP

6. **LibUTP** - Évaluation
   - Décider: Maintenir, Fork, ou Supprimer

7. **BugTrap** - Évaluation
   - Décider: Maintenir ou migrer vers Crashpad

---

## ⚠️ Notes de Compatibilité

### UnRAR
- **Licence:** Vérifier usage commercial - peut nécessiter licence WinRAR
- **Alternative 7-Zip:** Format RAR partiellement supporté (lecture uniquement pour certains formats)

### GeoIP Legacy
- **Migration:** Format `.dat` → `.mmdb` (incompatible)
- **Base de données:** Télécharger GeoLite2 depuis MaxMind (gratuit, mise à jour mensuelle)

### MiniUPnP
- **API:** Vérifier changements d'API entre 2.0 et 2.2.6
- **Tests:** Tester sur routeurs récents (2020+)

---

## ✅ Checklist de Validation

Pour chaque mise à jour:
- [ ] Vérifier compatibilité ABI/API
- [ ] Lire changelog pour breaking changes
- [ ] Tester fonctionnalités critiques
- [ ] Vérifier licences (usage commercial)
- [ ] Mettre à jour documentation
- [ ] Tests de régression complets

---

## 📝 Notes de Licence

### UnRAR
- **Freeware:** Usage gratuit pour extraction uniquement
- **Commercial:** Développement d'archiver RAR nécessite licence WinRAR
- **Distribution:** Permis dans autres logiciels (avec licence incluse)

### GeoIP Legacy
- **LGPL/GPL:** Selon version
- **GeoIP2 (libmaxminddb):** Apache 2.0
- **GeoLite2 DB:** Creative Commons Attribution-ShareAlike 4.0

### Autres
- **zlib:** zlib License (très permissive)
- **MiniUPnP:** BSD-3-Clause
- **SQLite:** Public Domain
- **LibUTP:** MIT

---

**Prochaines Étapes:**
1. Vérifier versions exactes de toutes les dépendances
2. Prioriser mises à jour P1 (sécurité)
3. Planifier tests de régression
4. Documenter changements de licence si nécessaire
