# 🔒 Audit de Sécurité - Envy

**Date:** 16 janvier 2026  
**Version:** 1.0  
**Objectif:** Identification des risques de sécurité critiques et recommandations de correction

---

## 📋 Modèle de Menace

### Surfaces d'Attaque Identifiées

1. **Interface HTTP Remote** (`Envy/Remote.cpp`, `Envy/UploadTransferHTTP.cpp`)
   - Exposition réseau par défaut
   - Authentification faible (SHA-1 simple)
   - Absence de protection CSRF
   - Pas de rate limiting

2. **Parsers Réseau** (`Envy/*Packet.cpp`, `Envy/Datagrams.cpp`)
   - Parsing binaire non validé
   - Buffer overflows potentiels
   - Désérialisation non sécurisée

3. **Extraction d'Archives** (`Services/UnRAR/`)
   - Bibliothèque UnRAR 5.3.8 (2015) - obsolète
   - Path traversal potentiel
   - Extraction de fichiers malveillants

4. **UPnP** (`Envy/UPnPFinder.cpp`, `Envy/UPnPNAT.cpp`, `Services/MiniUPnP/`)
   - Port forwarding automatique
   - Exposition de services internes
   - Version MiniUPnP 2.0 (2016) - obsolète

5. **Kademlia/ED2K** (`Envy/Kademlia.cpp`, `Envy/EDClient.cpp`)
   - RNG faible (`rand()` utilisé)
   - Hash non cryptographique (djb2)
   - Pas de validation d'ID de nœud

---

## 🚨 Risques Critiques (P0)

### 1. Interface Remote HTTP - Exposition Non Sécurisée

**Fichiers affectés:**
- `Envy/Remote.cpp:72-217` - Construction et gestion des connexions
- `Envy/UploadTransferHTTP.cpp:456-467` - Détection des requêtes `/remote`
- `Envy/PageSettingsRemote.cpp:79-246` - Configuration

**Scénario d'exploitation:**
```cpp
// Envy/UploadTransferHTTP.cpp:456-467
else if ( ::StartsWith( m_sRequest, _P( L"/remote" ) ) )
{
    if ( Settings.Remote.Enable )  // Pas de vérification de binding
    {
        Prefix( _P("GET /remote/ HTTP/1.1\r\n\r\n") );
        new CRemote( this );
        // Accepte les connexions depuis n'importe quelle IP
    }
}
```

**Problèmes:**
1. **Binding par défaut:** Écoute sur `0.0.0.0` (toutes interfaces) - `Envy/Network.cpp:135`
2. **Authentification faible:** SHA-1 simple sans salt - `Envy/Remote.cpp:598-606`
3. **Pas de CSRF:** Cookies simples sans token - `Envy/Remote.cpp:246-263`
4. **Pas de rate limiting:** Pas de protection contre brute force

**Recommandation de correction:**
```cpp
// 1. Binding localhost par défaut
// Envy/Network.cpp - Modifier l'écoute HTTP
if (Settings.Remote.Enable) {
    // Par défaut, bind uniquement sur localhost
    if (Settings.Remote.BindAddress.IsEmpty()) {
        Settings.Remote.BindAddress = "127.0.0.1";
    }
    // Écouter uniquement sur l'adresse spécifiée
    ListenOnAddress(Settings.Remote.BindAddress, Settings.Connection.InPort);
}

// 2. Ajouter rate limiting
// Envy/Remote.cpp - Ajouter dans CRemote::OnRead()
static std::map<CString, RateLimitInfo> rateLimits;
CString clientIP = GetClientIP();
if (rateLimits[clientIP].requests > 10 && 
    (GetTickCount() - rateLimits[clientIP].lastRequest) < 60000) {
    Close(); // Trop de requêtes
    return FALSE;
}

// 3. Protection CSRF
// Envy/Remote.cpp - Modifier CheckCookie()
BOOL CRemote::CheckCookie() {
    // Vérifier cookie ET token CSRF
    CString csrfToken = GetKey(L"csrf_token");
    if (csrfToken != GetStoredCSRFToken()) {
        m_sRedirect = L"/remote/";
        return TRUE;
    }
    // ... reste du code
}
```

**Validation:**
- Test: Vérifier que l'interface n'est pas accessible depuis l'extérieur par défaut
- Test: Brute force password - doit être bloqué après 5 tentatives
- Test: CSRF - requêtes cross-origin doivent être rejetées

---

### 2. RNG Faible dans Kademlia/ED2K

**Fichiers affectés:**
- `Envy/Kademlia.cpp:234-247` - Génération d'ID Kad
- `Envy/Kademlia.cpp:338-341` - Génération d'ID cible
- `Envy/EDClient.cpp:69` - SecureID challenge
- `Envy/KademliaPlatform.cpp:95-118` - Fallback vers `rand()`

**Scénario d'exploitation:**
```cpp
// Envy/Kademlia.cpp:242-244
srand(GetTickCount());  // Seed prévisible
for (size_t i = oGUID.byteCount; i < KAD_ID_SIZE; i++) {
    m_ownId[i] = (BYTE)(rand() & 0xFF);  // RNG non cryptographique
}
```

**Problèmes:**
1. **Seed prévisible:** `GetTickCount()` permet de deviner la seed
2. **RNG non cryptographique:** `rand()` est déterministe et prévisible
3. **Fallback dangereux:** `KademliaPlatform.cpp:106` utilise `rand()` si `CryptGenRandom` échoue

**Recommandation de correction:**
```cpp
// Envy/Kademlia.cpp - Remplacer GenerateOwnKadId()
void CKademlia::GenerateOwnKadId() {
    Hashes::Guid oGUID = MyProfile.oGUID;
    memcpy(m_ownId, &oGUID[0], std::min(oGUID.byteCount, size_t(KAD_ID_SIZE)));
    
    if (oGUID.byteCount < KAD_ID_SIZE) {
        // Utiliser BCryptGenRandom (Windows CNG)
        BCRYPT_ALG_HANDLE hAlgorithm = NULL;
        if (BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RNG_ALGORITHM, NULL, 0) == STATUS_SUCCESS) {
            BCryptGenRandom(hAlgorithm, 
                           m_ownId + oGUID.byteCount, 
                           KAD_ID_SIZE - oGUID.byteCount, 
                           0);
            BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        } else {
            // Fallback: CryptGenRandom (plus sûr que rand())
            HCRYPTPROV hProv = 0;
            if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
                CryptGenRandom(hProv, KAD_ID_SIZE - oGUID.byteCount, m_ownId + oGUID.byteCount);
                CryptReleaseContext(hProv, 0);
            } else {
                // Dernier recours: échouer plutôt que d'utiliser rand()
                ASSERT(FALSE); // Ne jamais utiliser rand() pour la crypto
            }
        }
    }
}
```

**Validation:**
- Test: Vérifier que les IDs Kad générés sont non prévisibles (entropie test)
- Test: Vérifier que `BCryptGenRandom` est utilisé (pas de fallback vers `rand()`)

---

### 3. Hash Non Cryptographique dans Kademlia

**Fichiers affectés:**
- `Envy/KademliaPlatform.cpp:54-92` - Fonction `kad_hash()`

**Scénario d'exploitation:**
```cpp
// Envy/KademliaPlatform.cpp:77-80
unsigned int hash = 5381; // djb2 hash
for (size_t i = 0; i < data.size(); i++) {
    hash = ((hash << 5) + hash) + data[i];
}
```

**Problèmes:**
1. **djb2 non cryptographique:** Vulnérable aux collisions
2. **Pas de résistance préimage:** Facile à inverser
3. **Commentaire TODO:** Indique que SHA-1 devrait être utilisé

**Recommandation de correction:**
```cpp
// Envy/KademliaPlatform.cpp - Remplacer kad_hash()
void kad_hash(void *hash_return, int hash_size,
             const void *v1, int len1,
             const void *v2, int len2,
             const void *v3, int len3)
{
    // Utiliser SHA-1 pour Kademlia (compatible eMule)
    CSHA sha1;
    
    if (v1 && len1 > 0) sha1.Add(v1, len1);
    if (v2 && len2 > 0) sha1.Add(v2, len2);
    if (v3 && len3 > 0) sha1.Add(v3, len3);
    
    sha1.Finish();
    Hashes::Sha1Hash result;
    sha1.GetHash(&result[0]);
    
    // Copier le résultat (tronquer si nécessaire)
    int copySize = min(hash_size, (int)Hashes::Sha1Hash::byteCount);
    memcpy(hash_return, &result[0], copySize);
}
```

**Validation:**
- Test: Vérifier que les hashs générés sont résistants aux collisions
- Test: Comparer avec eMule pour compatibilité

---

## ⚠️ Risques Élevés (P1)

### 4. Parsing de Paquets Non Validé

**Fichiers affectés:**
- `Envy/G2Neighbour.cpp:282-358` - Parsing G2
- `Envy/G1Neighbour.cpp:278-320` - Parsing Gnutella
- `Envy/EDPacket.cpp:1525-1571` - Parsing ED2K
- `Envy/Datagrams.cpp:737-880` - Détection UDP

**Scénario d'exploitation:**
```cpp
// Envy/G2Neighbour.cpp:298-303
BYTE nLenLen = (nInput & 0xC0) >> 6;
BYTE nTypeLen = (nInput & 0x38) >> 3;
// Pas de validation que nLenLen/nTypeLen sont dans des limites raisonnables

DWORD nLength = 0;
// Calcul de longueur sans vérification de débordement
```

**Problèmes:**
1. **Pas de validation de taille:** Longueurs de paquet non vérifiées
2. **Débordement potentiel:** Calculs arithmétiques non protégés
3. **Pas de limites maximales:** `Settings.Gnutella.MaximumPacket` peut être contourné

**Recommandation de correction:**
```cpp
// Envy/G2Neighbour.cpp - Ajouter validation
BOOL CG2Neighbour::ProcessPackets(CBuffer* pInput) {
    // ... code existant ...
    
    // Validation stricte
    if (nLenLen > 4 || nTypeLen > 4) {  // Limites raisonnables
        Close(IDS_PROTOCOL_INVALID);
        return FALSE;
    }
    
    // Vérifier débordement avant calcul
    if (pInput->m_nLength < nLenLen + nTypeLen + 2ul) break;
    
    DWORD nLength = 0;
    // Calcul avec vérification
    if (nLenLen > 0) {
        if (pInput->m_nLength < 1 + nLenLen) break;
        // ... calcul sécurisé ...
    }
    
    // Vérifier limites maximales AVANT allocation
    if (nLength > Settings.Gnutella.MaximumPacket || 
        nLength > MAX_SAFE_PACKET_SIZE) {  // Constante de sécurité
        Close(IDS_PROTOCOL_TOO_LARGE);
        return FALSE;
    }
}
```

**Validation:**
- Fuzzing: Utiliser AFL ou libFuzzer sur les parsers
- Tests: Paquets malformés doivent être rejetés sans crash

---

### 5. Extraction d'Archives - Path Traversal

**Fichiers affectés:**
- `Services/UnRAR/extract.cpp:159-197` - Extraction
- `Plugins/RARBuilder/RARBuilder.cpp` - Utilisation

**Problèmes:**
1. **UnRAR 5.3.8 (2015):** Version obsolète, vulnérabilités connues
2. **Path traversal:** Pas de validation des chemins extraits
3. **Licence:** UnRAR nécessite une licence pour usage commercial

**Recommandation de correction:**
```cpp
// Services/UnRAR/extract.cpp - Ajouter validation
void CmdExtract::ExtrPrepareName(Archive &Arc, const wchar *ArcFileName, 
                                  wchar *DestName, size_t DestSize) {
    // ... code existant ...
    
    // Validation path traversal
    if (wcsstr(DestName, L"..") || wcsstr(DestName, L"//")) {
        ErrHandler.SetErrorCode(RARX_WARNING);
        return; // Rejeter les chemins suspects
    }
    
    // Normaliser le chemin
    wchar normalizedPath[MAX_PATH];
    if (!PathCanonicalizeW(normalizedPath, DestName)) {
        ErrHandler.SetErrorCode(RARX_WARNING);
        return;
    }
    
    // Vérifier que le chemin normalisé est dans le répertoire de destination
    wchar basePath[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, basePath);
    if (!PathIsRelativeW(normalizedPath) && 
        !PathIsPrefixW(basePath, normalizedPath)) {
        ErrHandler.SetErrorCode(RARX_WARNING);
        return;
    }
}
```

**Plan de mise à jour:**
- Migrer vers UnRAR 6.2.12 (dernière version) ou alternative (7-Zip)
- Vérifier licence pour usage commercial

**Validation:**
- Test: Extraire archive avec `../../etc/passwd` - doit être rejeté
- Test: Extraire archive avec chemins absolus - doit être normalisé

---

## ⚡ Risques Moyens (P2)

### 6. UPnP - Exposition de Services

**Fichiers affectés:**
- `Envy/UPnPFinder.cpp:709-743` - Création de port mappings
- `Envy/UPnPNAT.cpp:127-188` - Mapping moderne
- `Services/MiniUPnP/` - Bibliothèque 2.0 (2016)

**Problèmes:**
1. **Port forwarding automatique:** Expose des ports sans validation utilisateur
2. **MiniUPnP obsolète:** Version 2.0 (2016), version actuelle 2.2.6
3. **Pas de validation:** Ports forwardés sans vérification de sécurité

**Recommandation:**
- Mettre à jour MiniUPnP vers 2.2.6+
- Ajouter confirmation utilisateur pour port forwarding
- Limiter les ports forwardés aux ports nécessaires uniquement

---

### 7. Authentification Remote - SHA-1 Faible

**Fichiers affectés:**
- `Envy/Remote.cpp:598-606` - Hash du mot de passe

**Problèmes:**
1. **SHA-1 obsolète:** Vulnérable aux collisions
2. **Pas de salt:** Hashs identiques pour mots de passe identiques
3. **Pas de stretching:** Pas de PBKDF2/Argon2

**Recommandation:**
```cpp
// Envy/Remote.cpp - Remplacer hash SHA-1
CString HashPassword(const CString& password) {
    // Utiliser PBKDF2 avec SHA-256
    BYTE salt[16];
    BCryptGenRandom(..., salt, 16, ...);  // Générer salt unique
    
    BYTE hash[32];
    // PBKDF2 avec 100,000 itérations
    BCryptDeriveKeyPBKDF2(..., password, password.GetLength() * sizeof(TCHAR),
                          salt, 16, 100000, hash, 32, ...);
    
    // Stocker: salt + hash (base64)
    return EncodeBase64(salt, 16) + L":" + EncodeBase64(hash, 32);
}
```

---

## 🔧 Hardening Build Flags (MSVC x64)

### Flags Recommandés

```cpp
// Compiler Flags (/D, /W, etc.)
/D_CRT_SECURE_NO_WARNINGS  // Supprimer après correction
/D_SECURE_SCL=1            // Secure SCL
/D_HAS_ITERATOR_DEBUGGING=0 // Performance (Release)

// Linker Flags
/SAFESEH                   // Safe Exception Handling
/DYNAMICBASE               // ASLR
/NXCOMPAT                  // DEP
/GUARD:CF                  // Control Flow Guard

// Code Generation
/GS                        // Buffer Security Check
/guard:cf                  // Control Flow Guard
/RTC1                      // Runtime Checks (Debug uniquement)

// Optimizations (Release)
/O2                        // Optimizations
/Ob2                       // Inline function expansion
/Oi                        // Intrinsic functions
/Ot                        // Favor fast code
```

### Exemple de Configuration

```xml
<!-- Envy/Envy.vcxproj -->
<ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
  <ClCompile>
    <RuntimeLibrary>MultiThreaded</RuntimeLibrary>
    <BufferSecurityCheck>true</BufferSecurityCheck>
    <ControlFlowGuard>Guard</ControlFlowGuard>
    <AdditionalOptions>/guard:cf %(AdditionalOptions)</AdditionalOptions>
  </ClCompile>
  <Link>
    <AdditionalOptions>/DYNAMICBASE /NXCOMPAT /GUARD:CF %(AdditionalOptions)</AdditionalOptions>
  </Link>
</ItemDefinitionGroup>
```

---

## ✅ Checklist CI/CD

### Checks de Sécurité Recommandés

1. **Static Analysis**
   - CppCheck avec règles de sécurité
   - Clang-Tidy security checks
   - PVS-Studio (si disponible)

2. **Dynamic Analysis**
   - Fuzzing avec AFL/libFuzzer sur parsers
   - Tests de pénétration sur interface Remote
   - Memory sanitizers (AddressSanitizer)

3. **Dependency Scanning**
   - Snyk ou Dependabot pour vulnérabilités
   - Vérification des versions de bibliothèques

4. **Build Verification**
   - Vérifier que les flags de sécurité sont activés
   - Vérifier que ASLR/DEP sont activés

---

## 📊 Résumé des Risques

| Risque | Priorité | Fichiers | Complexité Fix | Impact |
|--------|----------|----------|----------------|--------|
| Remote HTTP - Exposition | P0 | Remote.cpp, UploadTransferHTTP.cpp | M | Critique |
| RNG Faible (Kad/ED2K) | P0 | Kademlia.cpp, EDClient.cpp | S | Critique |
| Hash Non Crypto (Kad) | P0 | KademliaPlatform.cpp | S | Critique |
| Parsing Non Validé | P1 | *Packet.cpp, Datagrams.cpp | M | Élevé |
| Extraction Archives | P1 | UnRAR/extract.cpp | L | Élevé |
| UPnP Exposition | P2 | UPnPFinder.cpp, UPnPNAT.cpp | M | Moyen |
| Auth SHA-1 | P2 | Remote.cpp | M | Moyen |

---

**Prochaines Étapes:**
1. Implémenter les corrections P0 en priorité
2. Ajouter tests de sécurité pour chaque correction
3. Mettre à jour les dépendances obsolètes
4. Configurer CI/CD avec checks de sécurité
