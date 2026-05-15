# Envy - Plan de modernisation (mai 2026)

Ce document est le plan d'audit et de modernisation du code source d'Envy
(client P2P multi-réseau Windows). Il couvre la migration vers
**Visual Studio 2026 / PlatformToolset v145 / MSVC 14.50**, l'introduction
d'une chaîne CI/CD GitHub Actions complète, et l'automatisation des
mises à jour de dépendances.

> **Date de l'audit** : 2026-05-15
> **Branche cible** : `claude/code-audit-modernization-nJcTT`

---

## 1. Audit - état avant migration

| Indicateur | Valeur |
| --- | --- |
| Projets MSBuild (.vcxproj) | 46 |
| Fichiers `.cpp` / `.h` | 677 / 709 |
| Toolsets utilisés | v141_xp (36), v142 (12), v140 (templates) |
| Cible OS | Windows XP+ (via v141_xp + `_ATL_XP_TARGETING`) |
| C++ Standard configuré | **Aucun** (défaut MSVC = C++14) |
| `WindowsTargetPlatformVersion` | non défini (SDK par défaut) |
| `_CRT_SECURE_NO_WARNINGS` actif | Oui (tous projets) |
| `pragma warning(disable...)` | 70 occurrences dans `Envy/` |
| Inline ASM | Uniquement 3rd-party (UnRAR, BugTrap) |
| CI/CD | **Aucun** (pas de workflows, pas d'AppVeyor) |
| Encodage sources | Mixte ISO-8859 / UTF-8, pas de BOM systématique |
| Gestion deps tierces | **Sources bundlées** dans `Services/` et `Plugins/` |

### Dépendances tierces bundlées

| Lib | Version actuelle | Statut |
| --- | --- | --- |
| zlib | 1.2.10 (2017-01) | Obsolète (latest 1.3.1, vulns connues) |
| sqlite3 | 3.30.0 (2019-10) | Obsolète (latest 3.46+) |
| bzip2 (`Bzlib`) | 1.0.5 (2007) | **Très obsolète** (vulns CVE-2016-3189, CVE-2019-12900) |
| miniupnpc | inconnu | Obsolète |
| UnRAR | 5.30 (2015-11) | Obsolète, contient inline ASM x86 |
| GeoIP | inconnu | Obsolète (legacy MaxMind, à remplacer par libmaxminddb) |
| LibUTP | snapshot 2010 | Obsolète |
| BugTrap | 2005-2010 | À évaluer (peut être remplacé par WER) |
| LibGFL | 3.40 (~2003) | **Très obsolète** (binaire non-libre, à supprimer si possible) |

---

## 2. Cible

| Indicateur | Cible |
| --- | --- |
| Toolset | **v145** (VS 2026 v18.0+ / MSVC 14.50) |
| Cible OS | **Windows 10 1809 (build 17763)** ou plus récent |
| `WindowsTargetPlatformVersion` | `10.0` (SDK le plus récent installé) |
| C++ standard | **C++20** pour le code first-party, **C++17** pour plugins legacy |
| `/permissive-` | Phase 2 (après nettoyage des warnings) |
| Architectures | x64 (principal), Win32 (compatibilité), **ARM64** (nouveau) |
| Mitigations | `/GS`, `/guard:cf`, `/sdl`, Spectre runtime libs |
| Gestion deps | **vcpkg manifest** (`vcpkg.json`) |
| Auto-update | **Dependabot** (vcpkg + GitHub Actions) |
| CI | GitHub Actions sur `windows-2025` runners |
| Analyse code | CodeQL (cpp), `/analyze` MSVC, clang-tidy (advisory) |

---

## 3. Phases d'exécution

### Phase 0 - Bootstrap infrastructure (cette PR)

- [x] Audit complet du codebase
- [x] Choix architecturaux (drop XP, vcpkg manifest)
- [x] `.gitignore`, `.editorconfig`, `.clang-format`, `.clang-format-ignore`
- [x] `vcpkg.json` + `vcpkg-configuration.json` initialisés
- [x] `.github/dependabot.yml` (vcpkg + actions, hebdomadaire)
- [x] `.github/CODEOWNERS`, `SECURITY.md`, PR template, 3 issue templates
- [x] Workflows : `build.yml`, `codeql.yml`, `dependency-review.yml`,
      `clang-tidy.yml`, `format-check.yml`, `release.yml`, `stale.yml`,
      `labeler.yml`, `copilot-setup-steps.yml`
- [x] `Visual Studio/SetVS2026.bat` + `SetVS2026.ps1` (script de retarget)
- [x] Migration mécanique : 142 `<PlatformToolset>` -> v145 sur 45 projets
- [x] Suppression de `_ATL_XP_TARGETING` (66 occurrences) et
      `ENVY_USE_ASM` (2 occurrences) des préprocesseurs
- [x] Injection de `<WindowsTargetPlatformVersion>10.0</...>` dans 44 projets
- [x] `<LanguageStandard>stdcpp20</...>` sur Envy + 12 projets first-party
- [x] `<LanguageStandard>stdcpp17</...>` sur 19 plugins
- [x] Fix `register` keyword (Buffer.cpp) - retiré (réservé en C++17)
- [x] Fix `throw()` -> `noexcept` (Buffer.h, Buffer.cpp, Connection.h)

### Phase 1 - Premier build vert (PR suivante)

- [ ] Première compilation sur `windows-2025` avec v145
- [ ] Corriger les erreurs C++20 (`std::auto_ptr` 3rd-party, `wstring_convert`,
      etc.)
- [ ] Mettre à jour les chemins d'include / linker pour les libs vcpkg
- [ ] Désactiver temporairement les plugins cassés (RatDVD, SWF si SDK absent)
- [ ] Vérifier que `Envy.exe` se lance et établit une connexion Gnutella

### Phase 2 - Nettoyage warnings + /permissive-

- [ ] Activer `<ConformanceMode>true</ConformanceMode>` (`/permissive-`)
- [ ] Réviser les 70 `#pragma warning(disable ...)` :
      - Garder uniquement ceux nécessaires
      - Documenter les survivants
- [ ] Activer `<SDLCheck>true</SDLCheck>` (`/sdl`)
- [ ] Activer `<ControlFlowGuard>Guard</ControlFlowGuard>` (`/guard:cf`)
- [ ] Activer `<SpectreMitigation>Spectre</SpectreMitigation>` en Release
- [ ] Retirer `_CRT_SECURE_NO_WARNINGS` du préprocesseur projet par projet :
      remplacer les usages dangereux (`strcpy`, `sprintf`, `gets`) par les
      variantes `_s` ou `string_view`/`format`

### Phase 3 - Modernisation des dépendances

- [ ] Migrer chaque lib bundle vers vcpkg :
      - `Services/zlib` -> `vcpkg install zlib`
      - `Services/Bzlib` -> `vcpkg install bzip2`
      - `Services/SQLite` -> `vcpkg install sqlite3`
      - `Services/MiniUPnP` -> `vcpkg install miniupnpc`
      - `Services/GeoIP` -> `vcpkg install libmaxminddb` (remplacement moderne)
- [ ] Supprimer les sous-arbres `Services/<lib>/` après bascule
- [ ] Évaluer le remplacement de `BugTrap` par Windows Error Reporting (WER)
- [ ] Évaluer la suppression de `LibGFL` (binaire non-libre, AGPL conflit)

### Phase 4 - Robustesse run-time

- [ ] Ajouter HashLib unit tests dans CI (vcpkg feature `tests` activée)
- [ ] AddressSanitizer (`/fsanitize=address`) sur configurations Debug
- [ ] Crash dump symboles publiés en artifacts GitHub
- [ ] Bench `cppblog` : verifier l'amélioration 6% du backend MSVC

### Phase 5 - ARM64 + signature

- [ ] Ajouter `Release|ARM64` à `Envy.sln` et chaque `.vcxproj`
- [ ] Code signing via Azure Trusted Signing (workflow `release.yml`)
- [ ] WiX/MSIX en complément d'Inno Setup pour la distribution Microsoft Store

---

## 4. Infrastructure CI/CD livrée

### Workflows

| Fichier | Déclencheur | Job principal |
| --- | --- | --- |
| `.github/workflows/build.yml` | push / PR | Matrix x64+Win32 x Release+Debug sur windows-2025, v145, vcpkg restore, MSBuild, upload logs |
| `.github/workflows/codeql.yml` | push / PR / weekly | Analyse C/C++ avec security-extended + security-and-quality queries |
| `.github/workflows/dependency-review.yml` | PR | dependency-review-action + validation jq de `vcpkg.json` |
| `.github/workflows/clang-tidy.yml` | PR | clang-tidy sur les fichiers modifiés, **advisory** (continue-on-error) |
| `.github/workflows/format-check.yml` | PR | clang-format --dry-run, **advisory** |
| `.github/workflows/release.yml` | tag `v*` | Build x64+Win32, zip, draft GitHub Release |
| `.github/workflows/stale.yml` | daily | Marquage stale après 90j (issue) / 45j (PR) |
| `.github/workflows/labeler.yml` | PR | Auto-labels par paths (build, ci, core, plugins, etc.) |
| `.github/workflows/copilot-setup-steps.yml` | manuel | Préchauffe environnement Copilot |

### Bots et automatisation

- **Dependabot** :
  - vcpkg, hebdomadaire (lundi 07:00 Europe/Paris), groupe unique
    "vcpkg-baseline" qui avance le commit `builtin-baseline`.
  - GitHub Actions, hebdomadaire, groupe `actions-minor-patch`.
- **Stale bot** : auto-fermeture après inactivité (issues 90+14j, PR 45+21j).
- **Labeler** : auto-tag des PR selon les fichiers touchés.
- **CodeQL** : analyse hebdomadaire + sur chaque PR.

### Templates et conventions

- `.github/CODEOWNERS` : review requis pour CI / build files / 3rd-party.
- `.github/SECURITY.md` : politique de divulgation responsable.
- `.github/pull_request_template.md` : checklist build x64/Win32 + analyse.
- `.github/ISSUE_TEMPLATE/{bug_report,feature_request,build_failure}.yml`.
- `.editorconfig` : tab/4 pour C++, space/2 pour XML/JSON.
- `.clang-format` (Microsoft style, conservatif) + `.clang-format-ignore`
  pour exclure les sources 3rd-party.

---

## 5. Comment compiler localement avec VS 2026

```cmd
:: Pré-requis : Visual Studio 2026 v18.0+ avec :
::   - Desktop development with C++
::   - MSVC v145 (default toolset)
::   - MFC / ATL pour v145
::   - Windows 10/11 SDK (latest)
::   - C++ Spectre-mitigated libs (v145)
::   - C++ CMake tools for Windows
::   - vcpkg (intégré dans VS 2026)

:: 1. Cloner et basculer sur la branche
git clone https://github.com/mika3578/envy.git
cd envy
git checkout claude/code-audit-modernization-nJcTT

:: 2. Bootstrap vcpkg (manifest mode auto via VS 2026)
git clone https://github.com/microsoft/vcpkg.git
.\vcpkg\bootstrap-vcpkg.bat

:: 3. (Optionnel) Forcer le retarget de tous les vcxproj
cd "Visual Studio"
SetVS2026.bat
cd ..

:: 4. Ouvrir la solution
start "" "Visual Studio\Envy.sln"

:: 5. Build > Build Solution (Ctrl+Shift+B)
```

Ou en CLI :

```cmd
msbuild "Visual Studio\Envy.sln" /m /p:Configuration=Release /p:Platform=x64 ^
  /p:PlatformToolset=v145 /p:WindowsTargetPlatformVersion=10.0 ^
  /p:VcpkgEnableManifest=true /p:VcpkgTriplet=x64-windows-static
```

---

## 6. Comment activer Dependabot et les workflows

1. **Push de la branche** sur GitHub :
   ```
   git push -u origin claude/code-audit-modernization-nJcTT
   ```
2. **Créer la PR draft** vers `main`.
3. Dans **Settings -> Security and analysis** du repo :
   - Activer "Dependency graph"
   - Activer "Dependabot alerts"
   - Activer "Dependabot security updates"
   - Activer "Dependabot version updates" (utilisera `.github/dependabot.yml`)
   - Activer "Code scanning" (CodeQL via le workflow)
   - Activer "Secret scanning" et "Push protection"
4. **Branch protection** sur `main` :
   - Require pull request reviews (1+)
   - Require status checks: `Build x64 Release`, `Analyze C/C++`,
     `Dependency review`
   - Require CODEOWNERS review pour `.github/` et `Visual Studio/`
5. Première exécution Dependabot : la valeur placeholder `0000...` du
   `builtin-baseline` dans `vcpkg.json` sera remplacée automatiquement par
   un commit récent du registry vcpkg.

---

## 7. Risques connus

| Risque | Mitigation |
| --- | --- |
| Cassures C++20 sur code MFC legacy (200+ fichiers) | Phase 1 = build + corrections incrémentales, `<ConformanceMode>` désactivé temporairement |
| Plugins dépendant de SDK obsolètes (RatDVD, SWF, DirectShow) | Désactivés dans `Envy.sln` (déjà commentés), audit séparé |
| Inline ASM x86 dans UnRAR / BugTrap | Déjà conditionnel à Win32 - Win64 utilise les variantes C |
| Cible Win 10+ casse l'écosystème WinXP historique | Annoncé dans `SECURITY.md` ; branche `legacy` existante préservée |
| `vcpkg install` lent à la première run | Cache GitHub Actions configuré (clé sur hash de `vcpkg.json`) |
| LibGFL non libre vs licence AGPL | Tracker une issue, peut nécessiter retrait du build par défaut |
| Inno Setup absent des runners hosted | Soit ajouter une step `chocolatey install innosetup`, soit déplacer en job séparé |

---

## 8. Backout

Toutes les modifications sont localisées et réversibles :

```cmd
:: Restaurer le toolset v141_xp pour build VS 2017 legacy
"Visual Studio\SetVS2017.bat"

:: Ou désactiver les workflows
git rm -r .github/workflows
```

La branche `legacy` du repo conserve l'état pre-modernisation.

---

## 9. Métriques de succès

- [ ] CI verte sur `windows-2025` pour `Release|x64` et `Release|Win32`
- [ ] Première analyse CodeQL terminée sans CRITICAL
- [ ] Dependabot ouvre la première PR vcpkg dans les 7 jours
- [ ] Aucun pragma `_ATL_XP_TARGETING` ni `v141_xp` dans `git grep`
- [ ] Build local VS 2026 vert sans intervention manuelle
