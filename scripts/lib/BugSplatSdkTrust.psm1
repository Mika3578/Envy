# BugSplat Native SDK import trust helpers (Envy #354).
# Import compares source files to a maintainer-reviewed baseline in SDK-HASHES.json.
# BugSplat does not publish an independent SHA-256 manifest for the Native C++ zip.

Set-StrictMode -Version Latest

$Script:BugSplatOfficialNativeUrl = 'https://app.bugsplat.com/browse/download_item.php?item=native'
$Script:DefaultPublisherSubjectTokens = @('BugSplat')

function Resolve-BugSplatSdkRoot {
	param([string]$Root)
	$Root = (Resolve-Path -LiteralPath $Root).Path
	if (Test-Path -LiteralPath (Join-Path $Root 'inc\BugSplat.h')) { return $Root }
	$inner = Join-Path $Root 'BugSplat'
	if (Test-Path -LiteralPath (Join-Path $inner 'inc\BugSplat.h')) { return $inner }
	throw "Could not find inc\BugSplat.h under $Root or $inner"
}

function Find-BugSplatLibMt {
	param([string]$SdkRoot, [string]$Config)
	$candidates = @(
		(Join-Path $SdkRoot "x64\$Config\lib\mt\BugSplat.lib"),
		(Join-Path $SdkRoot "$Config\x64\lib\mt\BugSplat.lib")
	)
	foreach ($c in $candidates) {
		if (Test-Path -LiteralPath $c) { return $c }
	}
	return $null
}

function Find-BugSplatBinDir {
	param([string]$SdkRoot, [string]$Config)
	$candidates = @(
		(Join-Path $SdkRoot "x64\$Config\bin"),
		(Join-Path $SdkRoot "x64\$Config"),
		(Join-Path $SdkRoot "$Config\x64\bin")
	)
	foreach ($c in $candidates) {
		if (Test-Path -LiteralPath (Join-Path $c 'BugSplatMonitor.exe')) { return $c }
	}
	return $null
}

function Get-BugSplatStaticLibCrtKind {
	param([string]$Path)
	if (-not (Test-Path -LiteralPath $Path)) { return 'missing' }
	$ascii = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($Path))
	if ($ascii -match 'DEFAULTLIB:msvcrtd\.lib' -or $ascii -match 'DEFAULTLIB:msvcprtd\.lib') { return 'md-dynamic-debug' }
	if ($ascii -match 'DEFAULTLIB:msvcrt\.lib' -or $ascii -match 'DEFAULTLIB:msvcprt\.lib') { return 'md-dynamic-release' }
	if ($ascii -match 'DEFAULTLIB:LIBCMTD') { return 'mt-static-debug' }
	if ($ascii -match 'DEFAULTLIB:LIBCMT') { return 'mt-static-release' }
	return 'unknown'
}

function Assert-BugSplatLibMtCrt {
	param([string]$LibPath, [string]$Config)
	$kind = Get-BugSplatStaticLibCrtKind -Path $LibPath
	$expect = if ($Config -eq 'Debug') { 'mt-static-debug' } else { 'mt-static-release' }
	if ($kind -eq 'md-dynamic-release' -or $kind -eq 'md-dynamic-debug') {
		throw "Refusing to use ${LibPath}: CRT probe reports $kind. Envy links /MT (/MTd Debug). Use lib\mt from the official Native SDK."
	}
	if ($kind -eq 'unknown') {
		throw "CRT probe for $LibPath returned unknown. Refusing unverified BugSplat.lib (expected $expect from lib\mt)."
	}
	if ($kind -ne $expect) {
		throw "CRT probe for $LibPath returned $kind (expected $expect). Use lib\mt from the official Native SDK."
	}
}

function Get-BugSplatFileSha256 {
	param([string]$Path)
	return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToUpperInvariant()
}

function Read-BugSplatReferenceHashes {
	param([string]$Path)
	if (-not (Test-Path -LiteralPath $Path)) {
		return @{ Map = @{}; Document = $null }
	}
	$json = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
	$map = @{}
	if ($json.files) {
		$json.files.PSObject.Properties | ForEach-Object { $map[$_.Name] = $_.Value.ToUpperInvariant() }
	}
	return @{ Map = $map; Document = $json }
}

function Assert-BugSplatSourceMatchesReference {
	param(
		[string]$SourceFile,
		[string]$RelativePath,
		[hashtable]$ReferenceMap
	)
	if ($ReferenceMap.Count -eq 0) {
		throw @"
SDK-HASHES.json has no file entries. Normal import requires a maintainer-reviewed baseline.
Run scripts/establish-bugsplat-sdk-trust.ps1 after downloading from $Script:BugSplatOfficialNativeUrl,
commit the updated SDK-HASHES.json via PR review, then run scripts/import-bugsplat-sdk.ps1.
"@
	}
	$hash = Get-BugSplatFileSha256 -Path $SourceFile
	if (-not $ReferenceMap.ContainsKey($RelativePath)) {
		throw "No reference hash for $RelativePath in SDK-HASHES.json. Add it via establish-bugsplat-sdk-trust.ps1 and a reviewed PR."
	}
	$expected = $ReferenceMap[$RelativePath]
	if ($hash -ne $expected) {
		throw "SHA-256 mismatch for $RelativePath. Expected $expected got $hash. Source may be tampered or the wrong SDK version."
	}
	return $hash
}

function Assert-BugSplatAuthenticode {
	param(
		[string]$Path,
		[string[]]$PublisherSubjectContains = $Script:DefaultPublisherSubjectTokens,
		[bool]$RequireSignature = $true
	)
	if ($Path -notmatch '\.(exe|dll)$') { return }
	$sig = Get-AuthenticodeSignature -LiteralPath $Path
	if ($sig.SignatureType -eq 'None') {
		if ($RequireSignature) {
			throw "Authenticode signature required but missing on $Path"
		}
		Write-Warning "No Authenticode signature on $Path"
		return
	}
	if ($sig.Status -ne 'Valid') {
		throw "Authenticode check failed for $Path ($($sig.Status))"
	}
	$subject = $sig.SignerCertificate.Subject
	$matched = $false
	foreach ($token in $PublisherSubjectContains) {
		if ($subject -like "*$token*") { $matched = $true; break }
	}
	if (-not $matched) {
		throw "Authenticode signer for $Path does not match expected publisher tokens ($($PublisherSubjectContains -join ', ')). Subject: $subject"
	}
}

function Get-BugSplatImportPlan {
	param([string]$SdkRoot)
	$plan = [ordered]@{
		Header = (Join-Path $SdkRoot 'inc\BugSplat.h')
		Libs   = @()
		Bins   = @()
	}
	foreach ($config in @('Release', 'Debug')) {
		$libSrc = Find-BugSplatLibMt -SdkRoot $SdkRoot -Config $config
		if (-not $libSrc) {
			Throw-BugSplatSdkImportDiagnostics -SdkRoot $SdkRoot -Config $config
		}
		Assert-BugSplatLibMtCrt -LibPath $libSrc -Config $config
		$plan.Libs += [pscustomobject]@{
			Config       = $config
			Source       = $libSrc
			RelativePath = "x64/$config/lib/mt/BugSplat.lib"
		}
		$binSrc = Find-BugSplatBinDir -SdkRoot $SdkRoot -Config $config
		if (-not $binSrc) { throw "Missing BugSplatMonitor.exe for $config under $SdkRoot" }
		foreach ($name in @('BugSplatMonitor.exe', 'BugSplatWer.dll', 'BugSplatRc.dll')) {
			$srcFile = Join-Path $binSrc $name
			if (Test-Path -LiteralPath $srcFile) {
				$plan.Bins += [pscustomobject]@{
					Config       = $config
					Source       = $srcFile
					RelativePath = "x64/$config/bin/$name"
					Name         = $name
				}
			}
		}
	}
	return $plan
}

function New-BugSplatTrustDocumentSkeleton {
	param([string]$SdkVersion)
	return [ordered]@{
		description = 'Maintainer-reviewed SHA-256 baseline for the BugSplat Native Windows SDK. Not an independent publisher manifest.'
		trustModel  = [ordered]@{
			publisherIndependentSha256Manifest = $false
			sha256Role                         = 'Detect drift from a maintainer-reviewed baseline after portal download.'
			baselineEstablishedBy              = 'scripts/establish-bugsplat-sdk-trust.ps1 plus human PR review'
			authenticode                       = [ordered]@{
				requiredForPeFiles         = $true
				publisherSubjectContains = $Script:DefaultPublisherSubjectTokens
			}
			limitation = 'SHA-256 in this file does not prove the first download was uncompromised; it only detects changes after the baseline was committed.'
		}
		sdkVersion  = $SdkVersion
		sourceUrl   = $Script:BugSplatOfficialNativeUrl
		establishedAt = (Get-Date).ToUniversalTime().ToString('o')
		files       = [ordered]@{}
	}
}

function Invoke-BugSplatSdkTrustProposal {
	param(
		[string]$SourceRoot,
		[string[]]$PublisherSubjectContains = $Script:DefaultPublisherSubjectTokens
	)
	$sdk = Resolve-BugSplatSdkRoot -Root $SourceRoot
	$plan = Get-BugSplatImportPlan -SdkRoot $sdk
	$files = [ordered]@{}

	$incDir = Join-Path $sdk 'inc'
	foreach ($header in Get-ChildItem -LiteralPath $incDir -Filter '*.h' -File) {
		$rel = "inc/$($header.Name)"
		Assert-BugSplatAuthenticode -Path $header.FullName -RequireSignature:$false
		$files[$rel] = Get-BugSplatFileSha256 -Path $header.FullName
	}

	foreach ($lib in $plan.Libs) {
		$files[$lib.RelativePath] = Get-BugSplatFileSha256 -Path $lib.Source
	}
	foreach ($bin in $plan.Bins) {
		Assert-BugSplatAuthenticode -Path $bin.Source -PublisherSubjectContains $PublisherSubjectContains
		$files[$bin.RelativePath] = Get-BugSplatFileSha256 -Path $bin.Source
	}
	return @{ SdkRoot = $sdk; Plan = $plan; FileHashes = $files }
}

function Test-BugSplatCommittedSdkTree {
	param(
		[string]$DestRoot,
		[string]$ReferenceHashesPath
	)
	$loaded = Read-BugSplatReferenceHashes -Path $ReferenceHashesPath
	$reference = $loaded.Map
	if ($reference.Count -eq 0) {
		throw "SDK-HASHES.json has no file entries under $ReferenceHashesPath"
	}
	foreach ($rel in $reference.Keys) {
		$destFile = Join-Path $DestRoot ($rel -replace '/', [IO.Path]::DirectorySeparatorChar)
		if (-not (Test-Path -LiteralPath $destFile)) {
			throw "Committed SDK missing $rel at $destFile"
		}
		$null = Assert-BugSplatSourceMatchesReference -SourceFile $destFile -RelativePath $rel -ReferenceMap $reference
	}
	return $true
}

function Invoke-BugSplatSdkImport {
	param(
		[string]$SourceRoot,
		[string]$DestRoot,
		[string]$ReferenceHashesPath
	)
	$sdk = Resolve-BugSplatSdkRoot -Root $SourceRoot
	$loaded = Read-BugSplatReferenceHashes -Path $ReferenceHashesPath
	$reference = $loaded.Map
	$plan = Get-BugSplatImportPlan -SdkRoot $sdk

	$stageRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("bugsplat-import-{0}" -f [guid]::NewGuid().Guid)
	New-Item -ItemType Directory -Force -Path $stageRoot | Out-Null

	try {
		$incRelPaths = @($reference.Keys | Where-Object { $_ -like 'inc/*' })
		if ($incRelPaths.Count -eq 0) {
			throw 'SDK-HASHES.json has no inc/* entries; run establish-bugsplat-sdk-trust.ps1.'
		}
		$incDest = Join-Path $stageRoot 'inc'
		New-Item -ItemType Directory -Force -Path $incDest | Out-Null
		foreach ($rel in $incRelPaths) {
			$name = Split-Path $rel -Leaf
			$srcFile = Join-Path $sdk ("inc\$name")
			if (-not (Test-Path -LiteralPath $srcFile)) {
				throw "Source SDK missing $rel at $srcFile"
			}
			$null = Assert-BugSplatSourceMatchesReference -SourceFile $srcFile -RelativePath $rel -ReferenceMap $reference
			Copy-Item -Force $srcFile (Join-Path $incDest $name)
		}

		$manifest = @()
		foreach ($lib in $plan.Libs) {
			$null = Assert-BugSplatSourceMatchesReference -SourceFile $lib.Source -RelativePath $lib.RelativePath -ReferenceMap $reference
			$libDestDir = Join-Path $stageRoot ("x64\{0}\lib\mt" -f $lib.Config)
			New-Item -ItemType Directory -Force -Path $libDestDir | Out-Null
			Copy-Item -Force $lib.Source (Join-Path $libDestDir 'BugSplat.lib')
			$manifest += [pscustomobject]@{ Path = $lib.RelativePath; Sha256 = $reference[$lib.RelativePath] }
		}
		foreach ($bin in $plan.Bins) {
			Assert-BugSplatAuthenticode -Path $bin.Source
			$null = Assert-BugSplatSourceMatchesReference -SourceFile $bin.Source -RelativePath $bin.RelativePath -ReferenceMap $reference
			$binDest = Join-Path $stageRoot ("x64\{0}\bin" -f $bin.Config)
			New-Item -ItemType Directory -Force -Path $binDest | Out-Null
			Copy-Item -Force $bin.Source (Join-Path $binDest $bin.Name)
			$manifest += [pscustomobject]@{ Path = $bin.RelativePath; Sha256 = $reference[$bin.RelativePath] }
		}

		$null = Test-BugSplatCommittedSdkTree -DestRoot $stageRoot -ReferenceHashesPath $ReferenceHashesPath

		$manifestPath = Join-Path $stageRoot 'SDK-MANIFEST.json'
		$manifest | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

		$destParent = Split-Path -Parent $DestRoot
		$destName = Split-Path -Leaf $DestRoot
		$backup = Join-Path $destParent ("{0}.import-backup-{1}" -f $destName, [guid]::NewGuid().Guid)
		if (Test-Path -LiteralPath $DestRoot) {
			Move-Item -LiteralPath $DestRoot -Destination $backup -Force
		}
		try {
			Move-Item -LiteralPath $stageRoot -Destination $DestRoot -Force
			$stageRoot = $null
			if (Test-Path -LiteralPath $backup) {
				Remove-Item -LiteralPath $backup -Recurse -Force
			}
		} catch {
			if (Test-Path -LiteralPath $backup) {
				if (Test-Path -LiteralPath $DestRoot) {
					Remove-Item -LiteralPath $DestRoot -Recurse -Force
				}
				Move-Item -LiteralPath $backup -Destination $DestRoot -Force
			}
			throw
		}

		$manifestPath = Join-Path $DestRoot 'SDK-MANIFEST.json'
		return @{ ManifestPath = $manifestPath; DestRoot = $DestRoot; SdkRoot = $sdk }
	} finally {
		if ($stageRoot -and (Test-Path -LiteralPath $stageRoot)) {
			Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
		}
	}
}

function Throw-BugSplatSdkImportDiagnostics {
	param([string]$SdkRoot, [string]$Config)
	$lines = @(
		"Missing official x64\$Config\lib\mt\BugSplat.lib under $SdkRoot.",
		'',
		"Expected: Windows Native C++ SDK from $Script:BugSplatOfficialNativeUrl (login required).",
		'',
		'Common mistakes:'
	)
	if (Test-Path -LiteralPath (Join-Path $SdkRoot 'client\crashpad_client.h')) {
		$lines += '- Tree looks like BugSplat-Git/bugsplat-crashpad (Crashpad), not the Native SDK.'
	}
	if (Test-Path -LiteralPath (Join-Path $SdkRoot "x64\$Config\crashpad_handler.exe")) {
		$lines += '- Found crashpad_handler.exe: use the Native SDK zip, not bugsplat-crashpad GitHub releases.'
	}
	$flatLib = Join-Path $SdkRoot "x64\$Config\BugSplat.lib"
	if (Test-Path -LiteralPath $flatLib) {
		$kind = Get-BugSplatStaticLibCrtKind -Path $flatLib
		$lines += "- Found $flatLib (CRT probe: $kind). Samples are /MD; Envy requires lib\mt (/MT)."
	}
	throw ($lines -join [Environment]::NewLine)
}

Export-ModuleMember -Function @(
	'Resolve-BugSplatSdkRoot',
	'Find-BugSplatLibMt',
	'Get-BugSplatStaticLibCrtKind',
	'Assert-BugSplatLibMtCrt',
	'Get-BugSplatFileSha256',
	'Read-BugSplatReferenceHashes',
	'Assert-BugSplatSourceMatchesReference',
	'Assert-BugSplatAuthenticode',
	'Get-BugSplatImportPlan',
	'New-BugSplatTrustDocumentSkeleton',
	'Invoke-BugSplatSdkTrustProposal',
	'Invoke-BugSplatSdkImport',
	'Test-BugSplatCommittedSdkTree',
	'Throw-BugSplatSdkImportDiagnostics'
)
