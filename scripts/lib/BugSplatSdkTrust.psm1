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
	if ($kind -ne $expect -and $kind -ne 'unknown') {
		Write-Warning "CRT probe for $LibPath returned $kind (expected $expect). Verify lib\mt from the official Native SDK."
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

	Assert-BugSplatAuthenticode -Path $plan.Header -RequireSignature:$false
	$files['inc/BugSplat.h'] = Get-BugSplatFileSha256 -Path $plan.Header

	foreach ($lib in $plan.Libs) {
		$files[$lib.RelativePath] = Get-BugSplatFileSha256 -Path $lib.Source
	}
	foreach ($bin in $plan.Bins) {
		Assert-BugSplatAuthenticode -Path $bin.Source -PublisherSubjectContains $PublisherSubjectContains
		$files[$bin.RelativePath] = Get-BugSplatFileSha256 -Path $bin.Source
	}
	return @{ SdkRoot = $sdk; Plan = $plan; FileHashes = $files }
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

	New-Item -ItemType Directory -Force -Path $DestRoot | Out-Null

	$null = Assert-BugSplatSourceMatchesReference -SourceFile $plan.Header -RelativePath 'inc/BugSplat.h' -ReferenceMap $reference
	$incDest = Join-Path $DestRoot 'inc'
	if (Test-Path $incDest) { Remove-Item -Recurse -Force $incDest }
	Copy-Item -Recurse -Force (Join-Path $sdk 'inc') $incDest

	$manifest = @()
	foreach ($lib in $plan.Libs) {
		$null = Assert-BugSplatSourceMatchesReference -SourceFile $lib.Source -RelativePath $lib.RelativePath -ReferenceMap $reference
		$libDestDir = Join-Path $DestRoot ("x64\{0}\lib\mt" -f $lib.Config)
		New-Item -ItemType Directory -Force -Path $libDestDir | Out-Null
		Copy-Item -Force $lib.Source (Join-Path $libDestDir 'BugSplat.lib')
		$manifest += [pscustomobject]@{ Path = $lib.RelativePath; Sha256 = $reference[$lib.RelativePath] }
	}
	foreach ($bin in $plan.Bins) {
		Assert-BugSplatAuthenticode -Path $bin.Source
		$null = Assert-BugSplatSourceMatchesReference -SourceFile $bin.Source -RelativePath $bin.RelativePath -ReferenceMap $reference
		$binDest = Join-Path $DestRoot ("x64\{0}\bin" -f $bin.Config)
		New-Item -ItemType Directory -Force -Path $binDest | Out-Null
		Copy-Item -Force $bin.Source (Join-Path $binDest $bin.Name)
		$manifest += [pscustomobject]@{ Path = $bin.RelativePath; Sha256 = $reference[$bin.RelativePath] }
	}

	$manifestPath = Join-Path $DestRoot 'SDK-MANIFEST.json'
	$manifest | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
	return @{ ManifestPath = $manifestPath; DestRoot = $DestRoot; SdkRoot = $sdk }
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
	'Throw-BugSplatSdkImportDiagnostics'
)
