[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Path,
    [string]$OutputPath = ".\findings.json",
    [string]$ExternalFindingsPath,
    [Parameter(Mandatory=$true)][string]$CandidateRegexPath,
    [ValidateSet('Line','WholeFile')][string]$RegexScope = 'Line',
    [switch]$RunTruffleHog,
    [string]$TruffleHogCommand = 'trufflehog',
    [switch]$RunBetterLeaks,
    [string]$BetterLeaksCommand = 'betterleaks',
    # Replace/extend with the existing production regex terms. Do not narrow production rules.
    [string[]]$Keywords = @(
        'password','passwd','pass','pwd','secret','api[_ -]?key',
        'access[_ -]?key','private[_ -]?key','token','credential',
        'motdepasse','contrasena','contraseña','passwort','senha','parola'
    ),
    [long]$MaxFileBytes = 2097152
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'


function Get-Field($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}


function Get-DetectedSecret($Object) {
    # Scanner schemas vary by version. Inspect only known value-bearing fields and
    # never stringify an arbitrary object into the report.
    foreach ($name in @('Raw','RawV2','Secret','secret','raw','value','Value')) {
        $value = Get-Field $Object $name
        if ($value -is [string] -and -not [string]::IsNullOrEmpty($value)) { return $value }
    }
    foreach ($parentName in @('Match','match','Data','data')) {
        $parent = Get-Field $Object $parentName
        if ($null -eq $parent) { continue }
        foreach ($name in @('Secret','secret','Raw','raw','Value','value','Text','text')) {
            $value = Get-Field $parent $name
            if ($value -is [string] -and -not [string]::IsNullOrEmpty($value)) { return $value }
        }
    }
    return $null
}

function New-SecretRecord([string]$Scanner, [string]$SecretValue) {
    if ([string]::IsNullOrEmpty($SecretValue)) { return $null }
    $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($SecretValue)))
    return [pscustomobject]@{ Scanner=$Scanner; Secret=$SecretValue; Hash=$hash }
}

function Invoke-CapturedCommand([string]$Command, [string[]]$Arguments) {
    # Keep potentially sensitive scanner output out of the terminal and persistent files.
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $Command
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    foreach ($arg in $Arguments) { [void]$psi.ArgumentList.Add($arg) }
    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    if (-not $proc.Start()) { throw "Could not start scanner executable: $Command" }
    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderrTask = $proc.StandardError.ReadToEndAsync()
    $proc.WaitForExit()
    return [pscustomobject]@{
        ExitCode = $proc.ExitCode
        StdOut = $stdoutTask.GetAwaiter().GetResult()
        StdErr = $stderrTask.GetAwaiter().GetResult()
    }
}

function Resolve-ScanPath([string]$FilePath) {
    if ([string]::IsNullOrWhiteSpace($FilePath)) { return $null }
    try {
        if ([IO.Path]::IsPathRooted($FilePath)) {
            return [IO.Path]::GetFullPath($FilePath)
        }

        # Scanner reports may use either slash convention, regardless of host OS.
        $relativePath = $FilePath.Replace('/', [string][IO.Path]::DirectorySeparatorChar).Replace('\', [string][IO.Path]::DirectorySeparatorChar)

        # Prefer the source-relative path under the scan root.
        $candidate = [IO.Path]::GetFullPath((Join-Path $resolved $relativePath))
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }

        # Some tools include the scan-root directory name in their relative path.
        $rootName = Split-Path -Leaf $resolved
        $prefix = $rootName + [IO.Path]::DirectorySeparatorChar
        if ($relativePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            $trimmed = $relativePath.Substring($prefix.Length)
            $candidate = [IO.Path]::GetFullPath((Join-Path $resolved $trimmed))
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
        }

        # Still normalize relative paths against the scan root even if the file no longer exists.
        return [IO.Path]::GetFullPath((Join-Path $resolved $relativePath))
    } catch {
        return $FilePath
    }
}

function Test-PathWithinScanRoot([string]$CandidatePath) {
    if ([string]::IsNullOrWhiteSpace($CandidatePath)) { return $false }
    try { $candidateFull = [IO.Path]::GetFullPath($CandidatePath) } catch { return $false }
    if (-not $rootIsDirectory) {
        return $candidateFull.Equals($resolved, $pathComparison)
    }
    $rootPrefix = $resolved.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    return $candidateFull.StartsWith($rootPrefix, $pathComparison)
}

function Add-NormalizedExternalFinding([string]$FilePath, $LineNumber, $Start, $Length, [string]$Scanner, [string]$Rule, [string]$SecretValue) {
    if ([string]::IsNullOrWhiteSpace($FilePath) -or [string]::IsNullOrWhiteSpace($Scanner)) { return }
    $parsedLine = 0
    if (-not [int]::TryParse([string]$LineNumber, [ref]$parsedLine) -or $parsedLine -lt 1) { return }
    $parsedStart = -1
    $parsedLength = 0
    $candidateStart = 0
    if ($null -ne $Start -and [int]::TryParse([string]$Start, [ref]$candidateStart) -and $candidateStart -ge 0) { $parsedStart = $candidateStart }
    $candidateLength = 0
    if ($null -ne $Length -and [int]::TryParse([string]$Length, [ref]$candidateLength) -and $candidateLength -gt 0) { $parsedLength = $candidateLength }
    $normalizedPath = Resolve-ScanPath $FilePath
    if (-not (Test-PathWithinScanRoot $normalizedPath)) { return }
    # Scanner-produced rule labels are untrusted output too. Hash them before they
    # enter normalized JSON: this preserves stable correlation without echoing arbitrary
    # tool-controlled text that could contain a credential-shaped value.
    $ruleLabel = if ([string]::IsNullOrWhiteSpace($Rule)) { 'External' } else { $Rule }
    $ruleBytes = [Text.Encoding]::UTF8.GetBytes($ruleLabel)
    $ruleDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($ruleBytes)).Substring(0,12)
    $safeRule = $Scanner + '-Rule-' + $ruleDigest
    $raw.Add([pscustomobject]@{
        File=$normalizedPath; Line=$parsedLine
        Start=$parsedStart; Length=$parsedLength
        IdentityStart=-1; IdentityLength=0
        Scanner=$Scanner; SourceScanner=$Scanner; Rule=$safeRule
        Context='Unknown'; Literal=$null; SecretValue=$SecretValue
    })
}

function Get-Context([string]$Line) {
    # Ordering matters: classify runtime references before generic assignments.
    if ($Line -match '(?i)(GetEnvironmentVariable|Get-Item Env:|\$env:|os\.environ|process\.env|getenv\(|\$\{[^}]+\}|get_secret\(|secretmanager|keyvault|vault\.)') {
        return 'RuntimeReference'
    }
    if ($Line -match '(?i)\b(logger|logging|console|write-host|write-output|printf|println|print)\s*[\.(]') {
        return 'Logging'
    }
    if ($Line -match '^\s*(#|//|/\*|\*|<!--)') { return 'Comment' }
    if ($Line -match '(?i)(password|passwd|pass|pwd|secret|api[_ -]?key|access[_ -]?key|private[_ -]?key|token|credential|motdepasse|contrasena|contraseña|passwort|senha|parola)\w*\s*[:=]\s*["'']') {
        return 'LiteralAssignment'
    }
    return 'Unknown'
}

function Get-Literal([string]$Line, [string]$KeywordPattern) {
    $m = [regex]::Match($Line, '(?i)(?:' + $KeywordPattern + ')\w*\s*[:=]\s*["'']([^"'']{1,1000})["'']')
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

function Get-Entropy([string]$Value) {
    if ([string]::IsNullOrEmpty($Value)) { return 0.0 }
    $counts = @{}
    foreach ($c in $Value.ToCharArray()) {
        $k = [string]$c
        if (!$counts.ContainsKey($k)) { $counts[$k] = 0 }
        $counts[$k]++
    }
    $h = 0.0
    foreach ($n in $counts.Values) {
        $p = $n / $Value.Length
        $h -= $p * [Math]::Log($p, 2)
    }
    return $h
}

function Test-Placeholder([string]$Value) {
    if ([string]::IsNullOrEmpty($Value)) { return $false }
    return $Value -match '(?i)^(changeme|change_me|example|placeholder|your[-_ ]?(api[-_ ]?)?key|your[-_ ]?password|<[^>]+>|\$\{[^}]+\}|xxx+|dummy|sample|test)$'
}

function Get-Assessment([string[]]$Scanners, [string]$Context, [string]$Value) {
    $score = 15
    $reasons = [System.Collections.Generic.List[string]]::new()
    # Only findings parsed directly from the known scanner adapters count as independent
    # scanner evidence. ExternalImport is provenance, not a detector, and must not boost score.
    $independentScanners = @($Scanners | Where-Object { $_ -in @('TruffleHog','BetterLeaks') } | Sort-Object -Unique)
    $score += [Math]::Min(20, 10 * $independentScanners.Count)
    if ($Scanners -contains 'Regex') { $reasons.Add('KEYWORD_MATCH') }
    if ($independentScanners.Count) { $reasons.Add('ADDITIONAL_SCANNER_EVIDENCE') }

    switch ($Context) {
        'LiteralAssignment' { $score += 20; $reasons.Add('LITERAL_ASSIGNMENT') }
        'Logging' { $score -= 25; $reasons.Add('LOGGING_CONTEXT') }
        'Comment' { $score -= 10; $reasons.Add('COMMENT_CONTEXT') }
        'RuntimeReference' { $score -= 20; $reasons.Add('RUNTIME_REFERENCE') }
        default { $reasons.Add('CONTEXT_UNKNOWN') }
    }

    if (![string]::IsNullOrEmpty($Value)) {
        $entropy = Get-Entropy $Value
        # Strong secret-shaped literal signal; entropy is supporting evidence, never a rejection gate.
        if ($Value.Length -ge 12 -and $entropy -ge 3.5) {
            $score += 25; $reasons.Add('HIGH_ENTROPY_LITERAL')
        } elseif ($Value.Length -ge 8 -and $entropy -ge 2.5) {
            $score += 12; $reasons.Add('MODERATE_ENTROPY_LITERAL')
        } else { $reasons.Add('LOW_ENTROPY_OR_SHORT_LITERAL') }

        if (Test-Placeholder $Value) {
            $score -= 35; $reasons.Add('PLACEHOLDER_PATTERN')
        }
    } else { $reasons.Add('NO_LITERAL_EXTRACTED') }

    $score = [Math]::Max(0, [Math]::Min(100, $score))
    $tier = if ($score -ge 65) { 'High' } elseif ($score -ge 35) { 'Review' } else { 'Low' }
    return [pscustomobject]@{ Score=[int]$score; Tier=$tier; Reasons=@($reasons) }
}

# Keep literal-extraction keywords separate from candidate generation.
# CandidateRegexPath is mandatory. Its regex body is used as-is (only terminal CR/LF
# delimiters are removed); scanner integration must not rewrite production rules.
$keywordPattern = '(?:' + (($Keywords | ForEach-Object { '(?:' + $_ + ')' }) -join '|') + ')'
# Candidate generation must always use the caller-supplied production regex.
# Do not silently fall back to a different keyword regex: that would change recall.
$candidateRegexResolved = (Resolve-Path -LiteralPath $CandidateRegexPath).Path
$candidatePattern = [IO.File]::ReadAllText($candidateRegexResolved)
$candidatePattern = $candidatePattern.TrimEnd([char[]]@([char]13, [char]10))
if ([string]::IsNullOrEmpty($candidatePattern)) {
    throw 'CandidateRegexPath must contain the existing production regex; an empty pattern is unsafe.'
}
# Do not add IgnoreCase or any other option to the supplied production pattern.
$keywordRegex = [regex]::new($candidatePattern)
$raw = [System.Collections.Generic.List[object]]::new()

$resolved = (Resolve-Path -LiteralPath $Path).Path
$externalFindingsResolved = $null
if ($ExternalFindingsPath) {
    $externalFindingsResolved = (Resolve-Path -LiteralPath $ExternalFindingsPath).Path
}
$outputResolved = [IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $outputResolved -PathType Container) {
    throw 'OutputPath must name a file, not an existing directory.'
}
$rootIsDirectory = Test-Path -LiteralPath $resolved -PathType Container
$pathComparison = if ([IO.Path]::DirectorySeparatorChar -eq [char]92) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
$outputInsideRoot = $false
if ($rootIsDirectory) {
    $rootPrefix = $resolved.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $outputInsideRoot = $outputResolved.Equals($resolved, $pathComparison) -or $outputResolved.StartsWith($rootPrefix, $pathComparison)
} else {
    $outputInsideRoot = $outputResolved.Equals($resolved, $pathComparison)
}
if (($RunTruffleHog -or $RunBetterLeaks) -and $outputInsideRoot) {
    throw 'When external scanners are enabled, OutputPath must be outside the scan root to avoid scanning prior/generated findings.'
}
if ($RunTruffleHog -or $RunBetterLeaks) {
    if ($candidateRegexResolved -and (Test-PathWithinScanRoot $candidateRegexResolved)) {
        throw 'When external scanners are enabled, CandidateRegexPath must be outside the scan root; these tools scan the root independently of local file exclusions.'
    }
    if ($externalFindingsResolved -and (Test-PathWithinScanRoot $externalFindingsResolved)) {
        throw 'When external scanners are enabled, ExternalFindingsPath must be outside the scan root; these tools scan the root independently of local file exclusions.'
    }
}
$files = if (-not $rootIsDirectory) {
    @(Get-Item -LiteralPath $resolved)
} else { @(Get-ChildItem -LiteralPath $resolved -File -Recurse) }
# Exclude scanner control artifacts from the source walk. Otherwise the regex file,
# an imported findings manifest, or a previous report can create self-inflicted findings.
$pathComparer = if ($pathComparison -eq [StringComparison]::OrdinalIgnoreCase) {
    [StringComparer]::OrdinalIgnoreCase
} else {
    [StringComparer]::Ordinal
}
$excludedInputs = [System.Collections.Generic.HashSet[string]]::new($pathComparer)
[void]$excludedInputs.Add($outputResolved)
if ($candidateRegexResolved) {
    [void]$excludedInputs.Add([IO.Path]::GetFullPath($candidateRegexResolved))
}
if ($externalFindingsResolved) {
    [void]$excludedInputs.Add([IO.Path]::GetFullPath($externalFindingsResolved))
}
$files = @($files | Where-Object {
    -not $excludedInputs.Contains([IO.Path]::GetFullPath($_.FullName))
})

# Optional local scanner integrations. Both run in detection-only mode.
# TruffleHog JSONL may contain secrets; parse in memory and do not persist raw output.
if ($RunTruffleHog) {
    $th = Invoke-CapturedCommand -Command $TruffleHogCommand -Arguments @('--no-update', 'filesystem', '--no-verification', '--json', $resolved)
    if ($th.ExitCode -ne 0) { throw "TruffleHog failed (exit $($th.ExitCode)); captured output suppressed." }
    foreach ($line in ($th.StdOut -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try { $r = $line | ConvertFrom-Json } catch { continue }
        $sourceMeta = Get-Field $r 'SourceMetadata'
        if (-not $sourceMeta) { $sourceMeta = Get-Field $r 'sourceMetadata' }
        $data = Get-Field $sourceMeta 'Data'
        if (-not $data) { $data = Get-Field $sourceMeta 'data' }
        $meta = Get-Field $data 'Filesystem'
        if (-not $meta) { $meta = Get-Field $data 'filesystem' }
        $pathValue = Get-Field $meta 'file'
        if (-not $pathValue) { $pathValue = Get-Field $meta 'path' }
        $lineValue = Get-Field $meta 'line'
        $ruleValue = Get-Field $r 'DetectorName'
        if (-not $ruleValue) { $ruleValue = Get-Field $r 'detectorName' }
        if (-not $ruleValue) { $ruleValue = 'TruffleHog' }
        $secretValue = Get-DetectedSecret $r
        Add-NormalizedExternalFinding -FilePath $pathValue -LineNumber $lineValue -Start $null -Length $null -Scanner 'TruffleHog' -Rule $ruleValue -SecretValue $secretValue
    }
    Write-Host 'TruffleHog: completed (detection-only; raw output not persisted).'
}

if ($RunBetterLeaks) {
    # The .json suffix is required: BetterLeaks chooses report format from the filename extension.
    $betterReport = Join-Path ([IO.Path]::GetTempPath()) ('credential-scan-' + [guid]::NewGuid().ToString('N') + '.json')
    try {
        # Explicitly disable validation/analysis. Redaction is disabled only because the requested final report includes values;
        # the temporary report is parsed in memory and deleted in finally. Protect the final JSON as a secret-bearing artifact.
        $bl = Invoke-CapturedCommand -Command $BetterLeaksCommand -Arguments @('filesystem', $resolved, '--validate=false', '--analyze=false', '--redact=0', '--silent', '--output', $betterReport)
        if ($bl.ExitCode -ne 0) { throw "BetterLeaks failed (exit $($bl.ExitCode)); captured output suppressed." }
        if (-not (Test-Path -LiteralPath $betterReport)) { throw 'BetterLeaks did not create its JSON report.' }
        $report = Get-Content -LiteralPath $betterReport -Raw | ConvertFrom-Json
        $reportFindings = Get-Field $report 'findings'
        $scanMeta = Get-Field $report 'scan'
        $scanState = Get-Field $scanMeta 'state'
        if ($null -eq $reportFindings -or [string]::IsNullOrWhiteSpace([string]$scanState)) {
            throw 'BetterLeaks JSON schema mismatch: expected findings and scan.state.'
        }
        foreach ($f in @($reportFindings)) {
            $loc = Get-Field $f 'location'
            $pathValue = Get-Field $loc 'path'
            if (-not $pathValue) { $pathValue = Get-Field $f 'path' }
            # BetterLeaks v2 uses start_line/start_column/end_column. Columns are byte-based,
            # while the local regex uses .NET character indices; do not compare unlike offsets.
            $lineValue = Get-Field $loc 'start_line'
            if ($null -eq $lineValue) { $lineValue = Get-Field $loc 'line' }
            if ($null -eq $lineValue) { $lineValue = Get-Field $f 'line' }
            $startValue = $null
            $lengthValue = $null
            $ruleValue = Get-Field $f 'rule_id'
            if (-not $ruleValue) { $ruleValue = Get-Field $f 'rule' }
            if (-not $ruleValue) { $ruleValue = 'BetterLeaks' }
            $secretValue = Get-DetectedSecret $f
            Add-NormalizedExternalFinding -FilePath $pathValue -LineNumber $lineValue -Start $startValue -Length $lengthValue -Scanner 'BetterLeaks' -Rule $ruleValue -SecretValue $secretValue
        }
        if ($scanState -ne 'complete') {
            throw "BetterLeaks scan state is '$scanState'; findings may be incomplete."
        }
    } finally {
        Remove-Item -LiteralPath $betterReport -Force -ErrorAction SilentlyContinue
    }
    Write-Host 'BetterLeaks: completed (detection-only; temporary redacted report deleted).'
}

foreach ($file in $files) {
    if ($file.Length -gt $MaxFileBytes) { continue }
    $bytes = [IO.File]::ReadAllBytes($file.FullName)
    if ($bytes -contains 0) { continue }
    try { $content = [Text.UTF8Encoding]::new($false, $true).GetString($bytes) } catch { continue }
    $lines = $content -split "\r?\n"
    # Absolute character offsets provide stable identity across line-local presentation.
    $lineStarts = [System.Collections.Generic.List[int]]::new()
    $lineStarts.Add(0)
    for ($pos = 0; $pos -lt $content.Length; $pos++) {
        if ($content[$pos] -eq "`n") { $lineStarts.Add($pos + 1) }
    }
    if ($RegexScope -eq 'WholeFile') {
        # Match the regex against the original decoded file content, preserving anchors,
        # lookarounds, and newline-sensitive behavior from whole-content scanners.
        foreach ($m in $keywordRegex.Matches($content)) {
            $lineIndex = $lineStarts.BinarySearch([int]$m.Index)
            if ($lineIndex -lt 0) { $lineIndex = (-$lineIndex) - 2 }
            $lineIndex = [Math]::Max(0, [Math]::Min($lineIndex, $lines.Count - 1))

            $endPosition = if ($m.Length -gt 0) { $m.Index + $m.Length - 1 } else { $m.Index }
            $endLineIndex = $lineStarts.BinarySearch([int]$endPosition)
            if ($endLineIndex -lt 0) { $endLineIndex = (-$endLineIndex) - 2 }
            $endLineIndex = [Math]::Max(0, [Math]::Min($endLineIndex, $lines.Count - 1))

            $line = $lines[$lineIndex]
            $context = Get-Context $line
            $literal = if ($context -eq 'LiteralAssignment') { Get-Literal $line $keywordPattern } else { $null }
            # A cross-line match is retained as a candidate, but its length is set to zero
            # for same-line fusion because its range cannot be compared safely to line offsets.
            $mergeLength = if ($endLineIndex -eq $lineIndex) { $m.Length } else { 0 }
            $raw.Add([pscustomobject]@{
                File=$file.FullName; Line=$lineIndex+1
                Start=($m.Index - $lineStarts[$lineIndex]); Length=$mergeLength
                IdentityStart=$m.Index; IdentityLength=$m.Length
                Scanner='Regex'; SourceScanner='Regex'; Rule='KeywordRegex'; Context=$context; Literal=$literal; SecretValue=$literal
            })
        }
    } else {
        # Line mode preserves the prototype's prior matching scope.
        for ($i=0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            $context = Get-Context $line
            $literal = if ($context -eq 'LiteralAssignment') { Get-Literal $line $keywordPattern } else { $null }
            foreach ($m in $keywordRegex.Matches($line)) {
                $lineStartIndex = [Math]::Min($i, $lineStarts.Count - 1)
                $raw.Add([pscustomobject]@{
                    File=$file.FullName; Line=$i+1; Start=$m.Index; Length=$m.Length
                    IdentityStart=($lineStarts[$lineStartIndex] + $m.Index); IdentityLength=$m.Length
                    Scanner='Regex'; SourceScanner='Regex'; Rule='KeywordRegex'; Context=$context; Literal=$literal; SecretValue=$literal
                })
            }
        }
    }
}

# Optional normalized external findings:
# [{"file":"repo/file.py","line":4,"start":0,"length":8,"scanner":"TruffleHog","rule":"generic-api-key"}]
if ($externalFindingsResolved) {
    $external = @(Get-Content -LiteralPath $externalFindingsResolved -Raw | ConvertFrom-Json)
    foreach ($f in $external) {
        # Treat normalized JSON as untrusted input; missing fields should skip one row, not abort the scan.
        $externalFile = Get-Field $f 'file'
        $externalLine = Get-Field $f 'line'
        $externalScanner = Get-Field $f 'scanner'
        $parsedExternalLine = 0
        if ([string]::IsNullOrWhiteSpace([string]$externalFile) -or -not [int]::TryParse([string]$externalLine, [ref]$parsedExternalLine) -or $parsedExternalLine -lt 1 -or [string]::IsNullOrWhiteSpace([string]$externalScanner)) { continue }
        $externalStart = Get-Field $f 'start'
        $externalLength = Get-Field $f 'length'
        $parsedExternalStart = -1
        $parsedExternalLength = 0
        $startCandidate = 0
        $lengthCandidate = 0
        if ($null -ne $externalStart -and [int]::TryParse([string]$externalStart, [ref]$startCandidate) -and $startCandidate -ge 0) { $parsedExternalStart = $startCandidate }
        if ($null -ne $externalLength -and [int]::TryParse([string]$externalLength, [ref]$lengthCandidate) -and $lengthCandidate -gt 0) { $parsedExternalLength = $lengthCandidate }
        # The JSON manifest is untrusted: its scanner label is a claim, not proof that
        # the named tool actually produced this row. Keep the import channel distinct so
        # a row cannot impersonate Regex/TruffleHog/BetterLeaks or inflate independent-source scoring.
        $sourceScannerRaw = ([string]$externalScanner).Trim()
        # Keep only familiar labels readable. Unknown labels are represented by a stable
        # digest, so a malicious manifest cannot smuggle a credential into provenance text.
        if ($sourceScannerRaw -in @('Regex','TruffleHog','BetterLeaks','ExternalImport')) {
            $sourceScannerClaim = $sourceScannerRaw
        } else {
            $sourceBytes = [Text.Encoding]::UTF8.GetBytes($sourceScannerRaw)
            $sourceDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($sourceBytes)).Substring(0,12)
            $sourceScannerClaim = 'ImportedSource-' + $sourceDigest
        }
        # Rule names from imported JSON are untrusted too. Hash rather than echo them;
        # direct scanner adapters retain their native rule IDs because they are parsed in-process.
        $externalRuleRaw = [string](Get-Field $f 'rule')
        $externalRule = 'External'
        if (-not [string]::IsNullOrWhiteSpace($externalRuleRaw)) {
            $ruleBytes = [Text.Encoding]::UTF8.GetBytes($externalRuleRaw)
            $ruleDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($ruleBytes)).Substring(0,12)
            $externalRule = 'ImportedRule-' + $ruleDigest
        }
        # Imported context is an unverified claim and must not affect assessment or override
        # context derived locally from source text. Keep imported rows context-neutral.
        $externalContext = 'Unknown'
        $normalizedExternalPath = Resolve-ScanPath ([string]$externalFile)
        if (-not (Test-PathWithinScanRoot $normalizedExternalPath)) { continue }
        $raw.Add([pscustomobject]@{
            File=$normalizedExternalPath; Line=$parsedExternalLine
            Start=$parsedExternalStart
            Length=$parsedExternalLength
            IdentityStart=-1; IdentityLength=0
            Scanner='ExternalImport'; SourceScanner=$sourceScannerClaim
            Rule=if ($externalRule) { [string]$externalRule } else { 'External' }
            Context=if ($externalContext) { [string]$externalContext } else { 'Unknown' }
            Literal=$null; SecretValue=([string](Get-Field $f 'secret'))
        })
    }
}

# Conservative same-line merge. If an external result has no offsets, attach it only
# when exactly one local candidate exists on that line; otherwise preserve it separately.
$findings = [System.Collections.Generic.List[object]]::new()
$caseSensitivePaths = ([IO.Path]::DirectorySeparatorChar -ne [char]92)
$lineGroups = $raw | Group-Object {
    $pathKey = if ($caseSensitivePaths) { $_.File } else { $_.File.ToLowerInvariant() }
    "$pathKey|$($_.Line)"
}
foreach ($g in $lineGroups) {
    $clusters = [System.Collections.Generic.List[object]]::new()
    # Build one cluster per regex match first. External evidence is enriched afterward;
    # regex candidates must never merge with one another, even when their ranges overlap.
    $orderedGroup = @($g.Group | Sort-Object `
        @{Expression={ if ($_.Scanner -eq 'Regex') { 0 } else { 1 } }}, `
        @{Expression={ if ($_.Start -ge 0) {$_.Start} else {[int]::MaxValue} }}, `
        @{Expression={ [string]$_.Scanner }}, `
        @{Expression={ [string]$_.SourceScanner }}, `
        @{Expression={ [string]$_.Rule }})
    foreach ($f in $orderedGroup) {
        $target = $null
        if ($f.Scanner -eq 'Regex') {
            # Candidate generation is sacrosanct: each regex match gets its own cluster.
            $target = $null
        } else {
            $regexClusters = @($clusters | Where-Object { $_.Evidence.Scanner -contains 'Regex' })
            if ($f.Start -lt 0 -or $f.Length -le 0) {
                # Offset-less evidence enriches only one candidate with a comparable same-line range.
                # Length zero includes cross-line and zero-width regex matches, so keep those separate.
                $mergeableRegexClusters = @($regexClusters | Where-Object { $_.AnchorLength -gt 0 })
                if ($mergeableRegexClusters.Count -eq 1 -and $regexClusters.Count -eq 1) { $target = $mergeableRegexClusters[0] }
            } else {
                # Merge only when exactly one existing cluster overlaps. Ranges are half-open:
                # [start, end), so merely touching endpoints do not overlap.
                $overlapping = [System.Collections.Generic.List[object]]::new()
                foreach ($c in $clusters) {
                    # Compare against the immutable first-evidence range, not an expanded union.
                    # This prevents A↔B↔C overlap chains from collapsing distinct findings.
                    if ($c.AnchorStart -lt 0 -or $c.AnchorLength -le 0) { continue }
                    $cEnd = $c.AnchorStart + $c.AnchorLength
                    $fEnd = $f.Start + $f.Length
                    if ($f.Start -lt $cEnd -and $fEnd -gt $c.AnchorStart) { $overlapping.Add($c) }
                }
                if ($overlapping.Count -eq 1) { $target = $overlapping[0] }
            }
        }

        if ($null -eq $target) {
            $target = [pscustomobject]@{
                File=$f.File; Line=$f.Line; Start=$f.Start; Length=$f.Length
                AnchorStart=$f.Start; AnchorLength=$f.Length
                AnchorIdentityStart=$f.IdentityStart; AnchorIdentityLength=$f.IdentityLength
                Context=$f.Context; Literal=$f.Literal
                Evidence=[System.Collections.Generic.List[object]]::new()
            }
            $clusters.Add($target)
        } else {
            if ($f.Start -ge 0) {
                $oldEnd=$target.Start+[Math]::Max(0,$target.Length)
                $newEnd=$f.Start+[Math]::Max(0,$f.Length)
                $newStart=[Math]::Min($target.Start,$f.Start)
                $target.Start=$newStart; $target.Length=[Math]::Max($oldEnd,$newEnd)-$newStart
            }
            if ($target.Context -eq 'Unknown' -and $f.Context -ne 'Unknown') { $target.Context=$f.Context }
            if ([string]::IsNullOrEmpty($target.Literal) -and ![string]::IsNullOrEmpty($f.Literal)) { $target.Literal=$f.Literal }
        }
        $sourceScanner = if ($f.PSObject.Properties['SourceScanner'] -and $f.SourceScanner) { [string]$f.SourceScanner } else { [string]$f.Scanner }
        $secretRecord = New-SecretRecord -Scanner ([string]$f.Scanner) -SecretValue ([string]$f.SecretValue)
        $target.Evidence.Add([pscustomobject]@{
            Scanner=$f.Scanner; SourceScanner=$sourceScanner; Rule=$f.Rule
            SecretRecord=$secretRecord
        })
    }

    # Offset-less evidence can be genuinely ambiguous: two detections on the same
    # line may refer to different secrets. Keep them separate, but give each a unique,
    # deterministic fingerprint suffix rather than emitting colliding IDs.
    $unlocatedOccurrence = 0
    foreach ($c in $clusters) {
        $scanners=@($c.Evidence.Scanner | Sort-Object -Unique)
        $a=Get-Assessment -Scanners $scanners -Context $c.Context -Value $c.Literal
        # Stable location fingerprint: adding scanner evidence must not change a regex candidate ID.
        # Use the immutable anchor, not the expanded display range; include length to avoid same-start collisions.
        $fingerprintPath = if ($caseSensitivePaths) { $c.File } else { $c.File.ToLowerInvariant() }
        if ($c.Evidence.Scanner -contains 'Regex') {
            $identityStart = $c.AnchorIdentityStart
            $identityLength = $c.AnchorIdentityLength
        } else {
            $identityStart = $c.AnchorStart
            $identityLength = $c.AnchorLength
        }
        $id="$fingerprintPath|$($c.Line)|$identityStart|$identityLength"
        if (-not ($c.Evidence.Scanner -contains 'Regex')) {
            $id += "|external|$((@($c.Evidence.Scanner | Sort-Object -Unique) -join ','))|$((@($c.Evidence.SourceScanner | Sort-Object -Unique) -join ','))|$((@($c.Evidence.Rule | Sort-Object -Unique) -join ','))"
            # Comparable positive-length ranges should already have been conservatively
            # merged. For offset-less/zero-length rows, do not deduplicate by line alone:
            # that could hide distinct findings. Make their IDs unique instead.
            if ($identityStart -lt 0 -or $identityLength -le 0) {
                $id += "|unlocated-occurrence|$unlocatedOccurrence"
                $unlocatedOccurrence++
            }
        }
        $fingerprint=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($id))).Substring(0,20)
        $directScannerChannels = @($scanners | Where-Object { $_ -in @('Regex','TruffleHog','BetterLeaks') } | Sort-Object -Unique)
        $secretRecords = @(
            $c.Evidence |
                Where-Object { $null -ne $_.SecretRecord -and -not [string]::IsNullOrEmpty($_.SecretRecord.Secret) } |
                ForEach-Object { $_.SecretRecord } |
                Group-Object { "$($_.Scanner)|$($_.Hash)" } |
                ForEach-Object { $_.Group[0] } |
                Sort-Object Scanner, Hash
        )
        $findings.Add([pscustomobject]@{
            Fingerprint=$fingerprint; File=$c.File; Line=$c.Line; Start=$c.Start; Length=$c.Length
            MatchStart=if ($c.Evidence.Scanner -contains 'Regex') { $c.AnchorIdentityStart } else { $null }
            MatchLength=if ($c.Evidence.Scanner -contains 'Regex') { $c.AnchorIdentityLength } else { $null }
            Scanners=$scanners; ScannerCount=$directScannerChannels.Count; EvidenceChannelCount=$scanners.Count
            SourceClaims=@($c.Evidence.SourceScanner | Sort-Object -Unique)
            Evidence=@($c.Evidence | ForEach-Object { [pscustomobject]@{ Scanner=$_.Scanner; SourceScanner=$_.SourceScanner; Rule=$_.Rule } })
            Secrets=$secretRecords
            Context=$c.Context; Score=$a.Score; Tier=$a.Tier; Reasons=$a.Reasons
        })
    }
}

$out=@($findings | Sort-Object Score -Descending)
$out | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $OutputPath -Encoding utf8
Write-Host "Raw candidates: $($raw.Count)"
Write-Host "Merged findings: $($out.Count)"
Write-Host "Wrote: $OutputPath"
$out | Group-Object Tier | Select-Object @{N='Tier';E={$_.Name}},Count | Format-Table -AutoSize
