[CmdletBinding()]
param(
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ADOPT31-G2 is deliberately a small, deterministic source gate rather than a
# claim that the broader G1 design taxonomy is already complete. It enforces
# direct literal design drift in Slint property assignments only:
#
# * colours must be Theme-derived; the existing components.slint shadow alpha
#   is the one path-specific compatibility exception;
# * font-family must be Theme-derived;
# * direct pixel font-size values are limited to the checked-in initial ramp;
# * direct pixel border radii are limited to the checked-in initial ramp.
#
# Theme.* expressions always pass. Root.u scaling expressions and bare zero
# radius are also an explicit initial subset: they are component-local geometry
# rather than a second font/radius token system. G3 owns the durable design
# documentation and any expansion of this subset.
$AllowedFontSizes = @('9px', '10px', '14px', '16px', '20px', '28px', '30px', '56px')
$AllowedRadii = @('0', '1px', '2px', '3px', '3.5px', '4px')
$ColorPropertyPattern = [regex]'(?is)(?<![\w-])(?<property>color|background|border-color|drop-shadow-color|value-color)\s*:\s*(?<value>.*)'
$ColorLiteralPattern = [regex]'(?i)#[0-9a-f]{3,8}\b|rgba?\s*\('
$FontFamilyStatementPattern = [regex]'(?is)\bfont-family\s*:\s*(?<value>.*)'
$ThemeFontFamilyPattern = [regex]'(?i)^Theme\.[A-Za-z_][A-Za-z0-9_-]*$'
$FontSizeStatementPattern = [regex]'(?is)\bfont-size\s*:\s*(?<value>.*)'
$RadiusStatementPattern = [regex]'(?is)\bborder-radius\s*:\s*(?<value>.*)'
$MetricLiteralPattern = [regex]'(?i)\d+(?:\.\d+)?\s*\*\s*root\.u|\d+(?:\.\d+)?(?:px|pt|em|rem|%)|\b0\b'

function Add-GuiLintFinding {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.List[object]] $Findings,
        [Parameter(Mandatory)] [string] $Rule,
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [int] $Line,
        [Parameter(Mandatory)] [string] $Value
    )

    $Findings.Add([pscustomobject]@{
            Rule = $Rule
            Path = $Path
            Line = $Line
            Value = $Value
        }) | Out-Null
}

function Test-AllowedRootScale {
    param([Parameter(Mandatory)] [string] $Value)
    return $Value -match '^\d+(?:\.\d+)?\*root\.u$'
}

function Get-ContainedSlintFiles {
    param([Parameter(Mandatory)] [string] $Root)

    $rootItem = Get-Item -LiteralPath $Root -Force
    if (-not $rootItem.PSIsContainer) {
        throw "GUI lint root is not a directory: $Root"
    }
    if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "GUI lint root must not be a reparse point: $Root"
    }
    $resolvedRoot = (Resolve-Path -LiteralPath $rootItem.FullName).Path
    $rootPrefix = $resolvedRoot.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ) + [System.IO.Path]::DirectorySeparatorChar
    $pendingDirectories = [System.Collections.Generic.Stack[string]]::new()
    $pendingDirectories.Push($resolvedRoot)
    $files = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    while ($pendingDirectories.Count -gt 0) {
        $directory = $pendingDirectories.Pop()
        foreach ($entry in @(Get-ChildItem -LiteralPath $directory -Force)) {
            if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "GUI lint rejects reparse-point source entries: $($entry.FullName)"
            }
            $resolvedEntry = (Resolve-Path -LiteralPath $entry.FullName).Path
            if (-not $resolvedEntry.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "GUI lint source escaped its root: $($entry.FullName)"
            }
            if ($entry.PSIsContainer) {
                $pendingDirectories.Push($entry.FullName)
            } elseif ($entry.Extension -ieq '.slint') {
                $files.Add($entry) | Out-Null
            }
        }
    }
    return [pscustomobject]@{
        Root = $resolvedRoot
        Files = @($files | Sort-Object -Property FullName)
    }
}

function Get-SlintStatements {
    param([Parameter(Mandatory)] [System.IO.FileInfo] $File)

    $pending = ''
    $statementLine = 1
    $lineNumber = 0
    $blockCommentDepth = 0
    $inString = $false
    $escaped = $false
    foreach ($line in Get-Content -LiteralPath $File.FullName) {
        $lineNumber += 1
        if ($pending.Trim().Length -eq 0) {
            $pending = ''
            $statementLine = $lineNumber
        }
        for ($index = 0; $index -lt $line.Length; $index += 1) {
            $character = $line[$index]
            if ($blockCommentDepth -gt 0) {
                if ($character -eq '/' -and $index + 1 -lt $line.Length -and $line[$index + 1] -eq '*') {
                    $blockCommentDepth += 1
                    $index += 1
                } elseif ($character -eq '*' -and $index + 1 -lt $line.Length -and $line[$index + 1] -eq '/') {
                    $blockCommentDepth -= 1
                    $index += 1
                }
                continue
            }
            if ($inString) {
                $pending += $character
                if ($escaped) {
                    $escaped = $false
                } elseif ($character -eq '\') {
                    $escaped = $true
                } elseif ($character -eq '"') {
                    $inString = $false
                }
                continue
            }
            if ($character -eq '/' -and $index + 1 -lt $line.Length) {
                if ($line[$index + 1] -eq '/') {
                    break
                }
                if ($line[$index + 1] -eq '*') {
                    $blockCommentDepth = 1
                    $index += 1
                    continue
                }
            }
            $pending += $character
            if ($character -eq '"') {
                $inString = $true
                continue
            }
            if ($character -eq ';') {
                $statement = $pending.Substring(0, $pending.Length - 1)
                if ($statement.Trim().Length -gt 0) {
                    [pscustomobject]@{
                        Text = $statement
                        Line = $statementLine
                    }
                }
                $pending = ''
                $statementLine = $lineNumber
            }
        }
        $pending += "`n"
    }
}

function Get-StatementLine {
    param(
        [Parameter(Mandatory)] $Statement,
        [Parameter(Mandatory)] [int] $Offset
    )
    return $Statement.Line + [regex]::Matches($Statement.Text.Substring(0, $Offset), "`n").Count
}

# ADOPT31-G5a intentionally reuses the G2 lexical boundary: comments and string
# literals are never executable evidence.  The returned mask keeps character
# offsets and newlines stable so a finding still names the source line.
function Get-ExecutableSlintSource {
    param(
        [Parameter(Mandatory)] [System.IO.FileInfo] $File,
        [switch] $KeepStringLiterals
    )

    $text = [System.IO.File]::ReadAllText($File.FullName)
    $masked = [System.Text.StringBuilder]::new($text.Length)
    $blockCommentDepth = 0
    $inString = $false
    $escaped = $false
    for ($index = 0; $index -lt $text.Length; $index += 1) {
        $character = $text[$index]
        $next = if ($index + 1 -lt $text.Length) { $text[$index + 1] } else { [char]0 }
        if ($blockCommentDepth -gt 0) {
            if ($character -eq '/' -and $next -eq '*') {
                $blockCommentDepth += 1
                [void]$masked.Append('  ')
                $index += 1
            } elseif ($character -eq '*' -and $next -eq '/') {
                $blockCommentDepth -= 1
                [void]$masked.Append('  ')
                $index += 1
            } else {
                [void]$masked.Append((if ($character -eq "`n") { "`n" } else { ' ' }))
            }
            continue
        }
        if ($inString) {
            [void]$masked.Append((if ($KeepStringLiterals) { $character } elseif ($character -eq "`n") { "`n" } else { ' ' }))
            if ($escaped) {
                $escaped = $false
            } elseif ($character -eq '\') {
                $escaped = $true
            } elseif ($character -eq '"') {
                $inString = $false
            }
            continue
        }
        if ($character -eq '/' -and $next -eq '/') {
            while ($index -lt $text.Length -and $text[$index] -ne "`n") {
                [void]$masked.Append(' ')
                $index += 1
            }
            if ($index -lt $text.Length) {
                [void]$masked.Append("`n")
            }
            continue
        }
        if ($character -eq '/' -and $next -eq '*') {
            $blockCommentDepth = 1
            [void]$masked.Append('  ')
            $index += 1
            continue
        }
        if ($character -eq '"') {
            $inString = $true
            [void]$masked.Append((if ($KeepStringLiterals) { $character } else { ' ' }))
            continue
        }
        [void]$masked.Append($character)
    }
    if ($blockCommentDepth -ne 0 -or $inString) {
        throw "GUI lint rejects unterminated comment or string: $($File.FullName)"
    }
    return $masked.ToString()
}

function Get-SourceLineNumber {
    param(
        [Parameter(Mandatory)] [string] $Text,
        [Parameter(Mandatory)] [int] $Offset
    )
    return 1 + [regex]::Matches($Text.Substring(0, $Offset), "`n").Count
}

function Get-CanonicalMotionExpression {
    param([Parameter(Mandatory)] [string] $Expression)
    return ($Expression -replace '\s+', ' ').Trim()
}

function Get-MotionExpressionFingerprint {
    param([Parameter(Mandatory)] [string] $Expression)
    $canonical = Get-CanonicalMotionExpression $Expression
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($canonical)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha256.ComputeHash($bytes)
    } finally {
        $sha256.Dispose()
    }
    return 'sha256:' + (-join ($hash | ForEach-Object { $_.ToString('x2') }))
}

function Get-AnimateBlocks {
    param([Parameter(Mandatory)] [string] $Text)

    $headerPattern = [regex]'(?i)\banimate\s+(?<property>[A-Za-z][A-Za-z0-9-]*)\s*\{'
    foreach ($header in $headerPattern.Matches($Text)) {
        $depth = 0
        $end = -1
        for ($index = $header.Index; $index -lt $Text.Length; $index += 1) {
            if ($Text[$index] -eq '{') {
                $depth += 1
            } elseif ($Text[$index] -eq '}') {
                $depth -= 1
                if ($depth -eq 0) {
                    $end = $index
                    break
                }
            }
        }
        if ($end -lt 0) {
            throw 'GUI lint rejects an unterminated animate block.'
        }
        [pscustomobject]@{
            Property = $header.Groups['property'].Value.ToLowerInvariant()
            Text = $Text.Substring($header.Index, $end - $header.Index + 1)
            Offset = $header.Index
        }
    }
}

function Get-MotionPropertyAssignments {
    param([Parameter(Mandatory)] [string] $Text)

    $propertyPattern = [regex]'(?is)(?<![\w-])(?<property>x|y|opacity|scale)\s*:\s*(?<value>[^;]+);'
    foreach ($match in $propertyPattern.Matches($Text)) {
        [pscustomobject]@{
            Property = $match.Groups['property'].Value.ToLowerInvariant()
            Text = $match.Value
            Value = $match.Groups['value'].Value
            Offset = $match.Index
        }
    }
}

function Test-StaticPulseGuard {
    param([Parameter(Mandatory)] [string] $Value)

    # Deliberately accept only a reviewable ternary.  Every direct tick must be
    # in its moving branch; outer branches, the static branch, and the prefix
    # must be tick-free when animation mode is zero.
    $guard = [regex]::Match($Value, '(?is)Theme\.animation-mode\s*==\s*0\s*\?')
    if (-not $guard.Success) {
        return $false
    }
    $question = $guard.Index + $guard.Length - 1
    $depth = 0
    for ($index = 0; $index -lt $question; $index += 1) {
        if ($Value[$index] -eq '(') { $depth += 1 }
        elseif ($Value[$index] -eq ')') { $depth -= 1 }
    }
    $guardDepth = $depth
    $colon = -1
    for ($index = $question + 1; $index -lt $Value.Length; $index += 1) {
        if ($Value[$index] -eq '(') { $depth += 1; continue }
        if ($Value[$index] -eq ')') {
            $depth -= 1
            if ($depth -lt $guardDepth) { return $false }
            continue
        }
        if ($depth -eq $guardDepth -and $Value[$index] -eq '?') { return $false }
        if ($depth -eq $guardDepth -and $Value[$index] -eq ':') {
            $colon = $index
            break
        }
    }
    if ($colon -lt 0) { return $false }
    $falseBranchEnd = $Value.Length
    $depth = $guardDepth
    for ($index = $colon + 1; $index -lt $Value.Length; $index += 1) {
        if ($Value[$index] -eq '(') { $depth += 1; continue }
        if ($Value[$index] -eq ')') {
            $depth -= 1
            if ($depth -lt $guardDepth) {
                $falseBranchEnd = $index
                break
            }
            continue
        }
        if ($depth -eq $guardDepth -and ($Value[$index] -eq '?' -or $Value[$index] -eq ':')) {
            $falseBranchEnd = $index
            break
        }
    }
    $prefix = $Value.Substring(0, $question)
    $staticBranch = $Value.Substring($question + 1, $colon - $question - 1)
    $movingBranch = $Value.Substring($colon + 1, $falseBranchEnd - $colon - 1)
    $suffix = $Value.Substring($falseBranchEnd)
    return $prefix -notmatch '(?i)\banimation-tick\s*\(' -and
        $staticBranch -notmatch '(?i)\banimation-tick\s*\(' -and
        $suffix -notmatch '(?i)\banimation-tick\s*\(' -and
        $movingBranch -match '(?i)\banimation-tick\s*\('
}

function Get-MotionAllowlist {
    param(
        [Parameter(Mandatory)] [string] $Root,
        [Parameter(Mandatory)] [string] $AllowlistPath
    )

    $rootItem = Get-Item -LiteralPath $Root -Force
    $allowlistItem = Get-Item -LiteralPath $AllowlistPath -Force
    if (($allowlistItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "GUI motion allowlist must not be a reparse point: $AllowlistPath"
    }
    try {
        $document = Get-Content -LiteralPath $allowlistItem.FullName -Raw | ConvertFrom-Json
    } catch {
        throw "GUI motion allowlist is not valid JSON: $AllowlistPath"
    }
    $topLevelNames = @($document.PSObject.Properties.Name | Sort-Object)
    if (@(Compare-Object @('entries', 'schema_version') $topLevelNames).Count -ne 0 -or $document.schema_version -isnot [long] -or $document.schema_version -ne 1 -or $document.entries -isnot [System.Array]) {
        throw "GUI motion allowlist has an invalid schema: $AllowlistPath"
    }
    $entries = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($entry in @($document.entries)) {
        $names = @($entry.PSObject.Properties.Name | Sort-Object)
        $required = @('expression_fingerprint', 'path', 'property', 'reason', 'reduced_motion_contract', 'rule')
        if (@(Compare-Object $required $names).Count -ne 0) {
            throw "GUI motion allowlist entry has an invalid schema: $AllowlistPath"
        }
        $path = [string]$entry.path
        $rule = [string]$entry.rule
        $property = [string]$entry.property
        $fingerprint = [string]$entry.expression_fingerprint
        $reason = [string]$entry.reason
        $contract = [string]$entry.reduced_motion_contract
        if ($path -notmatch '^[A-Za-z0-9][A-Za-z0-9._/-]*\.slint$' -or $path.Contains('..') -or $path.Contains('\') -or $path.StartsWith('/')) {
            throw "GUI motion allowlist entry has an unsafe GUI-relative path: $path"
        }
        if ($rule -notin @('motion-bounce-spring', 'motion-layout-animation', 'motion-marquee', 'motion-pulse-guard')) {
            throw "GUI motion allowlist entry has an unknown rule: $rule"
        }
        $validProperty = switch ($rule) {
            'motion-layout-animation' { $property -in @('width', 'height', 'x', 'y', 'padding', 'spacing') }
            'motion-marquee' { $property -in @('x', 'y') }
            'motion-pulse-guard' { $property -in @('opacity', 'scale') }
            default { $property -match '^[A-Za-z][A-Za-z0-9-]*$' }
        }
        $validPulseContract = $rule -ne 'motion-pulse-guard' -or $contract -match 'Theme\.animation-mode\s*==\s*0.*\bstatic\b.*\bbefore\s+animation-tick\(\)'
        if (-not $validProperty -or $fingerprint -notmatch '^sha256:[0-9a-f]{64}$' -or $reason.Length -lt 12 -or $reason.Length -gt 240 -or $contract -notmatch 'Theme\.animation-mode\s*==\s*0' -or -not $validPulseContract) {
            throw "GUI motion allowlist entry failed fail-closed validation: $path"
        }
        $sourcePath = Join-Path $rootItem.FullName ($path -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf) -or (Get-Item -LiteralPath $sourcePath -Force).Extension -ine '.slint') {
            throw "GUI motion allowlist entry does not bind a source file: $path"
        }
        $separator = [char]0x1f
        $key = "$rule$separator$path$separator$property$separator$fingerprint"
        if (-not $seen.Add($key)) {
            throw "GUI motion allowlist has a duplicate exact entry: $path"
        }
        $entries.Add([pscustomobject]@{
                Rule = $rule; Path = $path; Property = $property; Fingerprint = $fingerprint
                Reason = $reason; ReducedMotionContract = $contract; Key = $key
            }) | Out-Null
    }
    return $entries.ToArray()
}

function Find-MotionAllowlistEntry {
    param(
        [Parameter(Mandatory)] [object[]] $Allowlist,
        [Parameter(Mandatory)] [string] $Rule,
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Property,
        [Parameter(Mandatory)] [string] $Expression
    )
    $fingerprint = Get-MotionExpressionFingerprint $Expression
    return @($Allowlist | Where-Object {
            $_.Rule -eq $Rule -and $_.Path -eq $Path -and $_.Property -eq $Property -and $_.Fingerprint -eq $fingerprint
        })
}

function Get-GuiLintFindings {
    param(
        [Parameter(Mandatory)] [string] $Root,
        [string] $MotionAllowlistPath = (Join-Path $PSScriptRoot '..\design-system\gui_motion_allowlist.json'),
        [switch] $SkipUnusedMotionAllowlistCheck
    )

    $source = Get-ContainedSlintFiles $Root
    $resolvedRoot = $source.Root
    $files = @($source.Files | ForEach-Object { $_ })
    if ($files.Count -eq 0) {
        throw "GUI lint root contains no .slint files: $resolvedRoot"
    }

    $findings = [System.Collections.Generic.List[object]]::new()
    $motionAllowlist = @(Get-MotionAllowlist $resolvedRoot $MotionAllowlistPath)
    $usedMotionAllowlistKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($file in $files) {
        $relativePath = $file.FullName.Substring($resolvedRoot.Length)
        $relativePath = $relativePath.TrimStart(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar
        ).Replace('\', '/')
        foreach ($statement in Get-SlintStatements $file) {
            foreach ($match in $ColorPropertyPattern.Matches($statement.Text)) {
                $property = $match.Groups['property'].Value.ToLowerInvariant()
                $value = $match.Groups['value'].Value
                $allowedShadowCompatibilityValue = ($value -replace '\s+', '').ToLowerInvariant() -eq '#00000040'
                foreach ($literal in $ColorLiteralPattern.Matches($value)) {
                    $normalizedLiteral = $literal.Value.ToLowerInvariant() -replace '\s+', ''
                    if ($relativePath -eq 'components.slint' -and $property -eq 'drop-shadow-color' -and $allowedShadowCompatibilityValue -and $normalizedLiteral -eq '#00000040') {
                        continue
                    }
                    $lineNumber = Get-StatementLine $statement ($match.Groups['value'].Index + $literal.Index)
                    Add-GuiLintFinding $findings 'design-system-color' $relativePath $lineNumber $literal.Value.Trim()
                }
            }

            foreach ($match in $FontFamilyStatementPattern.Matches($statement.Text)) {
                $value = $match.Groups['value'].Value.Trim()
                if ($value -notmatch $ThemeFontFamilyPattern) {
                    $lineNumber = Get-StatementLine $statement $match.Groups['value'].Index
                    Add-GuiLintFinding $findings 'design-system-font' $relativePath $lineNumber $value
                }
            }

            foreach ($match in $FontSizeStatementPattern.Matches($statement.Text)) {
                foreach ($literal in $MetricLiteralPattern.Matches($match.Groups['value'].Value)) {
                    $value = ($literal.Value -replace '\s+', '').ToLowerInvariant()
                    if ($AllowedFontSizes -notcontains $value -and -not (Test-AllowedRootScale $value)) {
                        $lineNumber = Get-StatementLine $statement ($match.Groups['value'].Index + $literal.Index)
                        Add-GuiLintFinding $findings 'design-system-font-size' $relativePath $lineNumber $literal.Value.Trim()
                    }
                }
            }

            foreach ($match in $RadiusStatementPattern.Matches($statement.Text)) {
                foreach ($literal in $MetricLiteralPattern.Matches($match.Groups['value'].Value)) {
                    $value = ($literal.Value -replace '\s+', '').ToLowerInvariant()
                    if ($AllowedRadii -notcontains $value -and -not (Test-AllowedRootScale $value)) {
                        $lineNumber = Get-StatementLine $statement ($match.Groups['value'].Index + $literal.Index)
                        Add-GuiLintFinding $findings 'design-system-radius' $relativePath $lineNumber $literal.Value.Trim()
                    }
                }
            }
        }

        $executableSource = Get-ExecutableSlintSource $file
        $fingerprintSource = Get-ExecutableSlintSource $file -KeepStringLiterals
        foreach ($block in Get-AnimateBlocks $executableSource) {
            $rules = [System.Collections.Generic.List[string]]::new()
            if ($block.Text -match '(?i)\b(?:spring|bounce)\b') {
                $rules.Add('motion-bounce-spring') | Out-Null
            }
            if ($block.Property -in @('width', 'height', 'x', 'y', 'padding', 'spacing')) {
                $rules.Add('motion-layout-animation') | Out-Null
            }
            foreach ($rule in $rules) {
                $fingerprintBlockText = $fingerprintSource.Substring($block.Offset, $block.Text.Length)
                $matches = @(Find-MotionAllowlistEntry $motionAllowlist $rule $relativePath $block.Property $fingerprintBlockText)
                if ($matches.Count -eq 1) {
                    [void]$usedMotionAllowlistKeys.Add($matches[0].Key)
                    continue
                }
                Add-GuiLintFinding $findings $rule $relativePath (Get-SourceLineNumber $executableSource $block.Offset) (Get-CanonicalMotionExpression $fingerprintBlockText)
            }
        }
        foreach ($assignment in Get-MotionPropertyAssignments $executableSource) {
            if ($assignment.Value -notmatch '(?i)\banimation-tick\s*\(') {
                continue
            }
            $rule = if ($assignment.Property -in @('x', 'y')) { 'motion-marquee' } else { 'motion-pulse-guard' }
            $hasPulseGuard = Test-StaticPulseGuard $assignment.Value
            $fingerprintAssignmentText = $fingerprintSource.Substring($assignment.Offset, $assignment.Text.Length)
            $matches = @(Find-MotionAllowlistEntry $motionAllowlist $rule $relativePath $assignment.Property $fingerprintAssignmentText)
            if ($rule -eq 'motion-pulse-guard' -and -not $hasPulseGuard) {
                Add-GuiLintFinding $findings $rule $relativePath (Get-SourceLineNumber $executableSource $assignment.Offset) 'missing static Theme.animation-mode == 0 guard before animation-tick()'
            } elseif ($matches.Count -eq 1) {
                [void]$usedMotionAllowlistKeys.Add($matches[0].Key)
            } else {
                Add-GuiLintFinding $findings $rule $relativePath (Get-SourceLineNumber $executableSource $assignment.Offset) (Get-CanonicalMotionExpression $fingerprintAssignmentText)
            }
        }
    }
    if (-not $SkipUnusedMotionAllowlistCheck) {
        foreach ($entry in $motionAllowlist) {
            if (-not $usedMotionAllowlistKeys.Contains($entry.Key)) {
                Add-GuiLintFinding $findings 'motion-allowlist-stale' $entry.Path 0 "$($entry.Rule) $($entry.Property) $($entry.Fingerprint)"
            }
        }
    }
    return $findings.ToArray()
}

function Invoke-GuiLintSelfTest {
    $fixtureRoot = Join-Path $PSScriptRoot 'gui_lint_fixtures'
    $motionAllowlist = Join-Path $fixtureRoot 'motion_allowlist.json'
    $emptyMotionAllowlist = Join-Path $fixtureRoot 'empty_motion_allowlist.json'
    $unboundMotionAllowlist = Join-Path $fixtureRoot 'unbound_motion_allowlist.json'
    $cases = @(
        @{ Name = 'allowed'; Expected = @(); MotionAllowlist = $emptyMotionAllowlist },
        @{ Name = 'bad_color'; Expected = @('design-system-color'); MotionAllowlist = $emptyMotionAllowlist },
        @{ Name = 'bad_font'; Expected = @('design-system-font'); MotionAllowlist = $emptyMotionAllowlist },
        @{ Name = 'bad_font_size'; Expected = @('design-system-font-size'); MotionAllowlist = $emptyMotionAllowlist },
        @{ Name = 'bad_radius'; Expected = @('design-system-radius'); MotionAllowlist = $emptyMotionAllowlist },
        @{ Name = 'bad_multiline'; Expected = @('design-system-color', 'design-system-font', 'design-system-font-size', 'design-system-radius'); MotionAllowlist = $emptyMotionAllowlist },
        @{ Name = 'bad_nested'; Expected = @('design-system-color', 'design-system-font', 'design-system-font-size', 'design-system-radius'); MotionAllowlist = $emptyMotionAllowlist },
        @{ Name = 'bad_inline_comment_delimiter'; Expected = @('design-system-color', 'design-system-font', 'design-system-font-size', 'design-system-radius'); MotionAllowlist = $emptyMotionAllowlist },
        @{ Name = 'bad_block_comment_delimiter'; Expected = @('design-system-color', 'design-system-font', 'design-system-font-size', 'design-system-radius'); MotionAllowlist = $emptyMotionAllowlist },
        @{ Name = 'bad_nested_block_comment_delimiter'; Expected = @('design-system-color', 'design-system-font', 'design-system-font-size', 'design-system-radius'); MotionAllowlist = $emptyMotionAllowlist },
        @{ Name = 'bad_allowlist_tail'; Expected = @('design-system-color', 'design-system-font'); MotionAllowlist = $emptyMotionAllowlist },
        @{ Name = 'motion_allowed'; Expected = @(); MotionAllowlist = $motionAllowlist },
        @{ Name = 'motion_bad_bounce_spring'; Expected = @('motion-bounce-spring'); MotionAllowlist = $motionAllowlist },
        @{ Name = 'motion_bad_layout'; Expected = @('motion-layout-animation'); MotionAllowlist = $motionAllowlist },
        @{ Name = 'motion_bad_marquee'; Expected = @('motion-marquee'); MotionAllowlist = $motionAllowlist },
        @{ Name = 'motion_bad_pulse_guard'; Expected = @('motion-pulse-guard'); MotionAllowlist = $motionAllowlist },
        @{ Name = 'motion_valid_pulse_guard'; Expected = @(); MotionAllowlist = $motionAllowlist },
        @{ Name = 'motion_bad_outer_pulse_branch'; Expected = @('motion-pulse-guard'); MotionAllowlist = $motionAllowlist },
        @{ Name = 'motion_comment_string_decoys'; Expected = @(); MotionAllowlist = $motionAllowlist },
        @{ Name = 'motion_changed_allowlisted_expression'; Expected = @('motion-layout-animation'); MotionAllowlist = $motionAllowlist }
    )
    $failed = $false
    foreach ($case in $cases) {
        $findings = @(Get-GuiLintFindings (Join-Path $fixtureRoot $case.Name) -MotionAllowlistPath $case.MotionAllowlist -SkipUnusedMotionAllowlistCheck)
        $actual = @($findings | ForEach-Object Rule | Sort-Object -Unique)
        $expected = @($case.Expected | Sort-Object -Unique)
        if (@(Compare-Object $expected $actual).Count -ne 0) {
            Write-Output "GUI_LINT_FIXTURE_FAIL=$($case.Name): expected [$($expected -join ', ')] got [$($actual -join ', ')]"
            $failed = $true
        } else {
            Write-Output "GUI_LINT_FIXTURE_PASS=$($case.Name)"
        }
    }
    try {
        Get-GuiLintFindings (Join-Path $fixtureRoot 'motion_allowed') -MotionAllowlistPath $unboundMotionAllowlist -SkipUnusedMotionAllowlistCheck | Out-Null
        Write-Output 'GUI_LINT_FIXTURE_FAIL=motion_unbound_allowlist: expected source-binding rejection'
        $failed = $true
    } catch {
        if ($_.Exception.Message -eq 'GUI motion allowlist entry does not bind a source file: missing.slint') {
            Write-Output 'GUI_LINT_FIXTURE_PASS=motion_unbound_allowlist'
        } else {
            throw
        }
    }
    if ($failed) {
        Write-Output 'GUI_LINT_SELF_TEST_EXIT=1'
        exit 1
    }
    Write-Output 'GUI_LINT_SELF_TEST_EXIT=0'
    exit 0
}

if ($SelfTest) {
    Invoke-GuiLintSelfTest
}

$uiRoot = Join-Path $PSScriptRoot 'neothd-gui/ui'
$findings = @(Get-GuiLintFindings $uiRoot)
foreach ($finding in $findings | Sort-Object -Property Path, Line, Rule, Value) {
    Write-Output ("GUI_LINT {0}:{1}: {2}: {3}" -f $finding.Path, $finding.Line, $finding.Rule, $finding.Value)
}
if ($findings.Count -gt 0) {
    Write-Output 'GUI_LINT_RESULT=FAIL'
    exit 1
}
Write-Output 'GUI_LINT_RESULT=PASS'
exit 0
