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

function Get-GuiLintFindings {
    param([Parameter(Mandatory)] [string] $Root)

    $source = Get-ContainedSlintFiles $Root
    $resolvedRoot = $source.Root
    $files = @($source.Files | ForEach-Object { $_ })
    if ($files.Count -eq 0) {
        throw "GUI lint root contains no .slint files: $resolvedRoot"
    }

    $findings = [System.Collections.Generic.List[object]]::new()
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
    }
    return $findings.ToArray()
}

function Invoke-GuiLintSelfTest {
    $fixtureRoot = Join-Path $PSScriptRoot 'gui_lint_fixtures'
    $cases = @(
        @{ Name = 'allowed'; Expected = @() },
        @{ Name = 'bad_color'; Expected = @('design-system-color') },
        @{ Name = 'bad_font'; Expected = @('design-system-font') },
        @{ Name = 'bad_font_size'; Expected = @('design-system-font-size') },
        @{ Name = 'bad_radius'; Expected = @('design-system-radius') },
        @{ Name = 'bad_multiline'; Expected = @('design-system-color', 'design-system-font', 'design-system-font-size', 'design-system-radius') },
        @{ Name = 'bad_nested'; Expected = @('design-system-color', 'design-system-font', 'design-system-font-size', 'design-system-radius') },
        @{ Name = 'bad_inline_comment_delimiter'; Expected = @('design-system-color', 'design-system-font', 'design-system-font-size', 'design-system-radius') },
        @{ Name = 'bad_block_comment_delimiter'; Expected = @('design-system-color', 'design-system-font', 'design-system-font-size', 'design-system-radius') },
        @{ Name = 'bad_nested_block_comment_delimiter'; Expected = @('design-system-color', 'design-system-font', 'design-system-font-size', 'design-system-radius') },
        @{ Name = 'bad_allowlist_tail'; Expected = @('design-system-color', 'design-system-font') }
    )
    $failed = $false
    foreach ($case in $cases) {
        $findings = @(Get-GuiLintFindings (Join-Path $fixtureRoot $case.Name))
        $actual = @($findings | ForEach-Object Rule | Sort-Object -Unique)
        $expected = @($case.Expected | Sort-Object -Unique)
        if (@(Compare-Object $expected $actual).Count -ne 0) {
            Write-Output "GUI_LINT_FIXTURE_FAIL=$($case.Name): expected [$($expected -join ', ')] got [$($actual -join ', ')]"
            $failed = $true
        } else {
            Write-Output "GUI_LINT_FIXTURE_PASS=$($case.Name)"
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
