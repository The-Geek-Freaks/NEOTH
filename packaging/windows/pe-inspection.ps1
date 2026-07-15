Set-StrictMode -Version Latest

function Stop-PeInspection {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "NEOTH PE inspection failed: $Message"
}

function Read-PeUInt16 {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][long]$Offset,
        [Parameter(Mandatory = $true)][string]$Field
    )

    if ($Offset -lt 0 -or ([uint64]$Offset + 2) -gt [uint64]$Bytes.LongLength) {
        Stop-PeInspection "$Field lies outside the file"
    }
    return [BitConverter]::ToUInt16($Bytes, [int]$Offset)
}

function Read-PeUInt32 {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][long]$Offset,
        [Parameter(Mandatory = $true)][string]$Field
    )

    if ($Offset -lt 0 -or ([uint64]$Offset + 4) -gt [uint64]$Bytes.LongLength) {
        Stop-PeInspection "$Field lies outside the file"
    }
    return [BitConverter]::ToUInt32($Bytes, [int]$Offset)
}

function Read-PeUInt64 {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][long]$Offset,
        [Parameter(Mandatory = $true)][string]$Field
    )

    if ($Offset -lt 0 -or ([uint64]$Offset + 8) -gt [uint64]$Bytes.LongLength) {
        Stop-PeInspection "$Field lies outside the file"
    }
    return [BitConverter]::ToUInt64($Bytes, [int]$Offset)
}

function Test-PeZeroRange {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][long]$Offset,
        [Parameter(Mandatory = $true)][int]$Length,
        [Parameter(Mandatory = $true)][string]$Field
    )

    if ($Offset -lt 0 -or ([uint64]$Offset + [uint64]$Length) -gt [uint64]$Bytes.LongLength) {
        Stop-PeInspection "$Field lies outside the file"
    }
    for ($index = 0; $index -lt $Length; $index++) {
        if ($Bytes[$Offset + $index] -ne 0) {
            return $false
        }
    }
    return $true
}

function Resolve-PeRva {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][object[]]$Sections,
        [Parameter(Mandatory = $true)][uint32]$SizeOfHeaders,
        [Parameter(Mandatory = $true)][uint32]$Rva,
        [Parameter(Mandatory = $true)][uint32]$Length,
        [Parameter(Mandatory = $true)][string]$Field
    )

    if ($Length -eq 0) {
        Stop-PeInspection "$Field requested a zero-length RVA mapping"
    }
    $rvaEnd = [uint64]$Rva + [uint64]$Length
    if ($rvaEnd -gt ([uint64][uint32]::MaxValue + 1)) {
        Stop-PeInspection "$Field RVA range overflows"
    }

    $matches = [Collections.Generic.List[long]]::new()
    if ([uint64]$Rva -lt [uint64]$SizeOfHeaders) {
        if ($rvaEnd -gt [uint64]$SizeOfHeaders -or $rvaEnd -gt [uint64]$Bytes.LongLength) {
            Stop-PeInspection "$Field extends beyond the PE headers"
        }
        [void]$matches.Add([long]$Rva)
    }

    foreach ($section in $Sections) {
        $sectionStart = [uint64]$section.VirtualAddress
        $sectionSpan = [Math]::Max(
            [uint64]$section.VirtualSize,
            [uint64]$section.SizeOfRawData
        )
        $sectionEnd = $sectionStart + $sectionSpan
        if ([uint64]$Rva -lt $sectionStart -or [uint64]$Rva -ge $sectionEnd) {
            continue
        }
        $delta = [uint64]$Rva - $sectionStart
        if (($delta + [uint64]$Length) -gt [uint64]$section.SizeOfRawData) {
            Stop-PeInspection "$Field points into unbacked virtual section data"
        }
        $fileOffset = [uint64]$section.PointerToRawData + $delta
        if (($fileOffset + [uint64]$Length) -gt [uint64]$Bytes.LongLength) {
            Stop-PeInspection "$Field maps outside the file"
        }
        [void]$matches.Add([long]$fileOffset)
    }

    if ($matches.Count -eq 0) {
        Stop-PeInspection "$Field RVA 0x$($Rva.ToString('X8')) is not backed by the file"
    }
    if ($matches.Count -ne 1) {
        Stop-PeInspection "$Field RVA 0x$($Rva.ToString('X8')) maps ambiguously"
    }
    return $matches[0]
}

function Read-PeAsciiName {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][object[]]$Sections,
        [Parameter(Mandatory = $true)][uint32]$SizeOfHeaders,
        [Parameter(Mandatory = $true)][uint32]$Rva,
        [Parameter(Mandatory = $true)][string]$Field
    )

    if ($Rva -eq 0) {
        Stop-PeInspection "$Field has a null name RVA"
    }
    $characters = [Collections.Generic.List[byte]]::new()
    for ($index = 0; $index -lt 512; $index++) {
        $currentRva = [uint64]$Rva + [uint64]$index
        if ($currentRva -gt [uint32]::MaxValue) {
            Stop-PeInspection "$Field name RVA overflows"
        }
        $offset = Resolve-PeRva `
            -Bytes $Bytes `
            -Sections $Sections `
            -SizeOfHeaders $SizeOfHeaders `
            -Rva ([uint32]$currentRva) `
            -Length 1 `
            -Field $Field
        $value = $Bytes[$offset]
        if ($value -eq 0) {
            if ($characters.Count -eq 0) {
                Stop-PeInspection "$Field has an empty module name"
            }
            $name = [Text.Encoding]::ASCII.GetString($characters.ToArray())
            if ($name -cnotmatch '\A[A-Za-z0-9._+-]+\z') {
                Stop-PeInspection "$Field has an invalid module name '$name'"
            }
            return $name
        }
        if ($value -lt 0x21 -or $value -gt 0x7E) {
            Stop-PeInspection "$Field contains a non-ASCII module name"
        }
        [void]$characters.Add($value)
    }
    Stop-PeInspection "$Field module name is not null-terminated within 512 bytes"
}

function Get-PeDirectory {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][long]$OptionalOffset,
        [Parameter(Mandatory = $true)][uint16]$OptionalSize,
        [Parameter(Mandatory = $true)][uint32]$DirectoryCount,
        [Parameter(Mandatory = $true)][int]$DirectoryBase,
        [Parameter(Mandatory = $true)][int]$Index,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ([uint32]$Index -ge $DirectoryCount) {
        return [pscustomobject]@{ Rva = [uint32]0; Size = [uint32]0 }
    }
    $relativeOffset = [uint64]$DirectoryBase + ([uint64]$Index * 8)
    if (($relativeOffset + 8) -gt [uint64]$OptionalSize) {
        Stop-PeInspection "$Name directory is declared outside the optional header"
    }
    $offset = $OptionalOffset + [long]$relativeOffset
    return [pscustomobject]@{
        Rva = Read-PeUInt32 -Bytes $Bytes -Offset $offset -Field "$Name directory RVA"
        Size = Read-PeUInt32 -Bytes $Bytes -Offset ($offset + 4) -Field "$Name directory size"
    }
}

function Get-PeImportedModules {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][object[]]$Sections,
        [Parameter(Mandatory = $true)][uint32]$SizeOfHeaders,
        [Parameter(Mandatory = $true)][uint64]$ImageBase,
        [Parameter(Mandatory = $true)][object]$Directory,
        [Parameter(Mandatory = $true)][ValidateSet('normal', 'delay')][string]$Kind
    )

    if ($Directory.Rva -eq 0 -and $Directory.Size -eq 0) {
        return
    }
    if ($Directory.Rva -eq 0 -or $Directory.Size -eq 0) {
        Stop-PeInspection "$Kind import directory has an incomplete RVA/size pair"
    }
    $descriptorSize = if ($Kind -eq 'normal') { 20 } else { 32 }
    if ($Directory.Size -lt $descriptorSize) {
        Stop-PeInspection "$Kind import directory is smaller than one descriptor"
    }
    $directoryOffset = Resolve-PeRva `
        -Bytes $Bytes `
        -Sections $Sections `
        -SizeOfHeaders $SizeOfHeaders `
        -Rva $Directory.Rva `
        -Length $Directory.Size `
        -Field "$Kind import directory"

    $terminated = $false
    for ($relative = 0; ($relative + $descriptorSize) -le $Directory.Size; $relative += $descriptorSize) {
        $descriptorOffset = $directoryOffset + $relative
        if (Test-PeZeroRange `
                -Bytes $Bytes `
                -Offset $descriptorOffset `
                -Length $descriptorSize `
                -Field "$Kind import descriptor") {
            $terminated = $true
            break
        }

        if ($Kind -eq 'normal') {
            $nameRva = Read-PeUInt32 `
                -Bytes $Bytes `
                -Offset ($descriptorOffset + 12) `
                -Field 'normal import name RVA'
        } else {
            $attributes = Read-PeUInt32 `
                -Bytes $Bytes `
                -Offset $descriptorOffset `
                -Field 'delay import attributes'
            if ($attributes -ne 0 -and $attributes -ne 1) {
                Stop-PeInspection "delay import descriptor has unsupported attributes 0x$($attributes.ToString('X8'))"
            }
            $nameValue = Read-PeUInt32 `
                -Bytes $Bytes `
                -Offset ($descriptorOffset + 4) `
                -Field 'delay import name'
            if ($attributes -eq 1) {
                $nameRva = $nameValue
            } else {
                if ([uint64]$nameValue -lt $ImageBase) {
                    Stop-PeInspection 'delay import name VA lies below the image base'
                }
                $relativeName = [uint64]$nameValue - $ImageBase
                if ($relativeName -gt [uint32]::MaxValue) {
                    Stop-PeInspection 'delay import name VA cannot be represented as an RVA'
                }
                $nameRva = [uint32]$relativeName
            }
        }
        Read-PeAsciiName `
            -Bytes $Bytes `
            -Sections $Sections `
            -SizeOfHeaders $SizeOfHeaders `
            -Rva $nameRva `
            -Field "$Kind import descriptor"
    }
    if (-not $terminated) {
        Stop-PeInspection "$Kind import directory has no null terminator within its declared size"
    }
}

function Get-PeImageInfo {
    param([Parameter(Mandatory = $true)][string]$Path)

    $leaf = Split-Path -Leaf $Path
    try {
        $bytes = [IO.File]::ReadAllBytes($Path)
    } catch {
        Stop-PeInspection "could not read ${leaf}: $($_.Exception.Message)"
    }
    if ($bytes.LongLength -lt 64) {
        Stop-PeInspection "$leaf is too small to be a PE executable"
    }
    if ((Read-PeUInt16 -Bytes $bytes -Offset 0 -Field 'DOS signature') -ne 0x5A4D) {
        Stop-PeInspection "$leaf is not a PE executable"
    }
    $peOffset = Read-PeUInt32 -Bytes $bytes -Offset 0x3C -Field 'PE header offset'
    if (([uint64]$peOffset + 24) -gt [uint64]$bytes.LongLength) {
        Stop-PeInspection "$leaf has an invalid PE header offset"
    }
    if ((Read-PeUInt32 -Bytes $bytes -Offset $peOffset -Field 'PE signature') -ne 0x00004550) {
        Stop-PeInspection "$leaf has no PE signature"
    }
    $machine = Read-PeUInt16 -Bytes $bytes -Offset ($peOffset + 4) -Field 'COFF machine'
    $sectionCount = Read-PeUInt16 -Bytes $bytes -Offset ($peOffset + 6) -Field 'COFF section count'
    if ($sectionCount -eq 0 -or $sectionCount -gt 96) {
        Stop-PeInspection "$leaf has an invalid COFF section count $sectionCount"
    }
    $optionalSize = Read-PeUInt16 -Bytes $bytes -Offset ($peOffset + 20) -Field 'optional header size'
    $optionalOffset = [long]$peOffset + 24
    if (([uint64]$optionalOffset + [uint64]$optionalSize) -gt [uint64]$bytes.LongLength) {
        Stop-PeInspection "$leaf has a truncated optional header"
    }
    $magic = Read-PeUInt16 -Bytes $bytes -Offset $optionalOffset -Field 'optional header magic'
    if ($magic -eq 0x10B) {
        $directoryBase = 96
        $directoryCountOffset = 92
        $imageBase = [uint64](Read-PeUInt32 -Bytes $bytes -Offset ($optionalOffset + 28) -Field 'PE32 image base')
    } elseif ($magic -eq 0x20B) {
        $directoryBase = 112
        $directoryCountOffset = 108
        $imageBase = Read-PeUInt64 -Bytes $bytes -Offset ($optionalOffset + 24) -Field 'PE32+ image base'
    } else {
        Stop-PeInspection "$leaf has unsupported optional header magic 0x$($magic.ToString('X4'))"
    }
    if ($optionalSize -lt ($directoryCountOffset + 4)) {
        Stop-PeInspection "$leaf optional header is too small for its directory count"
    }
    $sizeOfHeaders = Read-PeUInt32 `
        -Bytes $bytes `
        -Offset ($optionalOffset + 60) `
        -Field 'size of headers'
    $directoryCount = Read-PeUInt32 `
        -Bytes $bytes `
        -Offset ($optionalOffset + $directoryCountOffset) `
        -Field 'data directory count'
    $sectionTable = $optionalOffset + $optionalSize
    $sectionTableEnd = [uint64]$sectionTable + ([uint64]$sectionCount * 40)
    if ($sectionTableEnd -gt [uint64]$bytes.LongLength -or
        $sizeOfHeaders -lt $sectionTableEnd -or
        $sizeOfHeaders -gt $bytes.LongLength) {
        Stop-PeInspection "$leaf has an invalid section table or header size"
    }

    $sections = [Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $sectionCount; $index++) {
        $offset = $sectionTable + ($index * 40)
        $virtualSize = Read-PeUInt32 -Bytes $bytes -Offset ($offset + 8) -Field "section $index virtual size"
        $virtualAddress = Read-PeUInt32 -Bytes $bytes -Offset ($offset + 12) -Field "section $index virtual address"
        $rawSize = Read-PeUInt32 -Bytes $bytes -Offset ($offset + 16) -Field "section $index raw size"
        $rawOffset = Read-PeUInt32 -Bytes $bytes -Offset ($offset + 20) -Field "section $index raw offset"
        if ($rawSize -ne 0 -and ([uint64]$rawOffset + [uint64]$rawSize) -gt [uint64]$bytes.LongLength) {
            Stop-PeInspection "$leaf section $index raw data lies outside the file"
        }
        [void]$sections.Add([pscustomobject]@{
            VirtualSize = $virtualSize
            VirtualAddress = $virtualAddress
            SizeOfRawData = $rawSize
            PointerToRawData = $rawOffset
        })
    }

    $normalDirectory = Get-PeDirectory `
        -Bytes $bytes `
        -OptionalOffset $optionalOffset `
        -OptionalSize $optionalSize `
        -DirectoryCount $directoryCount `
        -DirectoryBase $directoryBase `
        -Index 1 `
        -Name 'normal import'
    $delayDirectory = Get-PeDirectory `
        -Bytes $bytes `
        -OptionalOffset $optionalOffset `
        -OptionalSize $optionalSize `
        -DirectoryCount $directoryCount `
        -DirectoryBase $directoryBase `
        -Index 13 `
        -Name 'delay import'
    $normalImports = @(Get-PeImportedModules `
        -Bytes $bytes `
        -Sections $sections.ToArray() `
        -SizeOfHeaders $sizeOfHeaders `
        -ImageBase $imageBase `
        -Directory $normalDirectory `
        -Kind normal)
    $delayImports = @(Get-PeImportedModules `
        -Bytes $bytes `
        -Sections $sections.ToArray() `
        -SizeOfHeaders $sizeOfHeaders `
        -ImageBase $imageBase `
        -Directory $delayDirectory `
        -Kind delay)

    return [pscustomobject]@{
        Machine = $machine
        Imports = $normalImports
        DelayImports = $delayImports
    }
}

function Assert-PeStaticMsvcRuntime {
    param([Parameter(Mandatory = $true)][string]$Path)

    $image = Get-PeImageInfo -Path $Path
    foreach ($module in @($image.Imports) + @($image.DelayImports)) {
        if ($module -match '\A(?:(?:VCRUNTIME|MSVCP|CONCRT).*|UCRTBASE|API-MS-WIN-CRT-.*)\.DLL\z') {
            Stop-PeInspection "$(Split-Path -Leaf $Path) dynamically imports forbidden MSVC runtime $module"
        }
    }
    return $image
}
