param(
    [Parameter(Mandatory = $true)][string]$FlutterSdk,
    [Parameter(Mandatory = $true)][string]$SourceDirectory,
    [Parameter(Mandatory = $true)][string]$ExpectedPubspecLockSha256,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [Parameter(Mandatory = $true)][string]$VerifiedNativeArtifactRoot,
    [Parameter(Mandatory = $true)][string]$NativeArtifactManifest,
    [ValidateSet('android', 'ios', 'all')][string]$Stage = 'all'
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $SourceDirectory -PathType Container)) { throw 'explicit application source directory missing' }
if ($ExpectedPubspecLockSha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw 'ExpectedPubspecLockSha256 must be a SHA-256.' }
if (-not (Test-Path -LiteralPath (Join-Path $SourceDirectory 'pubspec.lock') -PathType Leaf)) { throw 'source application pubspec.lock missing' }
if ((Get-FileHash -LiteralPath (Join-Path $SourceDirectory 'pubspec.lock') -Algorithm SHA256).Hash -ne $ExpectedPubspecLockSha256.ToUpperInvariant()) { throw 'source application pubspec.lock hash mismatch' }
foreach ($forbiddenOverlay in @('android/build.gradle','android/settings.gradle','android/app/build.gradle','android/build.gradle.kts','android/settings.gradle.kts','android/app/build.gradle.kts')) {
    if (Test-Path -LiteralPath (Join-Path $SourceDirectory $forbiddenOverlay) -PathType Leaf) { throw "Authored Gradle overlay is forbidden: $forbiddenOverlay" }
}
if (Test-Path -LiteralPath $OutputDirectory) { throw 'output directory must be fresh' }
if (-not (Test-Path -LiteralPath $NativeArtifactManifest)) { throw 'native artifact manifest missing' }
if (-not (Test-Path -LiteralPath $VerifiedNativeArtifactRoot)) { throw 'verified native artifact root missing' }
$flutter = @((Join-Path $FlutterSdk 'bin\flutter'), (Join-Path $FlutterSdk 'bin\flutter.bat')) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if ($null -eq $flutter) { throw 'pinned Flutter SDK missing' }

$logRoot = Join-Path (Split-Path -Parent $OutputDirectory) ("neoth-companion-hosted-logs-" + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Force -Path $logRoot | Out-Null
function Invoke-Flutter {
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][string[]]$Arguments)
    $log = Join-Path $logRoot ("$Name.log")
    & $flutter @Arguments 2>&1 | Tee-Object -LiteralPath $log
    if ($LASTEXITCODE -ne 0) { throw "flutter $Name failed with exit code $LASTEXITCODE; retained log: $log" }
}

# Version is admitted before Flutter creates any output directory.
$versionLog = Join-Path $logRoot '00-version.log'
$version = (& $flutter --version 2>&1 | Tee-Object -LiteralPath $versionLog | Out-String)
if ($LASTEXITCODE -ne 0) { throw "flutter --version failed with exit code $LASTEXITCODE; retained log: $versionLog" }
if ($version -notmatch 'Flutter 3\.24\.5') { throw 'hosted Flutter SDK is not pinned 3.24.5' }

# The input manifest must list {relative_path, sha256} for every copied native
# file. Only selected-platform manifest leaves are verified and copied.
$nativeManifestHash = (Get-FileHash -LiteralPath $NativeArtifactManifest -Algorithm SHA256).Hash
$nativeManifest = Get-Content -LiteralPath $NativeArtifactManifest -Raw | ConvertFrom-Json
if ($null -eq $nativeManifest.files -or $nativeManifest.files.Count -eq 0) { throw 'native artifact manifest has no files' }
$selectedNativeEntries = @($nativeManifest.files | Where-Object {
    ($Stage -in @('android','all') -and $_.relative_path -like 'android/*') -or
    ($Stage -in @('ios','all') -and $_.relative_path -like 'ios/*')
})
if ($selectedNativeEntries.Count -eq 0) { throw 'native artifact manifest has no selected-platform files' }
foreach ($entry in $selectedNativeEntries) {
    $relative = [string]$entry.relative_path; $expected = [string]$entry.sha256
    if ([string]::IsNullOrWhiteSpace($relative) -or [IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)' -or $expected -notmatch '^[0-9A-Fa-f]{64}$') { throw 'native artifact manifest has invalid path or hash' }
    $source = Join-Path $VerifiedNativeArtifactRoot $relative
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "verified native artifact missing: $relative" }
    if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $expected.ToUpperInvariant()) { throw "verified native artifact hash mismatch: $relative" }
}
if ($Stage -in @('android','all')) {
foreach ($abi in 'arm64-v8a','armeabi-v7a','x86_64') {
    if ($selectedNativeEntries.relative_path -notcontains "android/$abi/libneoth_companion_bridge.so") { throw "native manifest lacks Android ABI $abi" }
}
}
if ($Stage -in @('ios','all') -and $selectedNativeEntries.relative_path -notcontains 'ios/NEOTHCompanionBridge.xcframework/Info.plist') { throw 'native manifest lacks iOS XCFramework Info.plist' }

Invoke-Flutter -Name '01-create' -Arguments @('create', '--platforms=android,ios', '--org', 'org.neoth', '--project-name', 'companion', $OutputDirectory)
$generatedGradle = Join-Path $OutputDirectory 'android/app/build.gradle'
if (-not (Test-Path -LiteralPath $generatedGradle -PathType Leaf)) { throw 'Flutter 3.24.5 generated Android Groovy build.gradle is missing' }
$gradleText = Get-Content -LiteralPath $generatedGradle -Raw
$minSdkTemplateLine = 'minSdk = flutter.minSdkVersion'
if ([regex]::Matches($gradleText, [regex]::Escape($minSdkTemplateLine)).Count -ne 1) { throw 'Flutter template minSdk line is absent or not unique; refusing Android patch' }
$gradleText = $gradleText.Replace($minSdkTemplateLine, 'minSdk = 23')
$requiredR8Annotations = @(
    'com.google.errorprone:error_prone_annotations:2.3.2',
    'com.google.code.findbugs:jsr305:3.0.2'
)
foreach ($requiredR8Annotation in $requiredR8Annotations) {
    if ($gradleText.Contains($requiredR8Annotation)) { throw "Flutter template already declares required R8 annotation dependency: $requiredR8Annotation" }
}
$gradleDependencyBlock = [string]::Join([Environment]::NewLine, @(
    'dependencies {',
    '    implementation "com.google.errorprone:error_prone_annotations:2.3.2"',
    '    implementation "com.google.code.findbugs:jsr305:3.0.2"',
    '}'
))
$gradleText = $gradleText.TrimEnd() + [Environment]::NewLine + [Environment]::NewLine + $gradleDependencyBlock + [Environment]::NewLine
foreach ($requiredR8Annotation in $requiredR8Annotations) {
    if ([regex]::Matches($gradleText, [regex]::Escape($requiredR8Annotation)).Count -ne 1) { throw "generated Android R8 annotation dependency is absent or not unique: $requiredR8Annotation" }
}
[System.IO.File]::WriteAllText($generatedGradle, $gradleText, [System.Text.UTF8Encoding]::new($false))
Get-ChildItem -LiteralPath $SourceDirectory -Force | Copy-Item -Destination $OutputDirectory -Recurse -Force
# This file is generated by the template and asserts a different MyApp.
Remove-Item -LiteralPath (Join-Path $OutputDirectory 'test\widget_test.dart') -Force -ErrorAction SilentlyContinue

$androidDestination = Join-Path $OutputDirectory 'android\app\src\main\jniLibs'
$iosDestination = Join-Path $OutputDirectory 'ios\Frameworks'
if ($Stage -in @('android','all')) { New-Item -ItemType Directory -Force -Path $androidDestination | Out-Null }
if ($Stage -in @('ios','all')) { New-Item -ItemType Directory -Force -Path $iosDestination | Out-Null }
foreach ($entry in $selectedNativeEntries) {
    $relative = [string]$entry.relative_path
    $source = Join-Path $VerifiedNativeArtifactRoot $relative
    if ($relative -like 'android/*') {
        $target = Join-Path $androidDestination $relative.Substring('android/'.Length)
    } elseif ($relative -like 'ios/*') {
        $target = Join-Path $iosDestination $relative.Substring('ios/'.Length)
    } else { throw "unselected native artifact namespace: $relative" }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
    Copy-Item -LiteralPath $source -Destination $target -Force
}

Push-Location $OutputDirectory
try {
    Invoke-Flutter -Name '02-pub-get' -Arguments @('pub', 'get')
    if ((Get-FileHash -LiteralPath 'pubspec.lock' -Algorithm SHA256).Hash -ne $ExpectedPubspecLockSha256.ToUpperInvariant()) { throw 'flutter pub get changed the approved pubspec.lock' }
    Invoke-Flutter -Name '03-analyze' -Arguments @('analyze')
    Invoke-Flutter -Name '04-test' -Arguments @('test')
    $proof = [ordered]@{ schema='neoth.mobile.flutter.hosted.materialization.v2'; stage=$Stage; flutter_version=$version.Trim(); native_artifact_manifest_sha256=$nativeManifestHash; lockfile_sha256=(Get-FileHash -LiteralPath 'pubspec.lock' -Algorithm SHA256).Hash; artifacts=@() }
    if ($Stage -in @('android','all')) {
        Invoke-Flutter -Name '05-build-android' -Arguments @('build','apk','--release','--split-per-abi')
        foreach ($artifact in 'build\app\outputs\flutter-apk\app-arm64-v8a-release.apk','build\app\outputs\flutter-apk\app-armeabi-v7a-release.apk','build\app\outputs\flutter-apk\app-x86_64-release.apk') {
            if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) { throw "expected Android export missing: $artifact" }
            $proof.artifacts += [ordered]@{ path=$artifact; sha256=(Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash }
        }
    }
    if ($Stage -in @('ios','all')) {
        Invoke-Flutter -Name '06-build-ios' -Arguments @('build','ios','--release','--no-codesign')
        $runner = Join-Path (Get-Location) 'build\ios\iphoneos\Runner.app\Runner'
        if (-not (Test-Path -LiteralPath $runner -PathType Leaf)) { throw 'unsigned iOS Runner binary is missing' }
        $nmLines = @(& /usr/bin/nm -g $runner)
        if ($LASTEXITCODE -ne 0) { throw "nm failed for iOS Runner with exit code $LASTEXITCODE" }
        $requiredFfiExports = @(
            'neoth_companion_bridge_new',
            'neoth_companion_bridge_free',
            'neoth_companion_pair_start',
            'neoth_companion_reconnect_start',
            'neoth_companion_chat_start',
            'neoth_companion_operation_poll',
            'neoth_companion_operation_cancel',
            'neoth_companion_operation_free',
            'neoth_companion_chat_start_v2',
            'neoth_companion_operation_poll_v2',
            'neoth_companion_chat_start_v3',
            'neoth_companion_operation_poll_v3',
            'neoth_companion_conversation_start_v1',
            'neoth_companion_conversation_poll_v1'
        )
        $matchedFfiExports = @()
        foreach ($symbol in $requiredFfiExports) {
            $pattern = '\sT\s_?' + [regex]::Escape($symbol) + '$'
            $matches = @($nmLines | Where-Object { $_ -match $pattern })
            if ($matches.Count -eq 0) { throw "iOS Runner is missing required defined global T FFI export: $symbol" }
            $matchedFfiExports += [ordered]@{ symbol=$symbol; nm_lines=$matches }
        }
        $symbolProof = [ordered]@{
            schema='neoth.mobile.ios-ffi-symbols.v1'
            runner='build/ios/iphoneos/Runner.app/Runner'
            runner_sha256=(Get-FileHash -LiteralPath $runner -Algorithm SHA256).Hash
            required_exports=$requiredFfiExports
            matched_exports=$matchedFfiExports
        }
        $symbolProof | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath 'ios-ffi-symbols.json' -Encoding utf8
        $proof.ios_ffi_symbols_sha256=(Get-FileHash -LiteralPath 'ios-ffi-symbols.json' -Algorithm SHA256).Hash
        $iosFiles = Get-ChildItem -LiteralPath 'build\ios\iphoneos\Runner.app' -Recurse -File -ErrorAction Stop
        if ($iosFiles.Count -eq 0) { throw 'unsigned iOS Runner.app has no exported files' }
        foreach ($file in $iosFiles | Sort-Object FullName) { $proof.artifacts += [ordered]@{ path=$file.FullName.Substring((Get-Location).Path.Length + 1); sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash } }
    }
    $proof.logs = @(Get-ChildItem -LiteralPath $logRoot -File | Sort-Object Name | ForEach-Object { [ordered]@{ name=$_.Name; sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash } })
    $proof | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath 'hosted-evidence.json' -Encoding utf8
} finally { Pop-Location }
