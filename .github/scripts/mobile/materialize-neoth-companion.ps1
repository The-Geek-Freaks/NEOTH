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
    '    testImplementation "junit:junit:4.13.2"',
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
        # Inspect the actual release APKs on the hosted runner, never locally.
        $androidSdk = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { $env:ANDROID_SDK_ROOT }
        if ([string]::IsNullOrWhiteSpace($androidSdk)) { throw 'Android SDK path missing for APK permission verification' }
        $buildTools = Join-Path $androidSdk 'build-tools'
        $aaptCandidate = @(Get-ChildItem -LiteralPath $buildTools -Directory | Where-Object Name -match '^\d+\.\d+\.\d+$' | Sort-Object { [version]$_.Name } -Descending | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'aapt2') -PathType Leaf } | Select-Object -First 1)
        if ($aaptCandidate.Count -ne 1) { throw 'Installed Android aapt2 missing' }
        $aapt2 = Join-Path $aaptCandidate[0].FullName 'aapt2'
        $aaptVersionLines = @(& $aapt2 version 2>&1 | ForEach-Object { $_.ToString().Trim() })
        if ($LASTEXITCODE -ne 0) { throw 'Android aapt2 version failed' }
        if ($aaptVersionLines.Count -ne 1 -or $aaptVersionLines[0] -notmatch '^Android Asset Packaging Tool \(aapt\) [0-9][A-Za-z0-9._-]{1,80}$') { throw 'Android aapt2 version is empty or malformed' }
        $aaptVersion = $aaptVersionLines[0]
        $aaptVersionLog = Join-Path $logRoot '05a-aapt2-version.txt'
        [System.IO.File]::WriteAllText($aaptVersionLog, $aaptVersion + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
        $proof.android_network_permissions = @()
        foreach ($apkName in @('app-arm64-v8a-release.apk','app-armeabi-v7a-release.apk','app-x86_64-release.apk')) {
            $apkPath = Join-Path 'build/app/outputs/flutter-apk' $apkName
            if (-not (Test-Path -LiteralPath $apkPath -PathType Leaf)) { throw 'Expected release APK missing for permission verification' }
            $permissionLines = @(& $aapt2 dump permissions $apkPath)
            if ($LASTEXITCODE -ne 0) { throw 'Android APK permissions could not be read' }
            $internet = @($permissionLines | Where-Object { $_ -match "^uses-permission: name='android\.permission\.INTERNET'\s*$" })
            if ($internet.Count -ne 1) { throw 'Release APK must declare exactly one unrestricted INTERNET permission' }
            $permissionLog = Join-Path $logRoot ('05a-permissions-' + $apkName + '.txt')
            [System.IO.File]::WriteAllText($permissionLog, [string]::Join([Environment]::NewLine, $permissionLines) + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
            $proof.android_network_permissions += [ordered]@{
                apk=$apkName
                apk_sha256=(Get-FileHash -LiteralPath $apkPath -Algorithm SHA256).Hash
                permission='android.permission.INTERNET'
                unrestricted=$true
                report_sha256=(Get-FileHash -LiteralPath $permissionLog -Algorithm SHA256).Hash
                aapt2_version=$aaptVersion
                aapt2_version_report_sha256=(Get-FileHash -LiteralPath $aaptVersionLog -Algorithm SHA256).Hash
                aapt2_sha256=(Get-FileHash -LiteralPath $aapt2 -Algorithm SHA256).Hash
            }
            Write-Output ('NEOTH_ANDROID_INTERNET_PASS=' + $apkName)
        }
        # Hosted Android JVM policy tests. Never invoke this materializer locally.
        Push-Location 'android'
        try {
            $previewLog = Join-Path $logRoot '05b-notification-preview-unit-tests.log'
            & './gradlew' --no-daemon --max-workers=1 --console=plain ':app:testReleaseUnitTest' '--tests' 'org.neoth.companion.NotificationPreviewAdmissionTest' 2>&1 | Tee-Object -LiteralPath $previewLog
            if ($LASTEXITCODE -ne 0) { throw 'Android notification preview unit tests failed' }
        } finally { Pop-Location }
        $previewReportPath = 'build/app/test-results/testReleaseUnitTest/TEST-org.neoth.companion.NotificationPreviewAdmissionTest.xml'
        if (-not (Test-Path -LiteralPath $previewReportPath -PathType Leaf)) { throw 'Preview unit-test report missing' }
        [xml]$previewReport = Get-Content -LiteralPath $previewReportPath -Raw
        $previewNames = @(
            'disabledOrUnconfiguredOwnerRejects',
            'permissionForegroundAndLockEachGateAdmission',
            'everyPackageNeedsItsOwnExplicitSelection',
            'quietHoursHandleSameDayOvernightAndAllDay',
            'staleFutureAndPreConsentPostsReject',
            'originalDeadlineCannotBeExtendedByDelayedDelivery',
            'duplicateSourceDoesNotRefreshOrReplacePreview',
            'sourceIdentitySeparatesApps',
            'fullReplayWindowDropsNewEntriesWithoutEvictingLiveIdentities',
            'suspensionAndNewConsentCannotReplayAnEarlierEvent',
            'unicodeLimitsPreserveCompleteCodepoints',
            'emptyAndGroupSummaryNotificationsNeverCreateCards',
            'elapsedAndWallDriftCannotReopenExpiredReplayWindow',
            'backwardsClocksFailClosed'
        )
        $previewSuite = $previewReport.testsuite
        $previewCases = @($previewSuite.testcase)
        if ($previewSuite.name -cne 'org.neoth.companion.NotificationPreviewAdmissionTest' -or [int]$previewSuite.tests -ne 14 -or [int]$previewSuite.failures -ne 0 -or [int]$previewSuite.errors -ne 0 -or [int]$previewSuite.skipped -ne 0 -or $previewCases.Count -ne 14) { throw 'Preview unit-test suite differs or did not pass' }
        if (@(Compare-Object -CaseSensitive $previewNames @($previewCases.name)).Count -ne 0 -or @($previewCases.name | Sort-Object -Unique).Count -ne 14) { throw 'Preview test identity set differs' }
        foreach ($previewCase in $previewCases) {
            if ($previewCase.classname -cne 'org.neoth.companion.NotificationPreviewAdmissionTest' -or $null -ne $previewCase.failure -or $null -ne $previewCase.error -or $null -ne $previewCase.skipped) { throw 'Preview case lacks a success result' }
            Write-Output ('NEOTH_PREVIEW_UNIT_PASS=' + $previewCase.name)
        }
        $proof.notification_preview_unit_tests = [ordered]@{ passed=14; names=$previewNames; report_sha256=(Get-FileHash -LiteralPath $previewReportPath -Algorithm SHA256).Hash; log_sha256=(Get-FileHash -LiteralPath $previewLog -Algorithm SHA256).Hash }
        foreach ($artifact in 'build\app\outputs\flutter-apk\app-arm64-v8a-release.apk','build\app\outputs\flutter-apk\app-armeabi-v7a-release.apk','build\app\outputs\flutter-apk\app-x86_64-release.apk') {
            if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) { throw "expected Android export missing: $artifact" }
            $proof.artifacts += [ordered]@{ path=$artifact; sha256=(Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash }
        }
    }
    if ($Stage -in @('ios','all')) {
        Invoke-Flutter -Name '06-build-ios' -Arguments @('build','ios','--release','--no-codesign')
        $runner = Join-Path (Get-Location) 'build\ios\iphoneos\Runner.app\Runner'
        if (-not (Test-Path -LiteralPath $runner -PathType Leaf)) { throw 'unsigned iOS Runner binary is missing' }
        $runnerPlist = Join-Path (Get-Location) 'build/ios/iphoneos/Runner.app/Info.plist'
        if (-not (Test-Path -LiteralPath $runnerPlist -PathType Leaf)) { throw 'Built iOS application Info.plist missing' }
        $localNetworkUsage = @(& /usr/libexec/PlistBuddy -c 'Print :NSLocalNetworkUsageDescription' $runnerPlist)
        if ($LASTEXITCODE -ne 0 -or $localNetworkUsage.Count -ne 1 -or $localNetworkUsage[0] -cne 'NEOTH uses the local network to connect securely to your paired NEOTH daemon.') { throw 'Built iOS application has no expected local-network privacy explanation' }
        $proof.ios_local_network_usage = [ordered]@{ description=$localNetworkUsage[0]; info_plist_sha256=(Get-FileHash -LiteralPath $runnerPlist -Algorithm SHA256).Hash }
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
