import java.net.URI
import java.util.Base64
import java.util.Properties
import org.gradle.api.artifacts.result.UnresolvedDependencyResult

plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

val uploadKeystorePath = providers.environmentVariable("BUZZ_ANDROID_UPLOAD_KEYSTORE_PATH").orNull
val uploadKeystorePassword = providers.environmentVariable("BUZZ_ANDROID_UPLOAD_KEYSTORE_PASSWORD").orNull
val uploadKeyAlias = providers.environmentVariable("BUZZ_ANDROID_UPLOAD_KEY_ALIAS").orNull
val uploadKeyPassword = providers.environmentVariable("BUZZ_ANDROID_UPLOAD_KEY_PASSWORD").orNull
val uploadSigningValues =
    mapOf(
        "BUZZ_ANDROID_UPLOAD_KEYSTORE_PATH" to uploadKeystorePath,
        "BUZZ_ANDROID_UPLOAD_KEYSTORE_PASSWORD" to uploadKeystorePassword,
        "BUZZ_ANDROID_UPLOAD_KEY_ALIAS" to uploadKeyAlias,
        "BUZZ_ANDROID_UPLOAD_KEY_PASSWORD" to uploadKeyPassword,
    )
val missingUploadSigningValues = uploadSigningValues.filterValues { it.isNullOrBlank() }.keys
val hasUploadSigning = missingUploadSigningValues.isEmpty()
val dartDefines = providers.gradleProperty("dart-defines").orNull.orEmpty()
val pushGatewayDefinePrefix = "BUZZ_PUSH_GATEWAY_URL="
val pushGatewayOrigins =
    dartDefines.split(',').mapNotNull { encoded ->
        val define = runCatching { String(Base64.getDecoder().decode(encoded)) }.getOrNull()
        define
            ?.takeIf { it.startsWith(pushGatewayDefinePrefix) }
            ?.removePrefix(pushGatewayDefinePrefix)
    }
fun isValidPushGatewayOrigin(value: String, requireHttps: Boolean): Boolean {
    val uri = runCatching { URI(value) }.getOrNull() ?: return false
    val scheme = uri.scheme?.lowercase()
    return (scheme == "https" || (!requireHttps && scheme == "http")) &&
        !uri.host.isNullOrBlank() &&
        uri.rawUserInfo == null &&
        (uri.rawPath.isNullOrEmpty() || uri.rawPath == "/") &&
        uri.rawQuery == null &&
        uri.rawFragment == null &&
        (if (requireHttps) uri.port == -1 else uri.port == -1 || uri.port in 1..65535)
}

tasks.matching { it.name.startsWith("compileFlutterBuild") }.configureEach {
    doFirst {
        val requireHttps = !name.endsWith("Debug", ignoreCase = true)
        val hasValidPushGatewayOrigin =
            pushGatewayOrigins.isEmpty() ||
                (pushGatewayOrigins.size == 1 &&
                    isValidPushGatewayOrigin(pushGatewayOrigins.single(), requireHttps))
        if (!hasValidPushGatewayOrigin) {
            throw GradleException(
                "When supplied, BUZZ_PUSH_GATEWAY_URL must be an " +
                    (if (requireHttps) "HTTPS" else "HTTP(S)") +
                    " origin without " + (if (requireHttps) "an explicit port, " else "") +
                    "credentials, path, query, or fragment.",
            )
        }
    }
}

// Worktree-aware debug identity (gitignored, written by
// scripts/mobile-worktree-overrides.sh): debug builds from a git worktree get a
// branch-labelled app name and a unique applicationId suffix so builds from
// multiple worktrees install side by side. Release builds never read this.
val worktreePropsFile = rootProject.file("worktree.properties")
val worktreeProps =
    Properties().apply {
        if (worktreePropsFile.isFile) worktreePropsFile.inputStream().use { load(it) }
    }
// Optional gitignored developer overrides are loaded after the generated
// worktree values. They are consumed only by the debug build type below, so a
// long-lived device test build can keep a stable, descriptive local identity
// without changing release/profile or being overwritten by the worktree script.
val appOverridesFile = rootProject.file("AppOverrides.properties")
val appOverrides =
    Properties().apply {
        if (appOverridesFile.isFile) appOverridesFile.inputStream().use { load(it) }
    }
val worktreeLabel = worktreeProps.getProperty("label")?.takeIf { it.isNotBlank() }
if (worktreeLabel != null && !worktreeLabel.matches(Regex("""[A-Za-z0-9._-]+"""))) {
    throw GradleException(
        "worktree.properties label must match [A-Za-z0-9._-]+ (safe for string " +
            "resources), got: " + worktreeLabel,
    )
}
val worktreeAppName = worktreeProps.getProperty("appName")?.takeIf { it.isNotBlank() }
if (worktreeAppName != null && !worktreeAppName.matches(Regex("""[A-Za-z0-9._() \-]+"""))) {
    throw GradleException(
        "worktree.properties appName must contain only letters, numbers, spaces, ., _, -, or " +
            "parentheses, got: " + worktreeAppName,
    )
}
val worktreeIdSuffix =
    worktreeProps.getProperty("applicationIdSuffix")?.takeIf { it.isNotBlank() }
val debugIdSuffix =
    appOverrides.getProperty("applicationIdSuffix")?.takeIf { it.isNotBlank() }
        ?: worktreeIdSuffix
if (debugIdSuffix != null && !debugIdSuffix.matches(Regex("""\.[a-z][a-z0-9_]*"""))) {
    throw GradleException(
        "debug applicationIdSuffix must match \\.[a-z][a-z0-9_]*, got: " +
            debugIdSuffix,
    )
}
val debugAppName = appOverrides.getProperty("appName")?.takeIf { it.isNotBlank() }
if (
    debugAppName != null &&
        !debugAppName.matches(Regex("""[A-Za-z0-9][A-Za-z0-9 ._()\-]{0,39}"""))
) {
    throw GradleException(
        "debug appName must be 1-40 resource-safe characters, got: " + debugAppName,
    )
}

// Release signing modes:
//   - "upload-keystore" (default): sign with the CI-vended upload keystore;
//     release builds fail loudly when any credential is missing.
//   - "external": deliberately produce an UNSIGNED release bundle for a
//     pipeline that signs through the central APK Signer service (Cashkite,
//     BOT-1234). No keystore material may be present in this mode.
val releaseSigningMode =
    providers.environmentVariable("BUZZ_ANDROID_RELEASE_SIGNING").orNull ?: "upload-keystore"
val externalReleaseSigning = releaseSigningMode == "external"
if (releaseSigningMode !in setOf("upload-keystore", "external")) {
    throw GradleException(
        "BUZZ_ANDROID_RELEASE_SIGNING must be \"upload-keystore\" or \"external\", got: " +
            releaseSigningMode,
    )
}
if (externalReleaseSigning && uploadSigningValues.values.any { !it.isNullOrBlank() }) {
    throw GradleException(
        "BUZZ_ANDROID_RELEASE_SIGNING=external must not be combined with " +
            "BUZZ_ANDROID_UPLOAD_* credentials; unset one of them.",
    )
}

android {
    namespace = "xyz.block.buzz.mobile"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_17.toString()
    }

    defaultConfig {
        applicationId = "xyz.block.buzz.mobile"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        resValue("string", "app_name", "Buzz")
    }

    signingConfigs {
        if (hasUploadSigning) {
            create("upload") {
                storeFile = file(requireNotNull(uploadKeystorePath))
                storePassword = uploadKeystorePassword
                keyAlias = uploadKeyAlias
                keyPassword = uploadKeyPassword
            }
        }
    }

    buildTypes {
        debug {
            // Only debug builds take the worktree identity; release/profile
            // keep the production applicationId and label.
            if (debugIdSuffix != null) {
                applicationIdSuffix = debugIdSuffix
            }
            val resolvedAppName =
                debugAppName
                    ?: worktreeAppName
                    ?: worktreeLabel?.let { "Buzz ($it)" }
            if (resolvedAppName != null) {
                resValue("string", "app_name", resolvedAppName)
            }
        }
        release {
            if (hasUploadSigning) {
                signingConfig = signingConfigs.getByName("upload")
            }
        }
    }
}

dependencies {
    implementation("com.google.android.play:age-signals:0.0.4")
    implementation("androidx.appcompat:appcompat:1.6.1")

    testImplementation(kotlin("test"))

    androidTestImplementation(kotlin("test"))
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
}

// QR scanning must stay independent of ML Kit and Firebase ML. This rule is
// evaluated for every resolved Android configuration, including transitive
// dependencies pulled in by Flutter plugins.
val forbiddenQrDependencyPrefixes =
    listOf(
        "com.google.mlkit:",
        "com.google.firebase:firebase-ml",
        "com.google.android.odml:",
    )
val isForbiddenQrDependency = { group: String?, name: String ->
    val coordinate = "$group:$name".lowercase()
    val isPlayServicesScanner =
        group == "com.google.android.gms" &&
            (name.lowercase().contains("mlkit") || name == "play-services-code-scanner")
    isPlayServicesScanner || forbiddenQrDependencyPrefixes.any(coordinate::startsWith)
}

configurations.configureEach {
    resolutionStrategy.eachDependency {
        val coordinate = "${requested.group}:${requested.name}".lowercase()
        if (isForbiddenQrDependency(requested.group, requested.name)) {
            throw GradleException(
                "Forbidden Google ML/Firebase ML Android dependency: $coordinate. " +
                    "Pairing QR scanning must use the ZXing-C++ FFI implementation.",
            )
        }
    }
}

val checkQrDependencyPolicy by tasks.registering {
    group = "verification"
    description = "Resolves the packaged Android runtime and rejects ML Kit/Firebase ML artifacts."
}

androidComponents {
    onVariants(selector().withBuildType("debug")) { variant ->
        checkQrDependencyPolicy.configure {
            doLast {
                // The component graph carries every transitive module
                // coordinate without forcing Gradle to choose among each
                // Android plugin's artifact-type subvariants.
                val components =
                    variant.runtimeConfiguration.incoming.resolutionResult.allComponents
                val forbidden =
                    components.mapNotNull { it.moduleVersion }.filter {
                        isForbiddenQrDependency(it.group, it.name)
                    }
                if (forbidden.isNotEmpty()) {
                    throw GradleException(
                        "Forbidden Google ML/Firebase ML Android dependencies: " +
                            forbidden.sortedBy { it.toString() }.joinToString(", "),
                    )
                }
                logger.lifecycle(
                    "QR dependency policy passed for ${variant.name}: " +
                        "${components.size} resolved components inspected.",
                )
            }
        }
    }
}

tasks.named("check").configure {
    dependsOn(checkQrDependencyPolicy)
}

tasks.withType<Test>().configureEach {
    systemProperty("buzz.android.appProjectDir", projectDir.absolutePath)
}

// CI consumes this canonical manifest instead of scraping Gradle's
// human-readable dependency report. Keep every installable app variant in the
// list so a variant-specific Google SDK dependency cannot bypass the APK gate.
val buzzRuntimeClasspathNames =
    listOf(
        "debugRuntimeClasspath",
        "profileRuntimeClasspath",
        "releaseRuntimeClasspath",
    )
val buzzRuntimeDependencyManifest =
    layout.buildDirectory.file("reports/buzz-runtime-dependencies.tsv")

tasks.register("writeBuzzRuntimeDependencyManifest") {
    group = "verification"
    description = "Writes canonical runtime dependency coordinates for every app variant."

    doLast {
        val missingConfigurations =
            buzzRuntimeClasspathNames.filter { configurations.findByName(it) == null }
        if (missingConfigurations.isNotEmpty()) {
            throw GradleException(
                "Missing required app runtime configurations: " +
                    missingConfigurations.joinToString(", "),
            )
        }

        val lines = mutableListOf<String>()
        for (configurationName in buzzRuntimeClasspathNames.sorted()) {
            lines += "configuration\t$configurationName"
            val configuration = configurations.getByName(configurationName)
            val resolutionResult = configuration.incoming.resolutionResult
            val unresolved =
                resolutionResult.allDependencies
                    .filterIsInstance<UnresolvedDependencyResult>()
                    .map { dependency -> dependency.attempted.displayName }
                    .distinct()
                    .sorted()
            if (unresolved.isNotEmpty()) {
                throw GradleException(
                    "Unresolved $configurationName dependencies: " + unresolved.joinToString(", "),
                )
            }
            val coordinates =
                resolutionResult.allComponents
                    .mapNotNull { component -> component.moduleVersion }
                    .map { module -> "${module.group}:${module.name}:${module.version}" }
                    .distinct()
                    .sorted()
            lines += coordinates.map { coordinate ->
                "component\t$configurationName\t$coordinate"
            }
        }

        val manifest = buzzRuntimeDependencyManifest.get().asFile
        manifest.parentFile.mkdirs()
        manifest.writeText(lines.sorted().joinToString(separator = "\n", postfix = "\n"))
    }
}

gradle.taskGraph.whenReady {
    val buildsRelease = allTasks.any { task ->
        task.project == project && task.name in setOf("assembleRelease", "bundleRelease")
    }
    if (buildsRelease && externalReleaseSigning) {
        // External signing: the unsigned bundle goes to the central APK
        // Signer. All keystore checks are intentionally skipped; the
        // guard above already rejected any BUZZ_ANDROID_UPLOAD_* values.
        return@whenReady
    }
    if (buildsRelease && !hasUploadSigning) {
        throw GradleException(
            "Release builds require Android upload signing credentials. Missing: " +
                missingUploadSigningValues.sorted().joinToString(", ") +
                ". For central APK Signer pipelines set BUZZ_ANDROID_RELEASE_SIGNING=external.",
        )
    }
    if (buildsRelease) {
        val configuredKeystore = File(requireNotNull(uploadKeystorePath))
        if (!configuredKeystore.isAbsolute) {
            throw GradleException(
                "BUZZ_ANDROID_UPLOAD_KEYSTORE_PATH must be absolute: $configuredKeystore",
            )
        }
        val keystore = file(configuredKeystore)
        val repositoryRoot = rootProject.projectDir.parentFile.parentFile.canonicalFile
        if (keystore.canonicalFile.toPath().startsWith(repositoryRoot.toPath())) {
            throw GradleException(
                "BUZZ_ANDROID_UPLOAD_KEYSTORE_PATH must be outside the repository: $keystore",
            )
        }
        if (!keystore.isFile || !keystore.canRead()) {
            throw GradleException(
                "BUZZ_ANDROID_UPLOAD_KEYSTORE_PATH is not a readable file: $keystore",
            )
        }
    }
}

flutter {
    source = "../.."
}
