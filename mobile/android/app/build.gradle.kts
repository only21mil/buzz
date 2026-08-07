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
val directReleaseKeystorePath =
    providers.environmentVariable("BUZZ_ANDROID_RELEASE_KEYSTORE_PATH").orNull
val directReleaseKeystorePassword =
    providers.environmentVariable("BUZZ_ANDROID_RELEASE_KEYSTORE_PASSWORD").orNull
val directReleaseKeyAlias = providers.environmentVariable("BUZZ_ANDROID_RELEASE_KEY_ALIAS").orNull
val directReleaseKeyPassword =
    providers.environmentVariable("BUZZ_ANDROID_RELEASE_KEY_PASSWORD").orNull
val directReleaseSigningValues =
    mapOf(
        "BUZZ_ANDROID_RELEASE_KEYSTORE_PATH" to directReleaseKeystorePath,
        "BUZZ_ANDROID_RELEASE_KEYSTORE_PASSWORD" to directReleaseKeystorePassword,
        "BUZZ_ANDROID_RELEASE_KEY_ALIAS" to directReleaseKeyAlias,
        "BUZZ_ANDROID_RELEASE_KEY_PASSWORD" to directReleaseKeyPassword,
    )
val missingDirectReleaseSigningValues =
    directReleaseSigningValues.filterValues { it.isNullOrBlank() }.keys
val hasDirectReleaseSigning = missingDirectReleaseSigningValues.isEmpty()

// Worktree-aware debug identity (gitignored, written by
// scripts/mobile-worktree-overrides.sh): debug builds from a git worktree get a
// branch-labelled app name and a unique applicationId suffix so builds from
// multiple worktrees install side by side. Release builds never read this.
val worktreePropsFile = rootProject.file("worktree.properties")
val worktreeProps =
    Properties().apply {
        if (worktreePropsFile.isFile) worktreePropsFile.inputStream().use { load(it) }
    }
val worktreeLabel = worktreeProps.getProperty("label")?.takeIf { it.isNotBlank() }
if (worktreeLabel != null && !worktreeLabel.matches(Regex("""[A-Za-z0-9._-]+"""))) {
    throw GradleException(
        "worktree.properties label must match [A-Za-z0-9._-]+ (safe for string " +
            "resources), got: " + worktreeLabel,
    )
}
val worktreeIdSuffix =
    worktreeProps.getProperty("applicationIdSuffix")?.takeIf { it.isNotBlank() }
if (worktreeIdSuffix != null && !worktreeIdSuffix.matches(Regex("""\.[a-z][a-z0-9_]*"""))) {
    throw GradleException(
        "worktree.properties applicationIdSuffix must match \\.[a-z][a-z0-9_]*, got: " +
            worktreeIdSuffix,
    )
}

// Release signing modes:
//   - "upload-keystore" (default): sign with the CI-vended upload keystore;
//     release builds fail loudly when any credential is missing.
//   - "external": deliberately produce an UNSIGNED release bundle for a
//     pipeline that signs through the central APK Signer service (Cashkite,
//     BOT-1234). No keystore material may be present in this mode.
//   - "direct-release": sign a direct-download APK with Victor's persistent
//     fork distribution key. This is a separate lineage from Block's upload
//     key and must use only BUZZ_ANDROID_RELEASE_* credentials.
val releaseSigningMode =
    providers.environmentVariable("BUZZ_ANDROID_RELEASE_SIGNING").orNull ?: "upload-keystore"
val externalReleaseSigning = releaseSigningMode == "external"
val directReleaseSigning = releaseSigningMode == "direct-release"
if (releaseSigningMode !in setOf("upload-keystore", "external", "direct-release")) {
    throw GradleException(
        "BUZZ_ANDROID_RELEASE_SIGNING must be \"upload-keystore\", \"external\", or " +
            "\"direct-release\", got: $releaseSigningMode",
    )
}
if ((externalReleaseSigning || directReleaseSigning) &&
    uploadSigningValues.values.any { !it.isNullOrBlank() }
) {
    throw GradleException(
        "BUZZ_ANDROID_RELEASE_SIGNING=$releaseSigningMode must not be combined with " +
            "BUZZ_ANDROID_UPLOAD_* credentials.",
    )
}
if (!directReleaseSigning && directReleaseSigningValues.values.any { !it.isNullOrBlank() }) {
    throw GradleException(
        "BUZZ_ANDROID_RELEASE_* credentials require " +
            "BUZZ_ANDROID_RELEASE_SIGNING=direct-release.",
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
        if (hasDirectReleaseSigning) {
            create("directRelease") {
                storeFile = file(requireNotNull(directReleaseKeystorePath))
                storePassword = directReleaseKeystorePassword
                keyAlias = directReleaseKeyAlias
                keyPassword = directReleaseKeyPassword
            }
        }
    }

    buildTypes {
        debug {
            // Only debug builds take the worktree identity; release/profile
            // keep the production applicationId and label.
            if (worktreeIdSuffix != null) {
                applicationIdSuffix = worktreeIdSuffix
            }
            if (worktreeLabel != null) {
                resValue("string", "app_name", "Buzz ($worktreeLabel)")
            }
        }
        release {
            if (directReleaseSigning && hasDirectReleaseSigning) {
                signingConfig = signingConfigs.getByName("directRelease")
            } else if (!directReleaseSigning && hasUploadSigning) {
                signingConfig = signingConfigs.getByName("upload")
            }
        }
    }
}

dependencies {
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
    val selectedSigningValues =
        if (directReleaseSigning) directReleaseSigningValues else uploadSigningValues
    val selectedMissingValues =
        if (directReleaseSigning) missingDirectReleaseSigningValues else missingUploadSigningValues
    val hasSelectedSigning =
        if (directReleaseSigning) hasDirectReleaseSigning else hasUploadSigning
    val selectedKeystorePath =
        if (directReleaseSigning) directReleaseKeystorePath else uploadKeystorePath
    val selectedPathVariable =
        if (directReleaseSigning) {
            "BUZZ_ANDROID_RELEASE_KEYSTORE_PATH"
        } else {
            "BUZZ_ANDROID_UPLOAD_KEYSTORE_PATH"
        }
    if (buildsRelease && !hasSelectedSigning) {
        throw GradleException(
            "Release builds require complete Android signing credentials. Missing: " +
                selectedMissingValues.sorted().joinToString(", ") +
                ". For central APK Signer pipelines set BUZZ_ANDROID_RELEASE_SIGNING=external.",
        )
    }
    if (buildsRelease) {
        check(selectedSigningValues.values.all { !it.isNullOrBlank() })
        val configuredKeystore = File(requireNotNull(selectedKeystorePath))
        if (!configuredKeystore.isAbsolute) {
            throw GradleException(
                "$selectedPathVariable must be absolute: $configuredKeystore",
            )
        }
        val keystore = file(configuredKeystore)
        val repositoryRoot = rootProject.projectDir.parentFile.parentFile.canonicalFile
        if (keystore.canonicalFile.toPath().startsWith(repositoryRoot.toPath())) {
            throw GradleException(
                "$selectedPathVariable must be outside the repository: $keystore",
            )
        }
        if (!keystore.isFile || !keystore.canRead()) {
            throw GradleException(
                "$selectedPathVariable is not a readable file: $keystore",
            )
        }
    }
}

flutter {
    source = "../.."
}
