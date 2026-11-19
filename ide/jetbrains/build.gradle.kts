// PATHOS plugin for JetBrains IDEs (IntelliJ Platform).
// Every version is pinned here or in gradle.properties; Gradle verifies the
// SHA-256 of every downloaded artifact against gradle/verification-metadata.xml.

import org.jetbrains.intellij.platform.gradle.IntelliJPlatformType
import org.jetbrains.intellij.platform.gradle.TestFrameworkType
import org.jetbrains.kotlin.gradle.dsl.JvmDefaultMode
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinVersion

plugins {
    id("org.jetbrains.kotlin.jvm") version "2.4.21"
    id("org.jetbrains.intellij.platform") version "2.20.1"
}

group = "io.github.quditmind.pathos"
version = providers.gradleProperty("pluginVersion").get()

repositories {
    mavenCentral()
    intellijPlatform {
        defaultRepositories()
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_21)
        // The IDE provides the Kotlin standard library; do not use newer API than 2025.3 bundles.
        apiVersion.set(KotlinVersion.KOTLIN_2_2)
        languageVersion.set(KotlinVersion.KOTLIN_2_2)
        // Java default methods for interfaces: no Kotlin bridges overriding platform
        // interface defaults (flagged as deprecated/experimental API use by the verifier).
        jvmDefault.set(JvmDefaultMode.NO_COMPATIBILITY)
    }
}

dependencies {
    intellijPlatform {
        intellijIdea(providers.gradleProperty("platformVersion"))
        testFramework(TestFrameworkType.Platform)
    }
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.opentest4j:opentest4j:1.3.0")
}

intellijPlatform {
    // No settings search index: building it starts a headless IDE.
    buildSearchableOptions = false
    // No forms or Java @NotNull to instrument.
    instrumentCode = false

    pluginConfiguration {
        id = "io.github.quditmind.pathos"
        name = "PATHOS Security"
        version = providers.gradleProperty("pluginVersion")
        ideaVersion {
            sinceBuild = providers.gradleProperty("pluginSinceBuild")
            untilBuild = providers.gradleProperty("pluginUntilBuild")
        }
    }

    pluginVerification {
        ides {
            current()
            create(IntelliJPlatformType.IntellijIdea, providers.gradleProperty("verifierIdeVersion").get())
        }
    }
}

tasks {
    test {
        // Headless IDE for BasePlatformTestCase.
        systemProperty("java.awt.headless", "true")
    }
}
