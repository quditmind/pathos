// Plugins resolve from the Gradle Plugin Portal and Maven Central (the
// portal no longer serves every transitive dependency of the Kotlin and
// IntelliJ Platform plugins); every artifact is still checked against
// gradle/verification-metadata.xml.
pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

rootProject.name = "pathos-jetbrains"
