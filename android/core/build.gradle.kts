// Pure Kotlin/JVM: the MDANetPro protocol, crypto, P2P transport and network logic.
// No Android dependencies, so it runs in unit tests and in the CLI used for interop tests.
plugins {
    id("org.jetbrains.kotlin.jvm")
}
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
kotlin { jvmToolchain(17) }
dependencies {
    testImplementation("junit:junit:4.13.2")
}
