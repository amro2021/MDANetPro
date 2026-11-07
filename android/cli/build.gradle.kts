// Headless node for interoperability tests against the Python app (used by CI).
plugins {
    id("org.jetbrains.kotlin.jvm")
    application
}
kotlin { jvmToolchain(17) }
dependencies { implementation(project(":core")) }
application { mainClass.set("com.mdanetpro.cli.MainKt") }
