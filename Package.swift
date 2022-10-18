// swift-tools-version:5.3

import PackageDescription

let package = Package(
    name: "TreeSitterSSHClientConfig",
    platforms: [.macOS(.v10_13), .iOS(.v11)],
    products: [
        .library(name: "TreeSitterSSHClientConfig", targets: ["TreeSitterSSHClientConfig"]),
    ],
    dependencies: [],
    targets: [
        .target(name: "TreeSitterSSHClientConfig",
                path: ".",
                exclude: [
                    "binding.gyp",
                    "bindings",
                    "Cargo.lock",
                    "Cargo.toml",
                    "CITATION.cff",
                    "dev",
                    "examples",
                    "fuzz",
                    "grammar.js",
                    "LICENSE",
                    "Makefile",
                    "package.json",
                    "package-lock.json",
                    "README.md",
                    "src/grammar.json",
                    "src/node-types.json",
                    "test",
                ],
                sources: [
                    "src/parser.c",
                ],
                resources: [
                    .copy("queries")
                ],
                publicHeadersPath: "bindings/swift",
                cSettings: [.headerSearchPath("src")])
    ]
)
