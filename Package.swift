// swift-tools-version:5.3

import PackageDescription

let package = Package(
    name: "TreeSitterSshClientConfig",
    platforms: [.macOS(.v10_13), .iOS(.v11)],
    products: [
        .library(name: "TreeSitterSshClientConfig", targets: ["TreeSitterSshClientConfig"]),
    ],
    dependencies: [],
    targets: [
        .target(name: "TreeSitterSshClientConfig",
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
