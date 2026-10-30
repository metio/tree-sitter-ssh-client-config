# Contributor Guide

## Local Development

### Requirements

In order to build this project locally, you need the following software:

- [NodeJS](https://nodejs.org/) >= 18 LTS
- [GNU Make](https://www.gnu.org/software/make/) >= this decade (**optional** in case you want to use the `Makefile`)
- [breto](https://github.com/metio/breto) (**optional** in case you want breto to install Node.js, Rust and htmlq)
- [AFL++](https://aflplus.plus/) >= 4.00c (**optional** in case you want to do some fuzzing with AFL++)
- [Rust](https://www.rust-lang.org/) >= 1.57 (**optional** in case you want to use AFL++)

### Using NPM

Install the dependencies:

```shell
$ npm install
```

Generate the grammar:

```shell
$ npm run generate
```

Run the tests:

```shell
$ npm run test
```

Parse all examples:

```shell
$ npm run examples
```

Parse a single example and show syntax tree:

```shell
$ npm run parse examples/github-maskray-config
```

### Using Make

Generate the grammar:

```shell
$ make generate
```

Run the tests:

```shell
$ make test
```

Parse all examples:

```shell
$ make examples
```

Parse a single example and show syntax tree:

```shell
$ make parse file=examples/github-maskray-config
```

### Using breto

Put the tools named in `.breto.edn` on your `PATH`, then use the NPM or Make commands above:

```shell
$ eval "$(breto env)"
```

## Helpful Tasks

In case you do not want to develop on this project itself, you can still help! Thanks for taking your time to do so <3

### Using tree-sitter-ssh-client-config

The most helpful feedback is always provided by users themselves. Therefore, do not hesitate to use this grammar, integrate it, extend it, report bugs, and request features.

### New SSH Configuration Options

The upstream [OpenSSH](https://www.openssh.com/) project is actively developed and will introduce new config options from time-to-time. In order to keep up with OpenSSH, this grammar needs to be adjusted. You can help with this task by monitoring OpenSSH release notes and Open a ticket to notify maintainers of the new config option.

### Fuzzing

In order to ensure that this grammar is safe to use, we are using [fuzz testing](https://en.wikipedia.org/wiki/Fuzzing). You can help with this task by running any of the supported fuzzing tools on your local machine.

#### Jsfuzz

[Jsfuzz](https://gitlab.com/gitlab-org/security-products/analyzers/fuzzers/jsfuzz) is a coverage-guides fuzzer for JavaScript/NodeJS packages. All required software to run Jsfuzz will be installed automatically on your system once you execute these steps:

```shell
# manually
$ npm --prefix fuzz/jsfuzz install
$ npm --prefix fuzz/jsfuzz run fuzz

# using make
$ make jsfuzz
```

**Note**: This setup is experimental and seems to produce lots of false-positives, e.g. it produces SSH client configs that do **NOT** actually crash tree-sitter using this grammar. In order to verify that, run:

```shell
# manually
$ npm run parse fuzz/jsfuzz/crash.config

# using make
$ make jsfuzz-crash
```

In case the above command actually crashes this grammar, please open a bug report and attach the file `<project-root>/fuzz/jsfuzz/crash.config`.

#### AFL++

[AFL++](https://aflplus.plus/) is a security-oriented fuzzer without any particular focus on programming languages. In order to run this fuzzer, you must install it along with Rust on your local machine. Once you have done that, follow these steps to run AFL++:

```shell
# manually
$ cargo build --manifest-path fuzz/aflplusplus/Cargo.toml --release
$ afl-fuzz -i examples/ -o fuzz/aflplusplus/out -n -d -m none -f fuzz/aflplusplus/out/current.config -- fuzz/aflplusplus/target/release/tree-sitter-afl-fuzzer fuzz/aflplusplus/out/current.config

# using make
$ make aflfuzz
```

AFL++ will write any crashes that it could produce to `<project-root>/fuzz/aflplusplus/out/crashes`. Please open a bug report and attach any crashes that were produced.
