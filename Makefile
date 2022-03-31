node_modules:
	npm install

.PHONY: init
init: node_modules
	npm run init

.PHONY: generate
generate: node_modules
	npm run generate

.PHONY: test
test: generate
	npm run test

.PHONY: examples
examples: init generate
	npm run examples

.PHONY: parse
parse: init generate
	npm run parse $(file)

.PHONY: jsfuzz
jsfuzz: fuzz/jsfuzz/node_modules
	npm --prefix fuzz/jsfuzz run fuzz

fuzz/jsfuzz/node_modules:
	npm --prefix fuzz/jsfuzz install

.PHONY: jsfuzz-crash
jsfuzz-crash:
	npm run parse fuzz/jsfuzz/crash.config

.PHONY: aflfuzz
aflfuzz: fuzz/aflplusplus/target/release/tree-sitter-afl-fuzzer
	afl-fuzz -i examples/ -o fuzz/aflplusplus/out -n -d -m none -f fuzz/aflplusplus/out/current.config -- fuzz/aflplusplus/target/release/tree-sitter-afl-fuzzer fuzz/aflplusplus/out/current.config

fuzz/aflplusplus/target/release/tree-sitter-afl-fuzzer:
	cargo build --manifest-path fuzz/aflplusplus/Cargo.toml --release
