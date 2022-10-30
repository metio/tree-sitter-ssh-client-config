# tree-sitter-ssh-client-config

SSH client config grammar for [tree-sitter](https://github.com/tree-sitter/tree-sitter).

## Usage

This grammar is available at [crates.io](https://crates.io/crates/tree-sitter-ssh-client-config), and you can use it together with the [Rust language binding](https://github.com/tree-sitter/tree-sitter/tree/master/lib/binding_rust).

```rust
use tree_sitter::{Parser, Language};

let mut parser = Parser::new();
parser.set_language(tree_sitter_sshclientconfig::language()).expect("Error loading SSH client config grammar");
let config = "\
Host example.com
  User your-name
  Port 12345";
let tree = parser.parse(config, None).unwrap();
assert_eq!(tree.root_node().to_sexp(), "(client_config (host (host_value)) (user (user_value)) (port (port_value)))");
```

## References

- [ssh_config man page](https://man.openbsd.org/ssh_config)
