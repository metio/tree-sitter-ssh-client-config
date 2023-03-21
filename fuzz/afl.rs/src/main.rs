#[macro_use]
extern crate afl;

use tree_sitter::{Parser, Language};

extern "C" {
    fn tree_sitter_ssh_client_config() -> Language;
}

fn main() {
    let language = unsafe { tree_sitter_ssh_client_config() };
    let mut parser = Parser::new();
    parser.set_language(language).unwrap();

    fuzz!(|data: &[u8]| {
        if let Ok(client_config) = std::str::from_utf8(data) {
            let _ = parser.parse(client_config, None).unwrap();
        }
    });
}
