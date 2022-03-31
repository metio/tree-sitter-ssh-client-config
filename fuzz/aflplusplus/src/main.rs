extern crate encoding_rs;
extern crate encoding_rs_io;

use tree_sitter::{Parser, Language};
use std::fs::File;
use std::error::Error;
use std::io::Read;
use std::env;

use encoding_rs::UTF_8;
use encoding_rs_io::DecodeReaderBytesBuilder;

extern "C" {
    fn tree_sitter_sshclientconfig() -> Language;
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let filename = &args[1];

    let language = unsafe { tree_sitter_sshclientconfig() };
    let mut parser = Parser::new();
    parser.set_language(language).unwrap();

    let file = File::open(filename).expect("Unable to open the file");
    let mut decoder = DecodeReaderBytesBuilder::new()
        .encoding(Some(UTF_8))
        .build(file);
    let mut client_config = String::new();
    decoder.read_to_string(&mut client_config)?;

    let tree = parser.parse(client_config, None).unwrap();
    assert_eq!(tree.root_node().kind(), "client_config");
    Ok(())
}
