const Parser = require("tree-sitter");
const SSH_CLIENT_CONFIG = require("tree-sitter-ssh-client-config");
const fs = require("fs");
const path = require("path");

const data = fs.readFileSync(path.resolve(__dirname, "out/current.config"))
const parser = new Parser();
parser.setLanguage(SSH_CLIENT_CONFIG);

parser.parse(String.fromCodePoint(...data));
