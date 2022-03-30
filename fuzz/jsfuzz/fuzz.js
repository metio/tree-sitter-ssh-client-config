const Parser = require("tree-sitter");
const SSH_CLIENT_CONFIG = require("tree-sitter-ssh-client-config");

const parser = new Parser();
parser.setLanguage(SSH_CLIENT_CONFIG);

function fuzz(bytes) {
    parser.parse(String.fromCodePoint(...bytes));
}

module.exports = {
    fuzz
};
