<!--
SPDX-FileCopyrightText: The tree-sitter-ssh-client-config Authors
SPDX-License-Identifier: CC0-1.0
-->

# tree-sitter-ssh-client-config

SSH client config grammar for [tree-sitter](https://github.com/tree-sitter/tree-sitter).

## Usage

### NodeJS

This grammar is available at [npmjs.com](https://npmjs.com/package/tree-sitter-ssh-client-config), and you can use it together with the [NodeJS language binding](https://github.com/tree-sitter/node-tree-sitter).

```javascript
const Parser = require("tree-sitter");
const SSH_CLIENT_CONFIG = require("tree-sitter-ssh-client-config");

const parser = new Parser();
parser.setLanguage(SSH_CLIENT_CONFIG);

const config = `
Host example.com
  User your-name
  Port 12345
`;

const tree = parser.parse(config);
console.log(tree.rootNode.toString());
// (client_config
//   (host
//     (host_value))
//   (user
//     (user_value))
//   (port
//     (port_value)))
```

## References

- [ssh_config man page](https://man.openbsd.org/ssh_config)

## License

[CC0-1.0](LICENSES/CC0-1.0.txt).
