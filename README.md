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

```
To the extent possible under law, the author(s) have dedicated all copyright
and related and neighboring rights to this software to the public domain
worldwide. This software is distributed without any warranty.

You should have received a copy of the CC0 Public Domain Dedication along with
this software. If not, see https://creativecommons.org/publicdomain/zero/1.0/.
```
