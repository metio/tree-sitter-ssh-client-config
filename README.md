# tree-sitter-ssh-client-config

SSH client config grammar for [tree-sitter](https://github.com/tree-sitter/tree-sitter).

## Development

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
