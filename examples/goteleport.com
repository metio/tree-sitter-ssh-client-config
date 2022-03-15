# source: https://goteleport.com/blog/ssh-client-config-file-example/
# archive: https://web.archive.org/web/20220313083250/https://goteleport.com/blog/ssh-client-config-file-example/

Host newServer
  HostName newServer.url
  User adminuser
  Port 2222
  IdentityFile ~/.ssh/id_rsa.key

Host anotherServer.tld
  HostName anotherServer.url
  User mary
  Port 2222
