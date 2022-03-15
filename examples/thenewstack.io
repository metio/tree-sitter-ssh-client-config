# source: https://thenewstack.io/ssh-made-easy-with-ssh-agent-and-ssh-config/
# archive: https://web.archive.org/web/20220313083823/https://thenewstack.io/ssh-made-easy-with-ssh-agent-and-ssh-config/

Host AWS
   HostName ADDRESS
   User olivia
   IdentityFile ~/.ssh/id_rsa_olivia.pub

Host GoogleCloud
   HostName ADDRESS
   User bethany
   IdentityFile ~/.ssh/id_rsa_bethany.pub

Host AZURE
   HostName ADDRESS
   User trinity
   IdentityFile ~/.ssh/id_rsa_trinity.pub

Host WEB
   HostName ADDRESS
   User janet
   IdentityFile ~/.ssh/id_rsa_janet.pub

Host DB
   HostName ADDRESS
   User chenica
   IdentityFile ~/.ssh/id_rsa_chenica.pub
