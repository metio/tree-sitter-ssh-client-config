# source: https://linuxhint.com/ssh-config-file/
# archive: https://web.archive.org/web/20210701140949/https://linuxhint.com/ssh-config-file/

Host fahmida
     HostName Yasmin

Host fahmida.com.bd
     HostName 10.0.2.15
     ForwardX11 yes

Host *
     User Ubuntu
     HostName 10.0.2.15
     Port 22
     IdentityFile ~/.ssh/id_rsa
     Compression yes
     ServerAliveInterval 60
     ServerAliveCountMax 20
