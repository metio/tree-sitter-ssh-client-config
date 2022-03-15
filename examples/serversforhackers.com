# source: https://serversforhackers.com/c/using-the-ssh-config-file
# archive: https://web.archive.org/web/20220313083712/https://serversforhackers.com/c/using-the-ssh-config-file

Host ssh-ex
    HostName 104.236.90.57
    User root
    Port 22
    IdentitiesOnly yes
    IdentityFile ~/.ssh/id_sshex
