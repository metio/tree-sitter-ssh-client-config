# source: https://nerderati.com/2011/03/17/simplify-your-life-with-an-ssh-config-file/
# archive: not available

Host dev
    HostName dev.example.com
    Port 22000
    User fooey

Host github-project1
    User git
    HostName github.com
    IdentityFile ~/.ssh/github.project1.key
Host github-org
    User git
    HostName github.com
    IdentityFile ~/.ssh/github.org.key
Host github.com
    User git
    IdentityFile ~/.ssh/github.key

Host tunnel
    HostName database.example.com
    IdentityFile ~/.ssh/coolio.example.key
    LocalForward 9906 127.0.0.1:3306
    User coolio
