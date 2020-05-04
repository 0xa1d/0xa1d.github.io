# Intro

**Work in progress**  
Hello, I'm a French junior cybersecurity professional studying for OSCP for the past few months. I am mostly training on HackTheBox and taking notes on CherryTree but wanted to make all of this prettier.  
You'll find plenty of cheatsheets regarding OSCP on the web, this one is far from exhaustive nor finished, but it's mine and I'm planning to update it as long as I'm not done with the certification ! Bonus if it helps someone :)  
If something's wrong or you have suggestions, feel free to reach me.  

# Index

## Cheatsheet
- [Enumeration](#enumeration)
- [Vulnerabilities](#vulnerabilities)
- [Bruteforce](#bruteforce)
- [Payloads](#payloads)
- [Privesc](#privesc)

## Write-ups
- [HTB - OpenAdmin](https://0xa1d.github.io/openadmin)

# Content

## Enumeration

### Ports & services

I always run the following 2 scans to begin with. Heard about UDP scans but I haven't needed it yet.  

- Basic scan :
```
nmap -sT -sV -sC $HOST -oN nmapinit
```
-sT : TCP connect scan (as opposed to -sS which is SYN scan)  
-sV : Version detection  
-sC : Run default scripts (equivalent to --script=default)  
-oN : Normal output  

- All ports (fast) :
```
nmap -p- --max-retries 0 --min-rate 5000 $HOST -oN nmapfull
```
-p- : All ports  
--max-retries : Cap number of retransmission (default is 10)  
--min-rate : Packets per second to send  

When fast scan detects more ports, I run the first scan again on the newly found ports (for example `-p 45678,45679`)  

### 53 - DNS

- Zone transfer :
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

- sqlmap
Check for SQL injections :  
```
sqlmap -u "http://$HOST/index.php?page=1"
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
Example : `kerbrute userenum --dc 10.10.10.10 -d domain.local /opt/SecLists/Usernames/xato-net-10-million-usernames-dup.txt`  

**Bruteforce user :**  
```
kerbrute bruteuser --dc $HOST -d $DOMAIN $WORDLIST $USER
```
Example : `kerbrute bruteuser --dc 10.10.10.10 -d domain.local /usr/share/wordlists/rockyou.txt alice`  

**Password spray :**  
```
kerbrute passwordspray --dc $HOST -d $DOMAIN $FILE_USERS $PASSWORD
```
Example : `kerbrute passwordspray --dc 10.10.10.10 -d domain.local domain_users.txt Password123!`  


## Vulnerabilities

## Bruteforce

## Payloads

## Privesc
