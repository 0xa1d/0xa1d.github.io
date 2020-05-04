# Intro

**Work in progress**\
Hello, I'm a French cybersecurity professional studying for OSCP for the past few months. I am mostly training on HackTheBox and taking notes on CherryTree but wanted to make all of this prettier.\
You'll find plenty of cheatsheets regarding OSCP on the web, this one is far from exhaustive nor finished, but it's mine and I'm planning to update it as long as I'm not done with the certification ! Bonus if it helps someone :)\
If something's wrong or you have suggestions, feel free to reach me.\

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

Basic scan :

`nmap -sT -sV -sC $HOST -oN nmapinit`\
-sT : TCP connect scan (as opposed to -sS which is SYN scan)\
-sV : Version detection\
-sC : Run default scripts (equivalent to --script=default)\
-oN : Normal output\



## Vulnerabilities

## Bruteforce

## Payloads

## Privesc


```markdown
Syntax highlighted code block

# Header 1
## Header 2
### Header 3

- Bulleted
- List

1. Numbered
2. List

**Bold** and _Italic_ and `Code` text

[Link](url) and ![Image](src)
```

For more details see [GitHub Flavored Markdown](https://guides.github.com/features/mastering-markdown/).

### Jekyll Themes

Your Pages site will use the layout and styles from the Jekyll theme you have selected in your [repository settings](https://github.com/0xa1d/0xa1d.github.io/settings). The name of this theme is saved in the Jekyll `_config.yml` configuration file.

### Support or Contact

Having trouble with Pages? Check out our [documentation](https://help.github.com/categories/github-pages-basics/) or [contact support](https://github.com/contact) and we’ll help you sort it out.
