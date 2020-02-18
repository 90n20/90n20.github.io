---
layout: post
title: "NeverlanCTF 2020 Write-ups"
categories: [ctf, writeup]
tags: [ctf, writeup, neverlanctf]
---

# Trivia

## Milk Please!

*Trivia Question: a reliable mechanism for websites to remember stateful information. Yummy!*

*flag*: `cookie`
<hr>

## Professional guessing

*The process of attempting to gain Unauthorized access to restricted systems using common passwords or algorithms that guess passwords*

*flag*: `password cracking`
<hr>

## Base 2^6

*A group of binary_to_text encoding schemes that represent binary data in an ASCII string format by translating it into a radix-64 representation*

*flag*: `base64`
<hr>

## AAAAAAAAAAAAAA! I hate CVEs

*This CVE reminds me of some old school exploits. If flag is enabled in sudoers*

Here, some basic recon was needed. Googling for sudo vulnerabilities there is the [CVE-2019-18634](https://nvd.nist.gov/vuln/detail/CVE-2019-18634) which explains
a BOF attack in sudo process if pwfeedback is enabled in /etc/sudores.

![CVE-2019-18634](/assets/images/posts/2020-02-12-neverlan-ctf/cve_2019_18634.png)

*flag*: `pwfeedback`
<hr>

## Rick Rolled by the NSA??

*This CVE Proof of concept Shows NSA.gov playing "Never Gonna Give You Up," by 1980s heart-throb Rick Astley.*

*Use the CVE ID for the flag. flag{CVE-?????????}*

Another recon related challenge. Googling for "CVE", "NSA" and "Rick Astley" lead us to many artciles describing [CVE-2020-0601](https://nvd.nist.gov/vuln/detail/CVE-2020-0601)


![CVE-2020-0601](/assets/images/posts/2020-02-12-neverlan-ctf/cve_2020_0601.jpg)

*flag*: `CVE-2020-0601`
<hr><hr>

# Recon

## Front Page of the Internet

*Whoops... I leaked a flag on a public website*

Every internet freak knows that `reddit` is also known as the front page of the internet. Searching on posts related to this challenge author, `ZestyFE`, lead to the desired flag.

![reddit](/assets/images/posts/2020-02-12-neverlan-ctf/reddit.png)

*flag*: `flag{l3arningFr0mStr4ng3rs}`
<hr>

## The Big Stage

*One time we keynoted @SaintCon... I think I remember hiding a flag in our pres*

It seems to be something related to a tweet post. Searching over neverlancf twitter posts there is one mentioning SaintCon with an embedded keynote presentation hosted on google docs.

![saintcon](/assets/images/posts/2020-02-12-neverlan-ctf/saintcon.png)

Opening the document and looking throw slides lead to the flag.

![ppt](/assets/images/posts/2020-02-12-neverlan-ctf/ppt.png)

*flag*: `flag{N3v3r_g0na_g1v3_y0u_up}`
<hr>

## The Link

*NeverLAN's secret Track 2*

After some googling and breaking my brain I realized that neverlanctf website has a [music](https://live.neverlanctf.com/) section with 2 tracks.

Track 2 is a [youtube](https://www.youtube.com/watch?v=dhebl9oD5Lc) video (pretty cool one tho), so opening it and looking over the comments lead to the flag.

![youtube](/assets/images/posts/2020-02-12-neverlan-ctf/youtube.png)

*flag*: `flag{10684524746ba936b43a82d84385dcf5}`
<hr>

## Thats just Phreaky

*The first of many stories that have been told. 01 September 2017 | 14:01*

Thanks to my team mate [sarvmetal](https://twitter.com/sarvmetal), I was able to find an [article](https://darknetdiaries.com/episode/1/) on darknetdiaries that was posted at the same date and time as the one in the hint.

Flag was hidding in site source code.

![phreak](/assets/images/posts/2020-02-12-neverlan-ctf/phreak.png)

*flag*: `flag{n3v3rl4nctf_s4ys_t3ll_us_4n0th3r_1_jack}`
<hr><hr>

# PCAP

## Unsecured Login

*We caught someone logging into their website, but they didn't use https!*

As a pcap could have lots of entries, I just performed a conversation analysis in order to list all the trafic between two endpoints. 2 TCP sessions over port 80 (`http`) are shown, so having a quick look over them revealed the flag in a form POST data.

![unsecured_tcp](/assets/images/posts/2020-02-12-neverlan-ctf/unsecured_tcp.png)

![unsecured_post_data](/assets/images/posts/2020-02-12-neverlan-ctf/unsecured_post_data.png)

*flag*: `flag{n0httpsn0l0gin}`
<hr>

## Unsecured Login 2

*We caught someone logging into their website, but they didn't check their links when submitting data!*

Folling the same aproach, looking to the conversations over port 80 and looking over them, lead to the flag in the sumbitted data of a GET request

![unsecured_get](/assets/images/posts/2020-02-12-neverlan-ctf/unsecured_get.png)

*flag*: `flag{ensure_https_is_always_used}`
<hr>

## FTP

*It looks like someone forgot to use a secure version of ftp...*

This time I focused my analysis at the conversations over the port 21 (`ftp`). At some point, a client log in into a ProFTPD Server, hosted in what seems to be a raspberry pi and list the files at the current directory.

![unsecured_get](/assets/images/posts/2020-02-12-neverlan-ctf/ftp_login.png)

At */home/pi* folder there is a `flag.txt` file.

![unsecured_get](/assets/images/posts/2020-02-12-neverlan-ctf/ftp_list.png)

Then client log in again and perform a RETR command, this is, downloads the listed file.

![unsecured_get](/assets/images/posts/2020-02-12-neverlan-ctf/ftp_download.png)

As this is not a secure ftp, it's possible to look at the FTP Data transmited (file contents), revealing the flag.

![unsecured_get](/assets/images/posts/2020-02-12-neverlan-ctf/ftp_download_contents.png)

*flag*: `flag{sftp_OR_ftps_not_ftp}`
<hr>

## Teletype Network

*It looks like someone hasn't upgraded to ssh yet...*

This was just as simple as having a look at telnet tcp streams over the pcap, due to the fact thas telnet is not encrypted. After getting access to the sistem, there is a cat command against a flag.txt file.

![telnet](/assets/images/posts/2020-02-12-neverlan-ctf/telnet.png)

*flag*: `flag{telnet_1s_n0t_secur3}`
<hr>

## hidden-ctf-on-my-network

*So, I have a little CTF challenge I've been running on my home network for about a year now. No one has noticed it and I doubt anyone ever will.... Until today!

I grabbed a hak5 plunderbug and recorded the traffic of a cheap HP machine booting up for the first time on my network. Can you solve the CTF challenge I leave for my guests?*

This time, a conversation analysis reveals that there is a lot of `udp` traffic going on. Having a closer look to the `dhcp` one, a flag could be seen hidding on its datagrams

![telnet](/assets/images/posts/2020-02-12-neverlan-ctf/hidden_udp.png)
![telnet](/assets/images/posts/2020-02-12-neverlan-ctf/hidden_dhcp.png)


*flag*: `flag{who-actually-looks-at-dhcp-server-traffic-anyway}`
<hr><hr>

# Web

## Cookie Monster

*This website is hiding the flag. You'll need to use your browser's tools to solve the challenge.*

*https://challenges.neverlanctf.com:1110*

Accesing to the web just shows a simple web page with the text `He's my favorite Red guy`. Also, as the title suggests, the site sets a cookie called `Red_Guy's_name`.

![cookie_web](/assets/images/posts/2020-02-12-neverlan-ctf/cookie_web.png)

After some brainfuck, I realized that `Cookie monster` is a character from the `sessame street (Barrio sésamo)` TV series and that another of the characters `Elmo` is read.

![cookie_sessame](/assets/images/posts/2020-02-12-neverlan-ctf/cookie_sessame.png)
![cookie_cookie](/assets/images/posts/2020-02-12-neverlan-ctf/cookie_cookie.png)

Modifying the cookie value to fit this name and reloading the page lead to the flag.

![cookie_flag](/assets/images/posts/2020-02-12-neverlan-ctf/cookie_flag.png)

*flag*: `flag{YummyC00k13s}`
<hr>

## Stop the Bot

*https://challenges.neverlanctf.com:1140*

Browsing to the utl show a simple site with just random data in it. As the challenge title suggest something related to bots, the first thing that came to my mind was to check if there is any `robots.txt` file. As expected it is present and is preventing "bots" to read a `flag.txt` file over the site root.

![bot_robots](/assets/images/posts/2020-02-12-neverlan-ctf/bot_robots.png)

Accesing this file leads to the flag.

![bot_flag](/assets/images/posts/2020-02-12-neverlan-ctf/bot_flag.png)

*flag*: `flag{n0_b0ts_all0w3d}`
<hr>

## SQL Breaker

*https://challenges.neverlanctf.com:1160*

This is the classic SQLi example, where the payload can be directly into the login form fields. In this cases the query is in the form `SELECT user, password FROM users WHERE user = "$user" and password = "$password"`.

![sql_1_login](/assets/images/posts/2020-02-12-neverlan-ctf/sql_1_login.png)

Injecting `' OR True -- '` into the username will result in the query `SELECT user, password FROM users WHERE user = "" OR TRUE` which return all rows on the table, granting a suscessful login and revealing the flag.

![sql_1_flag](/assets/images/posts/2020-02-12-neverlan-ctf/sql_1_flag.png)

*flag*: `flag{Sql1nj3ct10n}`
<hr>

## SQL Breaker 2

*https://challenges.neverlanctf.com:1165*

This is the same kind of injection as before, but a bit "upgraded". The previous solution just let us to access the site as user John, but to get the flag
an admin access is needed.

![sql_2_john](/assets/images/posts/2020-02-12-neverlan-ctf/sql_2_john.png)

Usually programmers use an extra column on the users table to set if an user has the admin role or not. Knowing that, let's assume that there is an admin field with a boolean value, being 1 the value for admin and 0 for a normal user.

Knowing this and injecting `' OR admin=1  -- '` in the username field, result in the query `SELECT user, password FROM users WHERE user = "" OR admin=1`, granting acccess to the site as an admin user.

![sql_2_flag](/assets/images/posts/2020-02-12-neverlan-ctf/sql_2_flag.png)


*flag*: `flag{esc4p3y0ur1nputs}`
<hr>

## Follow Me!

*Let's start here. https://7aimehagbl.neverlanctf.com*

Browsing to the site lead to a bunch of 302 redirections that seems to have no end, in an infinite loop.

![follow_redirects](/assets/images/posts/2020-02-12-neverlan-ctf/follow_redirects.png)

To solve this I just use a simple python code that prints each response content, as it states the next redirect. At some point, this content will lead to
the flag.

```python
mport requests as req

base_url = "http://127.0.0.1"

while True:
    try:
        res = req.get(base_url, allow_redirects=False)
        content = res.text
        base_url = "https://" + content.split()[-1]
        print("[*]Content => {}".format(content))
    except:
        break
```

![follow_flag](/assets/images/posts/2020-02-12-neverlan-ctf/follow_flag.png)

*flag*: `flag{d0nt_t3ll_m3_wh3r3_t0_g0}`
<hr>

## Browser Bias

*https://challenges.neverlanctf.com:1130*

When opening the page on a normal broswser, it shows the message `Sorry, this site is only optimized for browsers that run on commodo 64`. This suggest to make changes on browser's User-Agent.

Performing a google search, I found the following UA list => [https://www2.sal.tohoku.ac.jp/~gothit/ua.html](https://www2.sal.tohoku.ac.jp/~gothit/ua.html). At line 675 the commodore64 UA is listed as `"Contiki/1.0 (Commodore 64; http://dunkels.com/adam/contiki/)"`.

Modifying the User-Angent and resending the page headers leads to the flag.

![browser_flag](/assets/images/posts/2020-02-12-neverlan-ctf/browser_flag.png)

*flag*: `flag{8b1t_w3b}`
<hr><hr>

# Forensics

## Listen to this

*You hear that?*

*Your flag will be in the normal flag{flagGoesHere] syntax*

*-ps This guy might be important*

When listening to this sound with my headphones I realized some `beeps`in the background, many of them covered by the speacher voice. All clues point to some kind of hidden morse code. In fact, looking at the sound `spectogram` in `audacity/sonic visualizer` reveals the dots and slashes.

![audacity](/assets/images/posts/2020-02-12-neverlan-ctf/audacity.png)

In order to get a clear visualization of the code I just aplied a voice removal filter to the audio, with a strength of 5.

![audacity_filter](/assets/images/posts/2020-02-12-neverlan-ctf/audacity_filter.png)

Finally, using an online conveter tool the flag was recovered.

![morse_code](/assets/images/posts/2020-02-12-neverlan-ctf/morse_code.png)

*flag*: `flag{FLAGDITSANDDAHSFORLIFE}`
<hr>

## Open Backpack

*There's more to this picture*

A `jpg` image is provided as evidence and the text suggests that there is something hidden in it. In this kind of challenges I usually start checking if there is embeded data using tools like `binwalk` and in fact, with this method, a `flag.png` file is extracted.

![morse_code](/assets/images/posts/2020-02-12-neverlan-ctf/openbackpack_extract.png)

Opening it reveals the flag.

![morse_code](/assets/images/posts/2020-02-12-neverlan-ctf/openbackpack_flag.png)

*flag*: `flag{AlWaYs_cH3ck_y0ur_sTuFF}`
<hr>

## Look into the past

*We've captured a snapshot of a computer, but it seems the user was able to encrypt a file before we got to it. Can you figure out what they encrypted?*

Due to its structure, the evidence seems to come from a linux based system.

![past_home](/assets/images/posts/2020-02-12-neverlan-ctf/past_home.png)

One good practice in this cases (if it is present) is to check the `.bash_history` file of each user, as it records the commands performed by the user over a session.

![past_history](/assets/images/posts/2020-02-12-neverlan-ctf/past_history.png)

It seems that the user encrypted the `flag.txt` file with `aes-256-cbc` using a key made with the combination of 3 passwords. Those passwords are then hidden: one using steghide with an image, another creating an user with this key as password and the last one inserted into a sqlite3 database.

The first one can be easily obtained with steghide extract command, as no password was provided to hide it.

![past_stego](/assets/images/posts/2020-02-12-neverlan-ctf/past_stego.png)

To get the second one is enough to show `etc/shadows` content filtering results by "user".

![past_shadow](/assets/images/posts/2020-02-12-neverlan-ctf/past_shadow.png)

The third one can be obtained uncompressing the `table.db.tar` and opening it with `sqlite3`. Performing a select query over the table passwords shows the key.

![past_sqlite](/assets/images/posts/2020-02-12-neverlan-ctf/past_sqlite.png)

The last step involves decrypting `flag.txt.enc` file using the recovered keys.

![past_decypher](/assets/images/posts/2020-02-12-neverlan-ctf/past_decypher.png)

*flag*: `flag{h1st0ry_1n_th3_m4k1ng}`
<hr><hr>

# Crypto

## Pigsfly

*There's more to this picture*

![pigsfly_image](/assets/images/posts/2020-02-12-neverlan-ctf/pigsfly_image.png)

Using an image search service with the provided image, reveals that is a message encoded using a `pigpen` cipher.

![pigsfly_pigpen](/assets/images/posts/2020-02-12-neverlan-ctf/pigsfly_pigpen.png)

Performing a basic substitution returns the flag.

*flag*: `flag{d0wn_and_d1r7y}`
<hr>

## BaseNot64

*ORUGS43PNZSXG33ONR4TGMRBEEYSC===*

The string seems to be a base64 encoding, however, as the challenge title suggests, it is using another one.

Using `CyberChef magic module` easily identifies this as a base32 encoding, revealing the encoded flag.  

![basenot64](/assets/images/posts/2020-02-12-neverlan-ctf/basenot64.png)

*flag*: `flag{thisonesonly!!1!}`
<hr>

## Dont Take All Knight

![knight_image](/assets/images/posts/2020-02-12-neverlan-ctf/knight_image.png)

Like in Pigsfly, an image search was performed, resulting that the message encoded in the image is related to the `Templar Cipher`as the title `Knight` suggests.

![knight_cipher](/assets/images/posts/2020-02-12-neverlan-ctf/knight_cipher.png)

Again, performing a substitution was enough to get the flag => `FLAGISEVENKNIGHTSNEEDCRYPTO`

*flag*: `flag{EVENKNIGHTSNEEDCRYPTO}`
<hr>

## The Invisibles

![invisibles_image](/assets/images/posts/2020-02-12-neverlan-ctf/invisibles_image.png)

Another image based crypto challenge. This was a bit harder to find as there are not too much info about it. Finally it seems that te code is related to the videogame `Arthur and the Minimoys".

![invisibles_image](/assets/images/posts/2020-02-12-neverlan-ctf/invisibles_cipher.jpg)

Using the provided decoding table the flag was easy to get => `FLAGISYOUCANSEETHEM`

*flag*: `flag{YOUCANSEETHEM}`
<hr>

## Stupid Cupid

The following text is provided:

```
6,12,5,20,15,1,5,3,4,10,13,16,7,12,14,8 - 
 ______________________________________________________________
| 1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20 21|
| ______________________________________________________________|
  J  O  W  W  A  V  Q  L  L  W  E  I  U  S  B  A  E  S  I  P  L
                                                              
  O  W  W  A  Q  A  P  K  E  Q  I  E  O  Q  D  Z  R  D  O  U  E
                                                              
  E  D  E  F  R  W  I  J  M  I  K  M  L  W  E  C  Y  E  I  R  O
                                                              
  D  Z  S  D  M  P  W  H  L  A  L  K  M  E  L  K  U  W  Q  Y  W
                                                              
  L  D  D  L  V  I  D  W  O  S  G  I  N  Z  S  K  K  I  Z  G  D
                                                              
  I  M  H  M  D  W  A  Q  Y  L  I  S  B  V  E  P  M  P  B  Q  Z
                                                              
  E  B  G  I  M  Q  S  A  T  M  S  W  J  C  W  L  V  Q  H  M  S
                                                              
  G  N  P  O  O  D  F  Z  D  B  A  T  K  N  R  U  D  K  I  P  L
                                                              
  S  P  I  L  R  F  Q  B  H  H  B  U  O  Q  T  U  I  L  F  U  K
                                                              
  W  I  O  Q  P  L  I  V  A  E  I  I  U  A  H  Y  P  Y  L  T  Y
                                                              
  F  Y  K  W  D  K  K  C  Q  O  O  Z  C  W  K  T  S  T  O  R  D
                                                              
  C  Q  M  A  J  L  F  O  W  Y  R  B  W  D  M  I  O  E  I  D  T
                                                              
  V  L  E  Z  Q  H  P  I  I  W  S  O  Q  F  N  N  M  D  K  Q  P
                                                              
  H  A  W  M  S  Q  L  Y  O  I  M  H  A  K  F  W  I  F  U  J  I
                                                              
  Y  Q  T  L  A  W  O  H  P  R  Q  W  S  E  Q  S  T  N  W  N  O
                                                              
  R  U  Y  O  X  S  E  R  L  I  W  X  D  P  A  A  P  O  E  D  U

  ```

  After a fast look, it seems to be the typical scheme of a polymorphic encryption, being the numbers the index of each column. Taking this into account I created a python script to make the decryption even easier, just by storing each row/column in a 2D array.

```python
file = "stupid_cupid.txt"

cypher_indexes = []
cypher_matrix = []
cypher_matrix_transposed = []
clear_msg = ""

f = open(file, "r")

#build index and matrix arrays
for i,line in enumerate(f):
    if i == 0:
        line = line.replace("- \n","")
        tmp = line.split(",")
        cypher_indexes = tmp
    elif i>= 4:
        tmp = line.split()
        if len(tmp) > 0:
            cypher_matrix.append(tmp)

#perform the deciphering
transposed_cypher_matrix = [[cypher_matrix[x][y] for x in range(len(cypher_matrix))] for y in range(len(cypher_matrix[0]))]

print("[*]Indexes")
print(cypher_indexes)

print("[*]Original matrix")
for r in cypher_matrix:
    print(r)

print("[*]Transposed matrix")
for r in transposed_cypher_matrix:
    print(r)

c = 0
for index in cypher_indexes:
    clear_msg += transposed_cypher_matrix[int(index)-1][c]
    c += 1

print("[*]Hidden message")
print(clear_msg)
```
![cupid_output](/assets/images/posts/2020-02-12-neverlan-ctf/cupid_output.png)

*flag*: `flag{VERYSIMPLECIPHER}`
<hr>

## My own encoding

*Here's an encoding challenge. This doesnt really test your technical skills, but focuses on your critical thinking.*

I have to admit that this callenge took me more time than the expected. Sometimes the most simple answer is the best one.

![own_image](/assets/images/posts/2020-02-12-neverlan-ctf/own_image.png)

An image is provided, in which there are 16 5x5 squares with one of its cells filled in black. One of them is just in blank. 
So for every square we have 26 possibilities and the standart alphabet has the same amount of characters.

Trying the `polybius cipher` at [dcode](https://www.dcode.fr/polybius-cipher) gives the text `MHBDINAXNTG??BIDQ`, suposing that the no filled square is represents `Z`, which results in `MHBDINAXNTGZBIDQ`.

![own_dcode](/assets/images/posts/2020-02-12-neverlan-ctf/own_dcode.png)

This not seems to be a correct flag, so I just shifted it, in order to test other positions for the blank square.

![own_flag](/assets/images/posts/2020-02-12-neverlan-ctf/own_flag.png)

From the results, it can be infered that the flag is `NICEJOBYOUHACKER`

*flag*: `flag{NICEJOBYOUHACKER}`
<hr>

## Baby RSA

*We've intercepted this RSA encrypted message 2193 1745 2164 970 1466 2495 1438 1412 1745 1745 2302 1163 2181 1613 1438 884 2495 2302 2164 2181 884 2302 1703 1924 2302 1801 1412 2495 53 1337 2217 we know it was encrypted with the following public key e: 569 n: 2533*

RSA is a way harder to decrypt, due the factorization of `n` into `p` and `q`, especially when using big prime numbers. The weakness of this algorithm resides in using low values for p and q, thus making factorization possible. With this, getting `d`, the private key for deciphering, is pretty straight forward.

In order to solve the challenge, I developed a python script that grabs the factors from the site [http://factordb.com/](http://factordb.com/) and decrypts each block of the intercepted message.

```python
import gmpy
import requests as req
import json
import sys

factordb = "http://factordb.com/api"

pub_key = {'e': 569, 'n': 2533}
factors = []

#get the factors of n, this is p and q, from factordb
res = req.get(factordb, params={"query": pub_key['n']}, verify=False)
raw_factors = res.json().get('factors')

if not raw_factors:
    print("[*]No factors knwon")
    sys.exit(0)

for x, y in raw_factors:
    factors.append(int(x) * y)

print("[*]e => %i, n => %i" % (pub_key['e'], pub_key['n']))
print("[*]p => %i, q => %i" % (factors[0], factors[1]))

#compute phin from both prime factors
phin = (factors[0]-1) * (factors[1]-1)
print("[*]phin => %i" % phin)

#compute d using gmpy library, e and the computed phin
d = gmpy.invert(pub_key['e'], phin)
print("[*]d => %i" % d)

#time to decrypt the message
f = open("baby_rsa.txt", "r")
msg = f.read()
msg = msg.split()

dec_msg = ""
for y in msg:
    dec_msg += chr(pow(int(y), d, pub_key['n']))

print(dec_msg)
```

The decrypted message is the desired flag.

![baby_rsa](/assets/images/posts/2020-02-12-neverlan-ctf/baby_rsa.png)

*flag*: `flag{sm4ll_pr1m3s_ar3_t0_e4sy}`
<hr>

## Crypto Hole

*Here's a lot of crypto challenges all packed into one. To start, unzip the starting zip file and enter NeverLANCTF as the password.*

*Each correct decryption, besides two, will be prefixed with password:*

`Not solved. Run out of time.`

*flag*:
<hr>

## It is like an onion of secrets

*This one has layers like an onion. Just don't let it make you cry..*

`Not solved. Run out of time.`

*flag*:
<hr><hr>

# Reverse Engineering

## Adobe Payroll

*We've forgotten the password to our payroll machine. Can you extract it?*

The evidence is a dotNet executable. For reversing it I used `dnSpy", a tool that debugs and edit .NET files without having the source code avaliable.

As the hint points towards a password, the first thing was search for some password check function. In fact there is a `checkPassword()` which is called from the fuction `btnLogin_Click`, triggered by clicking in the login button. 

![adobe_check](/assets/images/posts/2020-02-12-neverlan-ctf/adobe_check.png)

Here if the checkPassword suceed, a string is created by appending chars to it. The trick is that this chars are converted from its `ASCII` decimal code. 

![adobe_login](/assets/images/posts/2020-02-12-neverlan-ctf/adobe_login.png)

![adobe_ascii](/assets/images/posts/2020-02-12-neverlan-ctf/adobe_ascii.png)

I just made a simple python script to show the resulting string, which resulted in the desired flag.

```python
chars = [102, 108, 97, 103, 123, 46, 110, 101, 116, 95, 105, 115, 95, 112, 114, 102, 116, 121, 95, 101, 97, 115, 121, 95, 116, 111, 95, 100, 101, 99, 111, 109, 112, 105, 108, 101, 125]

result = ""

for c in chars:
	result += chr(c)

print(result)
```

*flag*: `flag{.net_is_prfty_easy_to_decompile}`
<hr>

## Script Kiddie

*It looks like a script kiddie was trying to build a crypto locker. See if you can get the database back?*

Opening the `encrypted_db` provided as evidence, it seems to be hexadecimal, as there are only numbers from 0 to 9 and letters from a to f. Converting this to text with `CyberChef` lead to a base64 encoded text. 

![script_hex](/assets/images/posts/2020-02-12-neverlan-ctf/script_hex.png)

Decoding it results in a json formated database. Performing a search over it lead to the flag.

![script_db](/assets/images/posts/2020-02-12-neverlan-ctf/script_db.png)

*flag*: `flag{ENC0D1NG_D4TA_1S_N0T_ENCRY7I0N}`
<hr>

## Reverse Engineer

*This program seems to get stuck while running... Can you get it to continue past the broken function?*

If we execute the provided file, a segmentation error happens. So I openned it with `radare2` reverse engineering framework with the -A parameter. This performs the `aaa` command, which analyze the assembly code to extract information.

Next step was list the program functions and have a look at the main function.

![reverse_afl](/assets/images/posts/2020-02-12-neverlan-ctf/reverse_afl.png)
![reverse_main](/assets/images/posts/2020-02-12-neverlan-ctf/reverse_main.png)

From this we can infer that the main function just calls the function `foo (sym.foo)`.

![reverse_foo](/assets/images/posts/2020-02-12-neverlan-ctf/reverse_foo.png)

This foo function is trying to put a `c (0x63)` char into an array, until a counter that begins with 0 is equal to char `f (0x66)`. The problem here is that the array has no size, leading to a program crash when it attemps to add a value into it.

Getting a closer look at program functions, there is a call to `print (sym.print)` that never got executed due to a comparation that never is false. This function build an array, adding one char at a time and prints it to stdout. The printed array is the flag.

![reverse_print](/assets/images/posts/2020-02-12-neverlan-ctf/reverse_print.png)

*flag*: `flag{w3c0n7r0lth3b1nari3s}`
<hr><hr>

# Programming

## Das Prime

*My assignments due and I still don't have the answer! Can you help me fix my Python script... and also give me the answer? I need to make a prime number generator and find the 10,497th prime number. I've already written a python script that kinda works... can you either fix it or write your own and tell me the prime number?*

```python
import math
def main():
    primes = []
    count = 2
    index = 0
    while True:
        isprime = False
        for x in range(2, int(math.sqrt(count) + 1)):
            if count % x == 0: 
                isprime = True
                continue
        if isprime:
            primes.append(count)
            print(index, primes[index])
            index += 1
        count += 1
if __name__ == "__main__":
    main()
```

After a first run, it is clear that the script is showing non-prime numbers in an infinite loop and the goal is just the opposite, get a `prime number`.

With some tweeks the code gives the desired prime.

```python
  GNU nano 4.7                                                                       primes.py                                                                        Modified  
import math
def main():
    primes = []
    count = 2
    index = 0
    while True:
        iseven = False
        for x in range(2, int(math.sqrt(count) + 1)):
            if count % x == 0: 
                iseven = True 
                continue
        if not iseven:  
            primes.append(count)
            if index == (10497 - 1):
                print("[*]Prime number at 10497 is: %i" % primes[index])
                break
            index += 1
        count += 1
if __name__ == "__main__":
    main()
```

![primes](/assets/images/posts/2020-02-12-neverlan-ctf/primes.png)

*flag*: `flag{110573}`
<hr>

## password_crack

*Another day, another CTF challenge.*

*This one should be super straight forward. Before you go on, go read this article: https://thehackernews.com/2019/10/unix-bsd-password-cracked.html*

*Ok, did you read that article? Good. So your challenge is to crack a password. Just like Ken Thompson, our password will be in a 'known format'. The format we'll use is: color-random_year-neverlan_team_member's_name. (all lowercase) A sample password could be: red-1991*

*Here's your hash: 267530778aa6585019c98985eeda255f. The hashformat is md5.*

This callenge involves making a custom `wordlist` as we have the hints to the password format and its contents. Around Discord many people suggested to use hashcat included toolkit for this, but I tryed to develop a python script to help me solve it.

Firstly, a list of all neverlanctf team members was needed. This was easy, as in the website there is a [creators](https://ctf.neverlanctf.com/creators) page that gives us that info => `"purvesta", "n30", "zestyfe", "viking", "s7a73farm", "bashninja"`.

Next, I just played with a list of the [most common colour names](https://simple.wikipedia.org/wiki/Colour) => `"red", "orange", "yellow", "green", "blue", "purple", "brown", "magenta", "tan", "cyan", "olive", "maroon", "navy", "aquamarine", "turquoise", "silver", "lime", "teal", "indigo", "violet", "pink", "black", "white", "gray", "grey"`.

Finally, for years, I just started from 1900 untill now.

```python
from hashlib import md5
import sys


hash = "267530778aa6585019c98985eeda255f"

team_members = {"purvesta", "n30", "zestyfe", "viking", "s7a73farm", "bashninja"}
colors = {"red", "orange", "yellow", "green", "blue", "purple", "brown", "magenta", "tan", "cyan", "olive", "maroon", "navy", "aquamarine", "turquoise", "silver", "lime", "tea>

for color in colors:
    for year in range(1900, 2020):
        for team_member in team_members:
            candidate = "{}-{}-{}".format(color, year, team_member)
            print("[*]Testing => %s" % candidate)

            candidate_md5 = md5(bytes(candidate, "utf-8"))
            candidate_md5 = candidate_md5.hexdigest()

            if candidate_md5 == hash:
                print("[*]Cracked! => %s" % candidate)
                sys.exit(0)
```

![crack](/assets/images/posts/2020-02-12-neverlan-ctf/crack.png)

*flag*: `flag{orange-1984-zestyfe}`
<hr>


## Evil

*You have been tasked with stealing sensitive data from an evil crime lord. do you have what it takes?*

*ssh neverlan@medusa.neverlanctf.com -p 3333*

*password:eyesofstone*

After performing a ssh into the provided host and port, some instructions on how to go further are shown.

![evil](/assets/images/posts/2020-02-12-neverlan-ctf/evil.png)

A simple listing on the current directory shows the intel file. It contains some data about the `evil lord` and gives the hint that he has a server with a easy to bruteforce password.

![evil_info](/assets/images/posts/2020-02-12-neverlan-ctf/evil_info.png)

With this info I created a wordlist of all possible pins, this is, 10.000 entries, with the help of `crunch` tool present on the machine. It gets as input min password length (4), max password lenght (4) and the numbers used to create the wordlist as well as the output file.

```
crunch 4 4 0123456789 -o pin.lst
```

Once done, I launched `medusa`, a brute-force tool, against the `victim` host over ssh, using evil as username and the wordlist as password input. In a matter of seconds a success was shown, using the password `0024`.

![evil_medusa](/assets/images/posts/2020-02-12-neverlan-ctf/evil_medusa.png)

With this info in hand, we connected to the victim machine, using the gathered credentials. A pretty cool ascii art is shown and performing a listing on current directory 2 files were found: a `zipped` file and a `hint`.

![evil_victim](/assets/images/posts/2020-02-12-neverlan-ctf/evil_victim.png)

At this point we need to take a closer look to the hint `My name is everything`. After some unsuccesful attemps with the intel gathered about evil, I performed a base6 decode over the zip file name, which gives the word `stonecold`. Surprisingly, this was the password to the zip file, which gave access to the flag.

![evil_flag](/assets/images/posts/2020-02-12-neverlan-ctf/evil_flag.png)

*flag*: `flag{d0nt_l00k_int0_h3r_Eyes!}`
<hr>

## Robot Talk

*This server only gives the flag to bots. You'll need to convince it that you're a bot by answering it's challenges.*

*challenges.neverlanctf.com:1120*

Performing a netcat to the provided host and port shows a `base64` challenge that we have to solve in 10 seconds. If we are fast as hell copying, decoding and pasting by hand it could be done, but as the title suggests, some kind of automation is needed.

To solve this I wrote a simple python script with the help of the awesome [Pwntools](https://github.com/Gallopsled/pwntools)

```python

```

![crack](/assets/images/posts/2020-02-12-neverlan-ctf/crack.png)

*flag*: `flag{orange-1984-zestyfe}`
<hr>

## BitsnBytes

*https://challenges.neverlanctf.com:1150*

Accesing the provided url lead to a svg image formed by just two colors, black and green.

![bits_svg](/assets/images/posts/2020-02-12-neverlan-ctf/bits_svg.png)

From the challenge title, I just realized that it has to be about interpreting each color either as a 0 or a 1. Then, making groups of bytes (8 bits) and converting them to their char representation would probably lead to something "readable". 

In order to automate this I coded a python script.

```python
from lxml  import etree
import timehash

bitsnbytes = "svg.php.svg"
tree = etree.parse(open(bitsnbytes, "r"))

result = ""
result_to_char = ""

c = 0
for element in tree.iter():
    if element.get("style") is not None:
        if "#00ff00" in element.get("style"):
            #green
            result += "0"
        else:
            result += "1"
        c += 1
        if c%8 == 0:
            result += " "

print("[*]Binary representation:\n{}".format(result))

for bit in result.split(" "):
    result_to_char += chr(int(bit, 2))

print("\n[*]Decoded string=> {}".format(result_to_char[:-1]))

#hash_tmp = result_to_char.split(":")[1]
#print("\n[*]Time hash decrypt=> {}".format(timehash.decode(hash_tmp[:1])))
```

It works, but it just give a time hash as a result, which didn't give any interesting info to work with. Here i got a hint from `N30` that suggested me that everything was related to `collect the hash`. Soon I realized that that the image was changing over time, thus giving different results, so I edited the previous script to handle this.

```python
from lxml  import etree
import requests as req

bitsnbytes = "https://challenges.neverlanctf.com:1150/svg.php"

results = []
bit_results = []
changes = []

while True:
	svg = req.get(bitsnbytes, verify=False)
	tree = etree.HTML(svg.text.encode("utf-8"))

	result = ""
	result_to_char = ""
	c = 0

	for element in tree.iter():
		if element.get("style") is not None:
			if "#00ff00" in element.get("style"):
				#green
				result += "0"
			else:
				result += "1"
			c += 1
			if c%8 == 0:
				result += " "

	for byte in result.split(" "):
		result_to_char += chr(int(bit, 2))
		bit_results.append(byte)

	if result_to_char not in results:
		print("[*]Binary representation:\n{}".format(result))
		print("[*]Decoded string=> {}\n".format(result_to_char[:-1]))
		results.append(result_to_char)

	#wait 10 seconds till next request
	time.sleep(10)
```

![bits_running](/assets/images/posts/2020-02-12-neverlan-ctf/bits_running.png)

After some time with it running, the decoded string was indeed the desired flag.

![bits_flag](/assets/images/posts/2020-02-12-neverlan-ctf/bits_flag.png)

*flag*: `flag{its_all_ab0ut_timing}`
<hr><hr>

# Chicken Little

## Chicken Little 1-7

`Not solved. Run out of time.`

My team mate [sarvmetal](https://twitter.com/sarvmetal) solved some of them.

