Couple tips in TCP stream for 10.0.0.30
```
running version ngircd-27 (x86_64/alpine/linux-musl)
IRC Server created in Tue Sep 24 2024 at 10:49:06 (CEST)

```

User list: 
- An4lys3r 
- @D3f3nd3r

They mention doing a test run a couple months before September.

# Ransom note

```
D3f3nd3r!~user1@10.0.0.20:

SHA-256 checksum for /home/user/emergency_net/DCC/RANSOM_NOTE.gz (remote): 7113f236b43d1672d881c6993a8a582691ed4beb4c7d49befbceb1fddfb14909
```

Found in the IRC convo, this sha256sum contains the ransom_note file
went in the tcp packet and saved the raw data into a file with the same name 
it spits out a massive poopy looking string 

### CTF-PC01

```
D3f3nd3r!~user1@10.0.0.20 PRIVMSG #emergency :

by the way, Christine came by and handed me a disk image from one of the clients, see if they left any clues on disk. I'll ==upload it to the ftp shortly==.

recording network traffic from a windows workstation called CTF-PC01. I'll upload the file to the ftp.
```



# Trying to solve tcp.stream 8
wrote an algorithm to replace all dots "." with a blank space, in the hopes of finding something useful:

![[Pasted image 20241011192259.png]]



result string still spits out gibberish

![[Pasted image 20241011192126.png]]

# Bruh?
tcp.stream eq 4
h.ttp://x1.c.lencr.org/0

![[Pasted image 20241011185315.png]]

tcp.stream eq 7
![[Pasted image 20241011190348.png]]


# FTP Wordlist and PCAP files

tcp.stream eq 9

![[Pasted image 20241011182845.png]]
anonymous user got in with password ==NcFTP@==
sent WORDLIST.txt to PORT 10,0,0,20,146,93

wordlist that was sent:
![[Pasted image 20241011184230.png]]
and then ==corp_net1.pcap== was sent over ftp

# IMPORTANT INFO

Suspicious IP involved in Command and Control attacks:  195.200.72.82
![[Pasted image 20241011202911.png]]
# Flags

CTF[E65D46AD10F92508F500944B53168930]
CTF[AES128]
CTF[OR]

//////////
RTRRTEo@@xn
<wbU6
\x7PASS CTF[AES128]
NICK D3f3nd3r
USER user1 0 * :realname
///////////

RTRRTE@@w

<8bV7
^x7PRIVMSG #emergency :SHA-256 checksum for /home/user/emergency_net/DCC/RANSOM_NOTE.gz (remote): 7113f236b43d1672d881c6993a8a582691ed4beb4c7d49befbceb1fddfb14909
