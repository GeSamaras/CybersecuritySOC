**==What the version and year of the windows machine?==**

```
systeminfo

Microsoft Windows Server 2016 Datacenter
IP address(es)
                                 [01]: 10.10.20.71
                                 [02]: fe80::99af:4cf5:fc9c:925a
```


**==Which user logged in last?==**

```CMD
Event Viewer > Security > Audit Success > Account Name
```


In Powershell 
```Powershell
Get-LocalUser
```


**==When did John log onto the system last?==**

```Powershell
net user John |findstr “Last”
  3/2/2019 5:48:32 PM
```


**==What IP does the system connect to when it first starts?==**

C:\ > Windows > System32 > drivers > etc_
_HKEY_LOCAL_MACHINE >_ _SOFTWARE > Microsoft > Windows > CurrentVersion > Run
![[Pasted image 20240527175923.png]]


**==What two accounts had administrative privileges (other than the Administrator user)?
Answer format: username1, username2==**
![[Pasted image 20240527180207.png]]
Jenny and guest

**==What is the name of the scheduled task that is malicious.==**
```Powershell
Get-ScheduledTask
```
![[Pasted image 20240528003623.png]]
"Gameover" / Clean File System

**==What file was the task trying to run daily?==**

![[Pasted image 20240528004035.png]]

**==What port did this file listen locally for?==**

Arguments: -l 1348

**==When did Jenny last logon?==**

```Powershell
net user Jenny | findstr “Last”
```

**==At what date did the compromise take place?==**

![[Pasted image 20240528005045.png]]

**==During the compromise, at what time did Windows first assign special privileges to a new logon?==**
![[Pasted image 20240528005541.png]]


**==What tools was used to get Windows passwords?==**

C:\TMP\mim-out.txt
mimikatz

==**What was the attackers external control and command servers IP?**==

![[Pasted image 20240528010507.png]]

**==What was the extension name of the shell uploaded via the the servers website?==**

76.32.97.132

==**What was the extension name of the shell uploaded via the servers website?**==

.jsp

**==What was the last port the attacker opened?==**

1337

**==Check for DNS poisoning, what site was targeted?==**

google.com


