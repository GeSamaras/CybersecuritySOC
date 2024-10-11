![[Pasted image 20241008071639.png]]

verifying if the machine is running properly with a quick ping

# Enumerating

![[Pasted image 20241008071849.png]]

Initial scan with nmap, running default scripts and outputting to a text file for convenience.
![[Pasted image 20241008072232.png]]
And the results are out! The lab ask specifically for attention on ports 139 and 445, and we can see that they are running Microsoft services, netbios and Microsoft-DS Active Directory.


