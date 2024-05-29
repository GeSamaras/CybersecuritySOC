Evidence of Execution

**UserAssist**:

Windows keeps track of applications launched by the user using Windows Explorer for statistical purposes in the User Assist registry keys. These keys contain information about the programs launched, the time of their launch, and the number of times they were executed. However, programs that were run using the command line can't be found in the User Assist keys. The User Assist key is present in the NTUSER hive, mapped to each user's GUID. We can find it at the following location:

`NTUSER.DAT\Software\Microsoft\Windows\Currentversion\Explorer\UserAssist\{GUID}\Count`


![](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/9bd8461865865ac3ff774c8a88d1afd5.png)

**ShimCache:**  

ShimCache is a mechanism used to keep track of application compatibility with the OS and tracks all applications launched on the machine. Its main purpose in Windows is to ensure backward compatibility of applications. It is also called Application Compatibility Cache (AppCompatCache). It is located in the following location in the SYSTEM hive:

`SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`  

ShimCache stores file name, file size, and last modified time of the executables.

Our goto tool, the Registry Explorer, doesn't parse ShimCache data in a human-readable format, so we go to another tool called AppCompatCache Parser, also a part of Eric Zimmerman's tools. It takes the SYSTEM hive as input, parses the data, and outputs a CSV file that looks like this:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/aad7dc918dbf3b1ab207dd71d03e8c0c.png)

We can use the following command to run the AppCompatCache Parser Utility:

`AppCompatCacheParser.exe --csv <path to save output> -f <path to SYSTEM hive for data parsing> -c <control set to parse>`

**Task**
Opening Registry Explorer in EZTools to search up all users connected in the desktop.
Most important registry hives are found in System32/Config. in Windows 

![[Pasted image 20240527003522.png]]
Tables "User name" and "Comment" give a good idea of who the users are, including which ones are made by the OS.

**NTUSER.DAT**
https://appuals.com/ntuser-dat-file-explained/
NTUSER.DAT is a file that is created by the Microsoft Windows operating system. The DAT extension files are data files that store some specific information related to the program. The data in DAT files can be plain or in binary format. The NTUSER.DAT file contains the information of the user account settings and customizations. Each user will have their own NTUSER.DAT file in their user’s profile. This file will be hidden by Microsoft because they don’t want users to interact with this file. The NTUSER.DAT file ensures that any changes you make in your user account are saved and loaded when you sign in back again.

![[Pasted image 20240527011317.png]]