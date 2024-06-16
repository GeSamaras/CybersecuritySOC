- Redline User Guide: [https://fireeye.market/assets/apps/211364/documents/877936_en.pdf](https://fireeye.market/assets/apps/211364/documents/877936_en.pdf)[](https://www.fireeye.com/content/dam/fireeye-www/services/freeware/ug-redline.pdf)
- IOC Editor User Guide: [https://fireeye.market/assets/apps/S7cWpi9W//9cb9857f/ug-ioc-editor.pdf](https://fireeye.market/assets/apps/S7cWpi9W//9cb9857f/ug-ioc-editor.pdf)

Many tools can aid a security analyst or incident responder in performing memory analysis on a potentially compromised endpoint. One of the most popular tools is **[Volatility](https://tryhackme.com/room/volatility)**, which will allow an analyst to dig deep into the weeds when examining memory artifacts from an endpoint. But this process can take time. Often, when an analyst is triaging, time is of the essence, and the analyst needs to perform a quick assessment to determine the nature of a security event.

That is where the FireEye tool [**Redline**](https://fireeye.market/apps/211364) comes in. Redline will essentially give an analyst a 30,000-foot view (10 kilometers high view) of a Windows, Linux, or macOS endpoint. Using Redline, you can analyze a potentially compromised endpoint through the memory dump, including various file structures. With a nice-looking GUI (Graphical User Interface) - you can easily find the signs of malicious activities. 

  

Here is what you can do using Redline:

- Collect registry data (Windows hosts only)
- Collect running processes
- Collect memory images (before Windows 10)
- Collect Browser History
- Look for suspicious strings
- And much more!

There are three ways or options to collect data using Redline: 

![](https://assets.tryhackme.com/additional/redline101/capture2.png)  

1. Standard Collector - this method configures the script to gather a minimum amount of data for the analysis. This is going to be our preferred method to collect data in this room. It is also usually the fastest method to collect the data you need. It takes only a few minutes to complete.
2. Comprehensive Collector - this method configures the script to gather the most data from your host for further analysis. This method takes up to an hour or more. You will choose this method if you prefer the full analysis of the system.
3. IOC Search Collector (Windows only) - this method collects data that matches with the [Indicators of Compromise (IOCs)](https://www.crowdstrike.com/cybersecurity-101/indicators-of-compromise/) that you created with the help of [IOC Editor](https://fireeye.market/apps/S7cWpi9W). You will choose this method if you want to run the data collection against known IOCs that you have gathered either through threat intelligence (data feed or narrative report), incident response, or malware analysis. You imported them into [IOC Editor](https://fireeye.market/apps/S7cWpi9W). We'll look at the IOC Editor a bit further in the next task.

Let's look at the Redline Interface.

You should have your first analysis file. Double-click on the _AnalysisSession1.mans_ file and the data will be imported automatically into Redline. Please give it up to 10 minutes to get the data imported.  

![](https://i.ibb.co/CH6zS38/red1.png)

When the data is imported, you will be presented with this view:

![](https://i.ibb.co/8YhfzHb/redlineee.png)

On the left panel, you will see different types of _Analysis Data;_ this is where you will perform information gathering and investigation process.

- System Information: this is where you will see the information about the machine, BIOS (Windows only), operating system, and user information.
- Processes: processes will contain different attributes such as Process Name, PID, Path, Arguments, Parent process, Username, etc. When you expand the Processes tab, there will be four sections: Handles, Memory Sections, Strings, and Ports.

A handle is a connection from a process to an object or resource in a Windows operating system. Operating systems use handles for referencing internal objects like files, registry keys, resources, etc.

Memory Sections will let you investigate unsigned memory sections used by some processes. Many processes usually use legitimate dynamic link libraries (DLLs), which will be signed. This is particularly interesting because if you see any unsigned DLLs then it will be worth taking a closer look. 

Strings - you will see the information on the captured strings.

Ports - this is one of the critical sections to pay attention to. Most malware often initiates the outbound or inbound connections to communicate to their command and control server (C2) to do some malicious activities like exfiltrating the data or grabbing a payload to the machine. This situation is where you can review the suspicious connections from ports and IP addresses. Pay attention to the system processes as well. The threat actors like to avoid detection by hiding under the system processes. For example, explorer.exe or notepad.exe shouldn't be on the list of processes with outbound connections. 

Some of the other important sections you need to pay attention to are:

- File System (**not included in this analysis session**)
- Registry
- Windows Services
- Tasks (Threat actors like to create scheduled tasks for persistence)
- Event Logs (this another great place to look for the suspicious Windows PowerShell events as well as the Logon/Logoff, user creation events, and others)
- ARP and Route Entries (**not included in this analysis session**)
- Browser URL History (**not included in this analysis session**)
- File Download History

We briefly discussed the usage of the **IOC Search Collector** in the **Data Collection** task.

Let's take a closer look at the capabilities of this collector type. But first, let's recap what an IOC is.   

IOC stands for **Indicators of Compromise**; they are artifacts of the potential compromise and host intrusion on the system or network that you need to look for when conducting threat hunting or performing incident response. IOCs can be MD5, SHA1, SHA256 hashes, IP address, C2 domain, file size, filename, file path, a registry key, etc.

One of the great tools you can use is [IOC Editor,](https://fireeye.market/apps/S7cWpi9W) created by FireEye, to create IOC files. You can refer to this link to learn how to use the IOC Editor: [https://fireeye.market/assets/apps/S7cWpi9W//9cb9857f/ug-ioc-editor.pdf](https://fireeye.market/assets/apps/S7cWpi9W//9cb9857f/ug-ioc-editor.pdf). 

**Note**: According to the [IOC Editor](https://fireeye.market/apps/S7cWpi9W) download page Windows 7 is the latest operating system officially supported. It is the same version installed in the attached VM. There is another tool called [OpenIOC Editor](https://fireeye.market/apps/211404) by FireEye, which supports Windows 10 that is worth taking a look at.

Next, create the IOC file.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/b26d9e80ac55821643531c3a0436f633.png)  

**Keylogger indicators in IOC Editor**:

![](https://i.ibb.co/02VS0M6/keylogger2.png)

A brief explanation of the above image:  

- The **Name** of the IOC file is Keylogger, Keylogger.ioc. (this field you can edit)
- The **Author** is RussianPanda. (this field you can edit)
- **GUID**, **Created**, and **Modified** are fields you can **NOT** edit, and IOC Editor populates the information.
- Under **Description**, you can add a summary explaining the purpose of the IOC file.

The actual IOCs will be added under, you guessed it, **Add**. 

Here are the values from the image above:

- **File Strings** - `psylog.exe`
- **File Strings** - `RIDEV_INPUTSINK`
- **File MD5** - `791ca706b285b9ae3192a33128e4ecbb`
- **File Size** - `35400`

Refer to the gif below to get an idea of adding specific IOCs to the IOC file.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/01db4361981d214c2692aa10d59961d1.gif)  

Once you select an item you can enter the value for the item directly. 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/81e9ffdb97a2ce98e8b9cec57a2be261.png)  

You can also add it within the **Properties**. 

  

All the fields are read-only except for **Content** and **Comment**. To add a value to the item enter it under **Content**. 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/5a0e549950f7ca673699d51a2ff14bc9.png)  

Once you enter the value click Save to save it.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/9d95abf1f3d62f3fe7d2eb6352b86235.png)  

**Note**: You can right-click on an item for additional options. See below.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/f5173beaf331e84b7672daf6be726092.png)  

We'll leave that for you to explore on your own. 

Now that we've created and saved the IOC file, let's move on and go back to the **IOC Search Collector** in the **Redline** tool.

**Note**: If you closed Redline now is the time to relaunch the application. You can close IOC Editor, again, to free up system resources. 

**IOC Search Collector** will ignore the data that doesn't match an IOC you have gathered. Although, you can always choose to collect additional data. As the Redline User Guide states, the quality of the IOC analysis will depend on the data you have available in the analysis session.

![](https://i.ibb.co/SwvyRyq/ioc.png)

To create an IOC Search Collector, click "Browse..." and choose the location of the .ioc file. Redline will automatically detect the .ioc file and place it in the Indicators section, as shown below.

**IOC Search Collector**:  

![](https://i.ibb.co/2S2t1sB/keylogger.png)  

**Unsupported Search Terms:** These terms will not show any successful hits in Redline, which means Redline doesn't recognize specific search terms. 

**Supported Search Terms:** The terms that Redline will recognize and search for.

After you are finished reviewing the configured IOCs, click "Next". Now click on "Edit your script" to configure what data will be collected for the analysis. For this example, Keylogger file IOC Search, the following parameters were selected.   

  

![](https://i.ibb.co/g7JkhPr/keylogger3.png)


