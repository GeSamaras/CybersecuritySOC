The first Windows process on the list is **System**. It was mentioned in a previous section that a PID for any given process is assigned at random, but that is not the case for the System process. The PID for System is always 4. What does this process do exactly?

The official definition from Windows Internals 6th Edition:

"_The System process (process ID 4) is the home for a special kind of thread that runs only in kernel mode a kernel-mode system thread. System threads have all the attributes and contexts of regular user-mode threads (such as a hardware context, priority, and so on) but are different in that they run only in kernel-mode executing code loaded in system space, whether that is in Ntoskrnl.exe or in any other loaded device driver. In addition, system threads don't have a user process address space and hence must allocate any dynamic storage from operating system memory heaps, such as a paged or nonpaged pool._"

What is user mode? Kernel-mode? Visit the following [link](https://docs.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/user-mode-and-kernel-mode) to understand each of these.

Now, what is normal behaviour for this process? Let's use Process Explorer and view the properties of the System.

![System properties.](https://assets.tryhackme.com/additional/windows-processes/system.png)  

**Image Path**:  N/A
**Parent Process**:  None
**Number of Instances**:  One
**User Account**:  Local System
**Start Time**:  At boot time

The information is slightly different if we view the System properties using Process Hacker.  

![System properties (2).](https://assets.tryhackme.com/additional/windows-processes/system2.png)  
 
**Image Path**: C:\Windows\system32\ntoskrnl.exe (NT OS Kernel)
**Parent Process**: System Idle Process (0)

Technically this is correct. You may notice that Process Hacker confirms this is legit (Verified) Microsoft Windows. 

What is unusual behaviour for this process?
- A parent process (aside from System Idle Process (0))
- Multiple instances of System. (Should only be one instance) 
- A different PID. (Remember that the PID will always be PID 4)
- Not running in Session 0


The Sysinternals tool(s) can be downloaded and run from the local system, or the tool(s) can be run from the web. 

Regarding local install/run, you can download the entire suite or just the tool(s) you need.

If you wish to download a tool or two but not the entire suite, you can navigate to the **Sysinternals Utilities Index** page, [https://docs.microsoft.com/en-us/sysinternals/downloads/](https://docs.microsoft.com/en-us/sysinternals/downloads/), and download the tool(s). If you know which tool you want to download, then this is fine. The tools are listed in alphabetical order are not separated by categories.

![Screenshot showing the webpage of Sysinternals Utilities Index](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/87a25829f06c629a47f269fb1650339a.png)  

Alternatively, you can use the category links to find and download the tool(s). This route is better since there are so many tools you can focus on all the tools of interest instead of the entire index.

For example, let's say you need tools to inspect Windows processes; then, you can navigate to the **Process Utilities** page, [https://docs.microsoft.com/en-us/sysinternals/downloads/process-utilities/](https://docs.microsoft.com/en-us/sysinternals/downloads/process-utilities/), for all the tools that fall under this category.

![Screenshot showing the webpage of Sysinternals Process Utilities](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/9b077a2ec0682837f2f31e48c357c94e.png)  

Notice that you are conveniently supplied with a brief explanation for each tool. 

Lastly, you can do the same from the Sysinternals Live URL, [https://live.sysinternals.com/](https://live.sysinternals.com/). This is the same URL to use if you wish to run the tool from the web. We will look at how to accomplish this in the next section.

If you chose to download from this page, it is similar to the Sysinternals Utilities Index page. The tools are listed in alphabetical order and are not separated by categories.


**Environment Variables** can be edited from **System Properties**.

The System Properties can be launched via the command line by running `sysdm.cpl`. Click on the `Advanced` tab. 

![Screenshot showing MS Windows System Properties Advanced tab](https://assets.tryhackme.com/additional/sysinternals/env-variables.png)  

Select `Path` under `System Variables` and select Edit... then OK.

![Screenshot showing the Path variable under System Variables](https://assets.tryhackme.com/additional/sysinternals/env-variables2.png)  

In the next screen select `New` and enter the folder path where the Sysinternals Suite was extracted to. Press OK to confirm the changes.

![Screenshot showing the addition of a new directory under the Path variable](https://assets.tryhackme.com/additional/sysinternals/env-variables3.png)  

Open a new command prompt (elevated) to confirm that the Sysinternals Suite can be executed from any location.

![Screenshot showing the Process Monitor tool started from the command prompt](https://assets.tryhackme.com/additional/sysinternals/env-variables4.png)  

A local copy of the Sysinternals Suite is located in `C:\Tools\Sysint`. 

Alternatively, a PowerShell module can download and install all of the Sysinternals tools. 

- PowerShell command: `Download-SysInternalsTools C:\Tools\Sysint`
