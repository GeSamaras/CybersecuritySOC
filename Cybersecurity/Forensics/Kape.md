## ﻿**Introduction to KAPE:**

Kroll Artifact Parser and Extractor (KAPE) parses and extracts Windows forensics artifacts. It is a tool that can significantly reduce the time needed to respond to an incident by providing forensic artifacts from a live system or a storage device much earlier than the imaging process completes. 

KAPE serves two primary purposes, 1) collect files and 2) process the collected files as per the provided options. For achieving these purposes, KAPE uses the concept of targets and modules. Targets can be defined as the forensic artifacts that need to be collected. Modules are programs that process the collected artifacts and extract information from them. We will learn about them in the upcoming tasks.

## **How it works**

KAPE is extensible and highly configurable. In essence, the KAPE binary ﻿ collects files and processes them as per the provided configuration.

The collection of files (targets) KAPE adds the files to a queue and copies them in two passes. In the first pass, it copies the files that it can. This works for files that the OS has not locked. The rest of the files are passed to a secondary queue. The secondary queue is processed using a different technique that uses raw disk reads to bypass the OS locks and copy the files. The copied files are saved with original timestamps and metadata and stored in a similar directory structure. 

Once the data is collected, KAPE can process it using modules. The modules can be independent binaries that run on the collected data and process them to extract information. For example, KAPE will collect and copy the Prefetch file to our target destination during the target collection. Running a Prefetch Parser (PECmd) module on this target will extract the prefetch file and save it in a CSV file. 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/d1489a8062d714fa227dd3382dfd15d1.png)  

As the above image shows, KAPE can extract targets from a Live system, a mounted image, or the [F-response](https://www.f-response.com/) utility. KAPE does not need to be installed. It is portable and can be used from network locations or USB drives.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/6af6adcb6ce48c0dd32aec787206e20d.png)  

**Tip:** If the Window is not correctly visible in the split-screen, you can open it in a full browser tab by clicking this button:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/af1a133b7384aac273451343dadc032d.png)  

Here you can see that there are different options, but most are disabled. To collect `Targets` We will go ahead by enabling the `Use Target Options` checkbox. This will enable the options present in the left half of the Window:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/ef839c3076a311b29ac9fedd933d58d8.png)  

If we want to perform forensics on the same machine on which KAPE is running, we will provide `C:\` for the Target source. We can select the target destination of our choice. All the triage files will be copied to the Target destination that we provide.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/f4a865927aef7b0fa4668f13ef8f9cfa.png)  

Here, the `Flush` checkbox will delete all the contents of the Target destination, so we have to be careful when using that. We have disabled the `Flush` checkbox so that it does not delete data already present in the directories. `Add %d` will append date info to the directory name where the collected data is saved. Similarly, `Add %m` will append machine info to the Target destination directory. We can select our desired Target from the list shown above. The Search bar helps us search for the names of the desired Targets quickly.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/a513c60028421e8fd103a161e1492e0a.png)  

We can select if we want to process Volume Shadow Copies by enabling `Process VSCs`. We can select the `transfer` checkbox if we want to transfer the collected artifacts through an SFTP server or an S3 bucket. For transfer, the files must be enclosed in a container, which can be Zip, VHD, or VHDX. Similarly, we can provide exclusions based on SHA-1, and KAPE will not copy the excluded files. When enclosing in a container, we will need to give a `Base name` that will be used for all the created files. It is not required if we are not transferring files or enclosing them in a container.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/22a7063c7c3bb75bc2ddaede7fcf9f57.png)  

In the `Current command line` tab, we can see the command line options being added or removed while configuring the UI. This Window will show more options in the command line as we add options. Please note that the destination path in your case will be different from the one shown in the image. Notice the `--tflush` flag here. It means that when this command line was created, the `Flush` checkbox was still checked.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/fd514feceacfd972097ef26b5ac433ed.png)  

By checking the Use Module Options checkbox, the right side of the KAPE Window will also be enabled.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/811ceeea4083ab70546d89f5ecfc2f6f.png)

When using both Target and Module Options, providing Module Source is not required. The selected Modules will use the Target destination as the source.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/8807a5d8eaf027af5f6e0a174e8079d3.png)

The rest of the options for Modules are similar to the ones for Targets, so we won't go into details for them.

Below you will see what the configuration looks like when we have KAPE all set up for collecting Targets and processing them using Modules.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/d4e260cbc96fd497859c9133cdb345a8.png)  

We have selected the `KapeTriage` compound Target and `!EZParser` Compound Module. The command line below shows the CLI command that will be run. The `Execute!` button in the bottom right corner will execute the command. The `Disable flush warnings` checkbox underneath it will not warn us when we are using the `Flush` flags. When we press `Execute!` We will see a command line window open and show us the logs as KAPE performs its tasks. It will take a few minutes to execute since it will be collecting all the data and then running the module processes on it. Once it completes, it will show us the total execution time, and we can press any key to terminate the command window.

D:\Kape\kape.exe

```shell-session
KAPE version 1.1.0.1 Author: Eric Zimmerman (kape@kroll.com)

KAPE directory: D:\KAPE
Command line: --tsource C: --tdest C:\Users\Umair\Desktop\kape --target KapeTriage --mdest C:\Users\Umair\Desktop\4n6-2 --module !EZParser --gui

System info: Machine name: UMAIR-THINKBOOK, 64-bit: True, User: Umair OS: Windows10 (10.0.22000)

Using Target operations
Found 14 targets. Expanding targets to file list...
Target 'ApplicationEvents' with Id '2da16dbf-ea47-448e-a00f-fc442c3109ba' already processed. Skipping!
Target 'ApplicationEvents' with Id '2da16dbf-ea47-448e-a00f-fc442c3109ba' already processed. Skipping!
Target 'ApplicationEvents' with Id '2da16dbf-ea47-448e-a00f-fc442c3109ba' already processed. Skipping!
Target 'ApplicationEvents' with Id '2da16dbf-ea47-448e-a00f-fc442c3109ba' already processed. Skipping!
Target 'ApplicationEvents' with Id '2da16dbf-ea47-448e-a00f-fc442c3109ba' already processed. Skipping!
Found 3,059 files in 4.257 seconds. Beginning copy...
        Deferring 'C:\Windows\System32\winevt\logs\Application.evtx' due to IOException...
        Deferring 'C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx' due to IOException...
        Deferring 'C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4WHC.evtx' due to IOException...
        Deferring 'C:\ProgramData\Microsoft\Windows Defender\Support\MPDetection-20220126-183133.log' due to IOException...
        Deferring 'C:\ProgramData\Microsoft\Windows Defender\Support\MPDeviceControl-20211016-164735.log' due to IOException...
        Deferring 'C:\ProgramData\Microsoft\Windows Defender\Support\MPLog-10172021-040927.log' due to IOException...
        Deferring 'C:\ProgramData\Microsoft\Windows Defender\Support\MpWppTracing-20220210-070038-00000003-ffffffff.bin' due to IOException...
        Deferring 'C:\Windows\System32\winevt\logs\HardwareEvents.evtx' due to IOException...
        Deferring 'C:\Windows\System32\winevt\logs\IntelAudioServiceLog.evtx' due to IOException...
        Deferring 'C:\Windows\System32\winevt\logs\Internet Explorer.evtx' due to IOException...
.
.
.
.
Executing remaining modules...
        Running 'EvtxECmd\EvtxECmd.exe': -d C:\Users\Umair\Desktop\kape --csv C:\Users\Umair\Desktop\4n6-2\EventLogs
        Running 'JLECmd.exe': -d C:\Users\Umair\Desktop\kape --csv C:\Users\Umair\Desktop\4n6-2\FileFolderAccess -q
        Running 'LECmd.exe': -d C:\Users\Umair\Desktop\kape --csv C:\Users\Umair\Desktop\4n6-2\FileFolderAccess -q
        Running 'PECmd.exe': -d C:\Users\Umair\Desktop\kape --csv C:\Users\Umair\Desktop\4n6-2\ProgramExecution -q
        Running 'RBCmd.exe': -d C:\Users\Umair\Desktop\kape --csv C:\Users\Umair\Desktop\4n6-2\FileDeletion -q
        Running 'RECmd\RECmd.exe': -d C:\Users\Umair\Desktop\kape --bn BatchExamples\Kroll_Batch.reb --nl false --csv C:\Users\Umair\Desktop\4n6-2\Registry -q
        Running 'SBECmd.exe': -d C:\Users\Umair\Desktop\kape --csv C:\Users\Umair\Desktop\4n6-2\FileFolderAccess -q
        Running 'SQLECmd\SQLECmd.exe': -d C:\Users\Umair\Desktop\kape --csv C:\Users\Umair\Desktop\4n6-2\SQLDatabases
        Running 'SrumECmd.exe': -d C:\Users\Umair\Desktop\kape -k --csv C:\Users\Umair\Desktop\4n6-2\SystemActivity
        Running 'SumECmd.exe': -d C:\Users\Umair\Desktop\kape\Windows\System32\LogFiles\SUM --csv C:\Users\Umair\Desktop\4n6-2\SUMDatabase
Executed 18 processors in 192.2738 seconds

Total execution time: 258.1812 seconds


Press any key to exit
```

Notice that at the backend, KAPE is running the `kape.exe` in a command line. We can check out the files created by KAPE once it completes processing them. The below snapshot shows our `Module destination`. Notice how KAPE has processed the files according to different categories.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/a0fad94b0afd9f8f424f3071f0d4e475.png)


For a list of all the different switches that can be used with KAPE, open an elevated PowerShell (Run As Administrator), go to the path where the KAPE binary is located, and type `kape.exe`. You will see something like this as an output.

With this information, let's build a command to perform the same task we performed in the previous task. i.e., collect triage data using the `KapeTriage` Compound Target and process it using the `!EZParser` Compound Module. Since we are not using the GUI version, we will start with typing:

`kape.exe`

To add a Target source, let's append `--tsource` and that Target path:

`kape.exe --tsource C:` 

The `--target` flag will be used for selecting the Target the `--tdest` flag for the Target destination. For the sake of simplicity, we will set the Target destination to a directory named target on the Desktop. KAPE will create a new directory if it doesn't already exist. Our command line now looks like this:

`kape.exe --tsource C: --target KapeTriage --tdest C:\Users\thm-4n6\Desktop\target` 

Running the above command will collect triage data defined in the KapeTriage Target and save it to the provided destination. However, it will not process it or perform any other activity on the data.

If we want to flush the Target destination, we can add `--tflush` to do that. For now, let's move on to adding the Module options. If we were using a Module source, we would have used a >`--msource` flag in a similar manner to the `--tsource` flag. But in this case, let's use the Target destination as the Module source. By doing this, we will not need to add it explicitly, and we can move on to adding the Module destination using the `--mdest` flag:

`kape.exe --tsource C: --target KapeTriage --tdest C:\Users\thm-4n6\Desktop\Target --mdest C:\Users\thm-4n6\Desktop\module`

We have just used a directory named module for the Module destination.

To Process the Target destination using a Module, we need to provide the Module name using the `--module` flag. To process it using the `!EZParser` Module, we will append `--module !EZParser`, making our command look like this:

`kape.exe --tsource C: --target KapeTriage --tdest C:\Users\thm-4n6\Desktop\Target --mdest C:\Users\thm-4n6\Desktop\module --module !EZParser`

Please note that we will need to run this command in an elevated shell (with Administrator privileges) for KAPE to collect the data.

We can modify the command as per our needs and the switches provided by KAPE. When we run this command, we will see a similar window as in the previous task. You can check out the files collected by KAPE Targets and Modules once it completes.

## **Batch Mode:**

﻿KAPE can also be run in batch mode. What this means is that we can provide a list of commands for KAPE to run in a file named `_kape.cli`. Then we keep this file in the directory containing the KAPE binary. When `kape.exe` is executed as an administrator, it checks if there is `_kape.cli` file present in the directory. If so, it executes the commands mentioned in the cli file. This mode can be used if you need someone to run KAPE for you, you will keep all the commands in a single line, and all you need is for the person to right-click and run kape.exe as administrator. For example, if we have to perform the same task as we did earlier in this task using batch mode, we will have to create a _kape.cli file with the following content:

`--tsource C: --target KapeTriage --tdest C:\Users\thm-4n6\Desktop\Target --mdest C:\Users\thm-4n6\Desktop\module --module !EZParser`

When we run `kape.exe`, it will perform the same tasks as when we ran it through CLI above.

