1.   
    Use the KQL query to list all failed SSH auth events on the Jumphost server:  
      
    `host.name: jumphost AND event.category: authentication AND system.auth.ssh.event: Failed`  
    

![Lens table of failed logon attempts via SSH.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/a7729d0aa83bae1e45489b4d8697432e.png)

_**Click to enlarge the image**_  

Upon checking the results above (highlight #5), it can be observed that the table provided the count of failed login attempts on specific users, including the source of the attack. These two IP addresses and accounts are highly notable since they generated over 500 failed authentication events within the given timeframe.

Now that we have gathered significant information about brute-force attempts, let's find a successful authentication. By doing this, we can verify if the attacks yielded successful results; in this case, the attacker accessed the Jumphost server successfully via SSH. To do this, we can replace the KQL query with the following: 

`host.name: jumphost AND event.category: authentication AND system.auth.ssh.event: Accepted AND source.ip: (167.71.198.43 OR 218.92.0.115)` 

This query focuses on the top 2 IP addresses where the SSH authentication event was **Accepted** using a valid credential.

![Lens table view of successful SSH authentication.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/0bc2a6d4be366ddd0bf59c7538e42f86.png)

_**Click to enlarge the image**_  

Now that we have confirmed that the attacker from `167.71.198.43` accessed the Jumphost server using the `dev` account, we have successfully hunted an intrusion attempt on this server. Following a threat hunter's mindset, the next step of this investigation is to identify the commands issued by the `dev` user after authenticating via SSH. 

On a footnote, it is not always the case that brute-forcing activities are the only indicators of unusual logon activity. Hunting can also be done in another way wherein you will hunt for successful authentication via SSH, differentiate the authentication source (IP address) and correlate the unusual activity after the successful execution to see potential intrusion attempts.

Remote Code Execution on Web01

In the following scenario, we will use the `packetbeat-*` index and hunt for suspicious actors attacking our web application (`web01`) on July 3, 2023. Ensure all queries to the Kibana console are set to look for the right index and timeframe.

Web application attacks typically start with enumeration attempts and proceed with exploiting discovered vulnerabilities. We will hunt for behaviours that satisfy this idea.

To start hunting, use the Visualize Library again and create a visualisation table using Lens. Ensure that the table is configured with the following:

1. Set the timestamp to July 3.
2. Set the index to packetbeat.
3. Set the Table Index (packetbeat), Rows (source.ip and http.response.status_code), and Metrics (count).
4. Use the KQL query to list all ingress network connections to the web server:  
      
    `host.name: web01 AND network.protocol: http AND destination.port: 80`  
    

**Note: The `http.response.status_code` is included in the rows to identify the web application's response to the attacker's HTTP requests.**

![Lens table view of ingress HTTP traffic to web01.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/a8191b2574cc9f57739e3640bf86c8cb.png)

**_Click to enlarge the image_**  

Upon checking the results above (highlight #5), it can be observed that the query provided a high count of `status code 404`, indicating a directory enumeration attempt by `167.71.198.43` since the attack produces many "Page Not Found" results due to its behaviour of guessing valid endpoints.

To better understand the attack, we can continue the investigation using the Discover tab with a query focused on status code 404 and the attacker's IP address. Let's use the following KQL query in the Discover tab: 

`host.name: web01 AND network.protocol: http AND destination.port: 80 AND source.ip: 167.71.198.43 AND http.response.status_code: 404`  

In addition, select the following fields and add them as a column:

- query
- user_agent.original  
    
- url.query  
    

![All events related to the directory enumeration attack via the Discover console.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/b3aed47ec50e397bf656a2d7acc79a14.png)  

_Click to enlarge the image_  

Based on the results, it can be seen that the attacker used **Gobuster** (inferred via the User Agent) to enumerate the directories in the web application and eventually focused on the `/gila` directory, which may indicate that the attacker is attempting to exploit the said application.

To continue, let's replace the KQL query with **status codes 200, 301, and 302** to focus on valid endpoints accessed by the attacker. 

`host.name: web01 AND network.protocol: http AND destination.port: 80 AND source.ip: 167.71.198.43 AND http.response.status_code: (200 OR 301 OR 302)`  

In addition, sort the timestamp in ascending order (click the arrow beside the Time column to view the sequence of attacks from the earliest timestamp).

![Events that may indicate a successful attack via the Discover console.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/00714db972dc460ddb8c99cfaff4d045.png)  

_Click to enlarge the image_  

Based on the results, we can infer the following:

- After discovering the **/gila** endpoint, the attacker focused on accessing it.
- The attacker then used a suspicious PHP code on the User-Agent field. The code uses x as a GET parameter to execute host commands via the system function.
- Lastly, the attacker used the x parameter to execute host commands.

With these findings, we can say that the attacker successfully compromised the web server, exploiting a Remote Code Execution vulnerability in our Gila web application. Following a threat hunter's mindset, the next step of this investigation is to identify the impact of the commands executed by the attacker via Remote Code Execution.

Phishing Links and Attachments

For our last scenario, we will use the `winlogbeat-*` index and hunt for indicators of malicious links and attachments being opened or downloaded from employee workstations on July 3, 2023. Ensure all queries to the Kibana console are set to look for the right index and timeframe.  

Phishing emails containing malicious links or attachments of malware payloads are either downloaded or opened directly from the email client before being executed. Given this, we will hunt for the following behaviours that satisfy this idea:

1. Files downloaded using a web browser.
2. Files opened from an email client (in this case, we will be hunting files opened from an Outlook client).

**Files Downloaded using Chrome**

Using the Discover tab, we will first focus on phishing links downloaded using a web browser. By using the following KQL query, we will hunt file creations (Sysmon Event ID 11) generated by chrome.exe:

`host.name: WKSTN-* AND process.name: chrome.exe AND winlog.event_id: 11`

In addition, ensure that the following fields are added as columns to aid us in our investigation:

- winlog.computer_name
- winlog.event_data.User
- file.path  
    

![Files created by the Chrome process that may indicate a potential download attempt of a malicious attachment.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/297abb4fdb610a0edc133d9b28ee8318.png)  

_Click to enlarge the image_

**Note: We can ignore the .tmp files created by Chrome. By default, chrome.exe creates a temporary file when a file is being downloaded.**

Based on the results, we can see that the following users on their respective workstations have downloaded unusual files.

|   |   |   |
|---|---|---|
|User|Workstation|Files Downloaded|
|THREATHUNTING\clifford.miller|WKSTN-1.threathunting.thm|C:\Users\clifford.miller\Downloads\chrome.exe<br><br>C:\Users\clifford.miller\Downloads\microsoft.hta|
|THREATHUNTING\bill.hawkins|WKSTN-2.threathunting.thm|C:\Users\bill.hawkins\Downloads\update.exe|

We can confirm if these files are suspicious once we see them in action. Since this task only focuses on the intrusion attempt, investigating these artefacts will continue on the following tasks. Following a threat hunter's mindset, the next step of this investigation is to identify potential child processes spawned or network connections made by these suspicious files.

**Files Opened using Outlook**  

For an alternative way of hunting malware payloads delivered via phishing emails, we will hunt phishing attachments opened using an Outlook client. Using the same setup of the Discovery tab, use the following KQL query to track files created by the Outlook client:

`host.name: WKSTN-* AND process.name: OUTLOOK.EXE AND winlog.event_id: 11`

![Files created by the outlook process that may indicate open attempt of an attachment.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/7fda4f67be441f5a45766fc66c484725.png)  

_Click to enlarge the image_  

Based on the results, an attachment named Update.zip was opened, which was temporarily stored in the `\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\` directory. Alternatively, this string can be used as a query syntax to hunt files created from the Outlook cache directory.

To confirm the zip file's contents, we can use the following KQL query to find events connected to it: `host.name: WKSTN-* AND *Update.zip*`

![Events related to the malicious zip file.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/1a26656dcda0a590b7bd0fd1be0f5c6a.png)

_Click to enlarge the image_  

Based on the results, we confirm that an LNK file exists from the archive. A shortcut file (.lnk) archived to zip is a typical malware attachment threat actors use. Following a threat hunter's mindset, the next step of this investigation is to identify the process spawned by the shortcut file. This can be done by following the events generated by update.lnk.

To do this in Kibana, click the dropdown of one of the events related to update.lnk and view the surrounding documents. Note that we have also added the `process.executable` column to aid us in correlating the events.

![View surrounding documents button to see events around the creation of the malicious zip file.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/218ec87deb70ed7bb0ba985f51a05a9c.png)

_Click to enlarge the image_  

Once the Surrounding Documents page is opened, filter the events to only focus on `WKSTN-2.threathunting.thm` and modify the count of newer documents to see the subsequent events generated.

![Events generated around the creation of the malicious zip file.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/f09e1ada7dca3913d1dd067d0304694c.png)


Tactic: Execution

The [Execution Tactic (TA0002)](https://attack.mitre.org/tactics/TA0002/) refers to adversaries' techniques to execute or run their malicious code in conjunction with the initial access techniques or ways of delivering the attack. This stage in the cyber-attack lifecycle is crucial as it enables the attackers to successfully run their commands remotely and continue with the series of attacks to establish further access. Example techniques used by adversaries are the following:

- Execution through command-line tools like PowerShell and Windows Command Processor (cmd.exe).
- Execution through built-in system tools or using [Living-off-the-land Binaries (LOLBAS)](https://lolbas-project.github.io/).
- Execution through scripting/programming tools, such as Python or PHP.

Moreover, these examples are typically used to download a staged payload. This means that the execution chain to establish persistent remote access starts with a minimised type of execution. This reduced-footprint approach is employed to mitigate the risk of detection in the early stages of the attack. By using a smaller, more discreet payload for initial infiltration, the attacker increases their chances of evading network defences and security protocols.

Understanding the Tactic

The techniques adversaries use are not limited to the provided examples above, as there are more ways to get initial code execution. However, we will use these examples to understand this tactic and grasp how to hunt it.

The common intersection of the examples above is executing malicious commands through pre-existing tools inside the victim machine.

|   |   |
|---|---|
|**Execution Technique**|**Examples**|
|Command-line Tools|Using built-in commands through `powershell.exe` and `cmd.exe` to download and execute the staged payload.|
|Built-in System Tools|Using `certutil.exe` or `bitsadmin.exe` for downloading the remote payload and `rundll32.exe` to run it.|
|Scripting / Programming Tools|Using built-in functionalities of programming tools such as Python's `os.system()` or PHP's `exec()`.|

**Note: The scripting/programming tools do not always exist on the target machine. However, it can be pre-determined in some cases that the programming tool exists, such as knowing the backend application used by the vulnerable target web server.**

Hunting Execution

The Execution phase can manifest in several ways, and recognising these signs can be complex due to the many potential execution methods an adversary might employ. However, it all boils down to executing a malicious command.

Unusual process creation, network connections, file modifications, and many more traces can indicate malicious execution. Recognising these red flags requires an in-depth understanding of typical endpoint behaviour and a keen eye for spotting anomalies. In line with these, we will use the following scenarios to build our hunting methodology:

- Suspicious usage of command-line tools.
- Abuse of built-in system tools.
- Execution via programming/scripting tools.

Usage of Command-Line Tools 

Starting with this scenario, we will use the `winlogbeat-*` index and hunt for executions of built-in Windows command-line tools, such as PowerShell and Command Prompt, from employee workstations on July 3, 2023. Ensure all queries to the Kibana console are set to look for the right index and timeframe.

System Administrators typically use these command-line tools to configure workstations and servers. However, threat actors commonly abuse it to execute malicious commands and control the compromised host. Given this, we will hunt for behaviours that show numerous usage of command-line tools, accompanied by unusual command executions and network connections.

Using the Discover tab, we will focus on the following processes: powershell.exe and cmd.exe. By using the following KQL query, we will hunt process creations (Sysmon Event ID 1) generated by these two tools:

`host.name: WKSTN-* AND winlog.event_id: 1 AND process.name: (cmd.exe OR powershell.exe)`  

In addition, ensure that the following fields are added as columns to aid us in our investigation:

- winlog.computer_name
- user.name
- process.parent.command_line  
    
- process.command_line  
    

![Process creation events related to PowerShell and CMD.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/631c0880041b3ab9ec0da41d7796b623.png)  

_Click to enlarge the image_  

Out of the 104 hits, it can be observed that numerous commands are used that seem unusual. One example is the execution of cmd.exe by `C:\Windows\Temp\installer.exe`, as shown in its parent-child process relationship. It is more remarkable that the parent process binary is located from C:\Windows\Temp, a typical folder threat actors use to write malicious payloads.

To add on PowerShell analysis, an alternative way to hunt unusual PowerShell execution is through the events generated by PowerShell's Script Block Logging. We can use the following KQL syntax to list all events generated by it: `host.name: WKSTN-* AND winlog.event_id: 4104` 

Moreover, we can use the following fields as columns to aid in our analysis:

- winlog.computer_name
- winlog.user.name
- powershell.file.script_block_text

Once the results are out, you may observe that the Script Block Logging generated 44,934 events. We can reduce this by removing the noise generated by the events. In this case, remove the "Set-StrictMode" events by clicking the minus button in the image below. These events are continuously repeated and do not indicate immediate suspicious activity and by filtering this, we can focus on more significant events that may lead to a successful hunt.

Note that when reducing noise, ensure that these events are guaranteed to be benign, or else you will miss significant events that might indicate suspicious activity.

![Filtering noise to view more significant events generated by PowerShell.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/cef30beb16d98882921b030f944ac497.png)

_Click to enlarge the image_  

After applying the filters, you will see that the events have been reduced to 489 hits, which makes hunting suspicious events easier. By scrolling through the executed PowerShell scripts, it can be observed that **Invoke-Empire** (signature of Empire C2 agent) was used in WKSTN-1. Moreover, other unusual PowerShell scripts seem to be malicious. You may continue analysing these events and assess the impact of the commands executed through PowerShell.

![Suspicious execution via PowerShell.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/0ce3b95d0e5cad597a1f6176fd2f1a68.png)

_Click to enlarge the image_  

Aside from manually reviewing the events generated by PowerShell or Windows Command Prompt, known strings used in cmd.exe or powershell.exe can also be leveraged to determine unusual traffic. Some examples of PowerShell strings are provided below:

- invoke / invoke-expression / iex
- -enc / -encoded
- -noprofile / -nop
- bypass
- -c / -command
- -executionpolicy / -ep
- WebRequest
- Download

Note that once these strings are seen in the logs, it is still recommended to validate the events, as some of these strings might be used by legitimate processes or benign activity executed by System Administrators.

Built-in System Tools

For this scenario, we will still use the `winlogbeat-*` index and hunt for executions of built-in Windows binaries from employee workstations on July 3, 2023. Ensure all queries to the Kibana console are set to look for the right index and timeframe.

Aside from PowerShell and Command Prompt binaries, other built-in binaries are also abused by threat actors to execute malicious commands. Most of these binaries, known as Living Off The Land Binaries (LOLBAS), are documented on this [page](https://lolbas-project.github.io/). Using this resource, we will hunt usage of built-in binaries and investigate unusual commands executed and network connections initiated.

Using the Discover tab, we will hunt some built-in tools typically used by threat actors (Certutil, Mshta, and Regsvr32). By using the following KQL query, we will again hunt process creation (Sysmon Event ID 1) as well as network connection (Sysmon Event ID 3) events:

`host.name: WKSTN-* AND winlog.event_id: (1 OR 3) AND (process.name: (mshta.exe OR certutil.exe OR regsvr32.exe) OR process.parent.name: (mshta.exe OR certutil.exe OR regsvr32.exe))`

**Note: The KQL query also lists all child processes spawned by these LOLBAS, which is why the** `process.parent.name` **field is also used.** 

Moreover, we can use the following fields as columns to aid in our analysis:

- winlog.computer_name
- user.name
- process.parent.command_line
- process.name
- process.command_line
- destination.ip

![Result of the query used to hunt LOLBAS activity.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/3362c4f8f3a5ac6851c1b149daf71934.png)

_Click to enlarge the image_  

Based on the results, it can be observed that all three binaries were suspicious due to their usage. Let's elaborate further on each binary.

- Certutil was used to download a binary (installer.exe), which is then stored in C:\Windows\Temp. (Remember that this binary was also discovered from the previous command-line tools investigation.)
- Regsvr32 accessed a remote file (teams.sct), then spawned a suspicious encoded PowerShell command.
- Mshta spawned a suspicious encoded PowerShell command.

Following a threat hunter's mindset, the next step of this investigation is to identify the extent of these malicious activities by correlating the subsequent events generated after these LOLBAS were used. One example is getting the process ID of the child processes spawned by these LOLBAS and investigating them further. Moreover, the encoded PowerShell commands can be decoded and hunted to understand the attack better.  

Scripting and Programming Tools  

For our last scenario, we will continue using the `winlogbeat-*` index and hunt for suspicious usage of scripting/programming tools from employee workstations on July 3, 2023. Ensure all queries to the Kibana console are set to look for the right index and timeframe.

Scripting and programming tools are typically found in either workstations owned by software developers or servers requiring these packages to run applications. These tools are benign, but threat actors abuse their functionalities to execute malicious code. Given this, we will hunt for unusual events generated by programming tools like Python, PHP and NodeJS. 

Using the Discover tab, we will use the following KQL query to hunt process creation (Sysmon Event ID 1) and network connection (Sysmon Event ID 3) events:

`host.name: WKSTN-* AND winlog.event_id: (1 OR 3) AND (process.name: (*python* OR *php* OR *nodejs*) OR process.parent.name: (*python* OR *php* OR *nodejs*))`  

Moreover, we can use the following fields as columns to aid in our analysis:

- winlog.computer_name
- user.name
- process.parent.command_line
- process.name
- process.command_line
- destination.ip
- destination.port

![Events generated by processes related to scripting or prgramming tools.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/6c02f3410b791abad780a580f9dcb2c4.png)  

_Click to enlarge the image_  

Based on the results, it can be observed that Python was used to do the following:

- Spawn a child cmd.exe process.
- Initiate a network connection to 167[.]71[.]198[.]43:8080

Using these findings, we can extend our investigation further by getting the process ID of the cmd.exe process spawned by Python and using it in our new KQL query. We can do this by clicking the dropdown button on the log that indicates Python created a cmd.exe process.

![Process ID of the suspicious python process.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/2c4d7093787c257bbb4bea5ba88a42b0.png)  

_Click to enlarge the image_  

Using this process PID, we can search all processes spawned by this cmd.exe instance by using it as our `process.parent.pid`:

`host.name: WKSTN-* AND winlog.event_id: (1 OR 3) AND process.parent.pid: 1832`  

![Correlated events based on the discovered process ID of unusual python process.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/2593b99702322aa3a0a5566fa5d56d87.png)  

_Click to enlarge the image_  

Based on the results, it can be observed that the cmd.exe process, spawned by Python, generated child processes, indicating that the script `dev.py` could be a Python reverse shell script allowing attackers to execute remote commands via cmd.exe. 

Following a threat hunter's mindset, the next step of this investigation is to identify the extent of these malicious activities by correlating the subsequent events generated after the execution of the suspicious Python script. In addition, it is also good to understand how the script was written in the compromised machine by backtracking the events related to `dev.py`.

# Defense Evasion

Tactic: Defense Evasion

The [Defense Evasion Tactic (TA0005)](https://attack.mitre.org/tactics/TA0005/) comprises strategies that adversaries employ to avoid detection by network security systems during or following an infiltration. This is often achieved by disguising malicious activities as usual legitimate operations or manipulating known benign files or processes. Attackers utilise a range of methods to evade defences, including but not limited to the following:

- Disabling security software.
- Deleting attack footprints on logs.
- Deceiving analysts through masquerading, obfuscation, and encryption. 
- Executing known bypasses to security controls.

Moreover, these examples are typically combined with the execution tactic to achieve better results. This makes it possible for an attacker to run their malicious code while avoiding or minimising the chances of being detected by the target's security systems, making the attack more likely to succeed.

Understanding the Tactic

The techniques adversaries use are not limited to the provided examples above, as there are more ways to deceive and evade defences. However, we will use these examples to understand this tactic and grasp how to hunt it.

The common intersection of the examples above is bypassing detection mechanisms, whether from a software solution or the security team.

|   |   |
|---|---|
|**Evasion Technique**|**Examples**|
|Disabling security software|Disabling Windows Defender via the command line or reverting the updated detection signatures.|
|Deleting logs|Deleting all existing Windows Event Logs inside the compromised machine.|
|Deceiving analysts|Mimicking process names or spoofing parent process IDs.|
|Executing known bypasses|Using known vulnerabilities or modifying host configurations to bypass the controls.|

Hunting Defense Evasion  

As we continue our deep dive into the adversary's playbook, we focus on hunting Defense Evasion. As discussed above, this method encompasses various techniques that adversaries use to avoid detection by security measures during or following an attack.

Despite adversaries' attempts to evade detection, their activities inevitably leave traces in these logs, providing us with potential leads. With these, we will use the following scenarios to uncover the traces of this tactic:

- Disabling security software.
- Log deletion attempts.
- Executing shellcode through process injection.

Disabling Security Software

Starting with this scenario, we will use the `winlogbeat-*` index and hunt for attempts to disable security software, such as Windows Defender, from employee workstations on July 3, 2023. Ensure all queries to the Kibana console are set to look for the right index and timeframe.

Most organisations nowadays have improved their security defences, deploying numerous security software to prevent threat actors from successfully compromising their network. However, threat actors still have some tricks up their sleeves to bypass these controls and disable them to not limit their attack vectors in achieving their goals.

For this example, we will focus on known commands used to disable Windows Defender. By using the following KQL query, we will hunt events indicating an attempt to disable the running host antivirus:

`host.name: WKSTN-* AND (*DisableRealtimeMonitoring* OR *RemoveDefinitions*)`

The following strings in this query are tied up with the following commands to blind Windows Defender from detecting malicious activity.

- DisableRealtimeMonitoring - Commonly used with PowerShell's `Set-MPPreference` to disable its real-time monitoring.
- RemoveDefinitions - Commonly used with built-in `MpCmdRun.exe` to remove all existing signatures of Windows Defender.

Moreover, we can use the following fields as columns to aid in our analysis:

- winlog.computer_name
- user.name
- process.parent.command_line
- process.name
- process.command_line

![Events that may indicate a potentially suspicious attempt to disable security controls.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/3b429919f44e0d05a028d2d8f0494b66.png)  

_Click to enlarge the image_  

Based on the results, it can be seen that both indicators were seen from `WKSTN-1`, which indicates that a malicious actor has attempted to disable Windows Defender's detection capability. Moreover, both of the execution were attributed to malicious activities identified previously from the Execution task.

- Set-MpPreference was executed by the installer.exe binary, previously identified as malicious.

![Parent process of the unusual attempt to disable the real-time detection of Windows Defender.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/7b55f8667f9c8380f5740a73d1eac00f.png)

_Click to enlarge the image_  

- MpCmdRun.exe -RemoveDefinitions was executed by cmd.exe with PID 1832, correlating to the Command Prompt spawned by Python.

![Parent process of the unusual attempt to remove the signatures of Windows Defender.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/ab2f4b9401128d4514219435413908bb.png)  

_Click to enlarge the image_  

Following a threat hunter's mindset, the next step of this investigation is to identify the extent of these malicious activities by correlating the subsequent events generated after the execution of these commands. The attacker is expected to execute more malicious commands since the existing antivirus software from the compromised workstation was successfully disabled.  

Log Deletion Attempts

Following the second scenario, we will still use the `winlogbeat-*` index and hunt for log deletion attempts from employee workstations on July 3, 2023. Ensure all queries to the Kibana console are set to look for the right index and timeframe.

From the perspective of the Security Team, every event log generated by workstations and servers is highly significant. Without these, analysts won't have enough visibility to complete the puzzle of investigating suspicious events and developing alerts from them. Given this, there won't be any good reason to delete these important files unless threat actors do. 

The simplest way to detect the deletion of Windows Event Logs is via Event ID 1102. These events are always generated when a user attempts to delete Windows Logs, so we will use this in our KQL query to hunt for this activity.

`host.name: WKSTN-* AND winlog.event_id: 1102`  

![Event/s showing potential log deletion attempt.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/26861fe6321548ab27e331bceff2cf22.png)

_Click to enlarge the image_  

Based on the results, it can be seen that Windows Event Logs were cleared from `WKSTN-1`. Following a threat hunter's mindset, the next step of this investigation is to identify the log source that was removed and the command used to delete the logs.

To complete the investigation, use `View surrounding documents` to see the command used to clear the event logs. Note that you need to add `process.name` and `process.command_line` columns to aid in analysing the surrounding documents.

![View surrounding documents button to see subsequent events around the log deletion attempt.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/d3c00e23c222926cf23500c24b5918bc.png)

_Click to enlarge the image_  

Execution through Process Injection

For the last scenario, we will use the `winlogbeat-*` index and hunt for potential process injection from employee workstations on July 3, 2023. Ensure all queries to the Kibana console are set to look for the right index and timeframe.

Process injection is a prominent technique malware developers use to execute malicious shellcodes while evading security defences successfully. Given this, we will use Sysmon's capability to detect CreateRemoteThread and hunt for potential process injection.

Using the Discover tab, we will focus on Sysmon's Event ID 8 (CreateRemoteThread), which detects when a process creates a thread in another process. We will use the following KQL query to hunt this behaviour: `host.name: WKSTN-* AND winlog.event_id: 8`

Moreover, we can use the following fields as columns to aid in our analysis:

- winlog.computer_name
- process.executable  
    
- winlog.event_data.SourceUser  
    
- winlog.event_data.TargetImage

![Potential process injection event.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/77c25bbb863bb5d22963735b6ae2ec70.png)

_Click to enlarge the image_  

Based on the results, the entry of `C:\Users\clifford.miller\Downloads\chrome.exe` created a new thread on `explorer.exe`, which is a typical target process threat actors use for process injection techniques. In addition, most entries are executed by a SYSTEM account, except for the chrome.exe, which is being run by Clifford Miller's account. 

Following a threat hunter's mindset, the next step of this investigation is to identify the extent of these malicious activities by correlating the subsequent events generated after the potential process injection activity. Moreover, it is good to trace back how the malicious chrome.exe binary reached the compromised host.


# Persistence

Tactic: Persistence

The [Persistence Tactic (TA0003)](https://attack.mitre.org/tactics/TA0003/) describes adversaries' techniques to maintain access to a compromised network over an extended period, often covertly. This allows adversaries to retain control over their foothold even if the system restarts or the user logs out. This involved various use of methods, such as:

- Modification of registry keys to hijack the typical system/program startup.
- Installation of malicious scripts or software that automatically starts.
- Creation of additional high-privileged backdoor accounts.

Moreover, these examples are typically executed right after the initial successful execution. This post-execution deployment of persistence methods ensures the attacker maintains a consistent presence within the compromised network, potentially making the attack more difficult to detect and remove.

Understanding the Tactic

The techniques adversaries use are not limited to the provided examples above, as there are more ways to implant continued access. However, we will use these examples to understand this tactic and grasp how to hunt it.

The common intersection of the examples above is modifying the system configuration inside the victim machine and abusing the built-in functionalities to have continued access.

|   |   |
|---|---|
|**Persistence Technique**|**Examples**|
|Modification of registry keys|Using `reg.exe` to modify registry keys related to system boot-up, such as Run or RunOnce keys.|
|Installation of auto-start scripts|Creation of scheduled tasks (via `schtasks.exe`) to regularly update and execute the implanted malware.|
|Creation of additional accounts|Using `net.exe` to create a new user and add it to the local administrators' group.|

Hunting Persistence

The hunt for persistence involves detecting the system's subtle changes and activities. This may entail identifying unrecognized or unexpected scripts running at startup, spotting unusual scheduled tasks, or noticing irregularities in system registry keys. We will use the following scenarios to learn more about the traces left when threat actors implant persistence mechanisms.

- Scheduled Task creation.
- Registry key modification.

Scheduled Task Creation

Starting with this scenario, we will use the `winlogbeat-*` index and hunt for scheduled task creation attempts from employee workstations on July 3, 2023. Ensure all queries to the Kibana console are set to look for the right index and timeframe.

Scheduled tasks are commonly used to automate commands and scripts to execute based on schedules or triggers. However, threat actors abuse this functionality to automate their malicious commands from executing regularly. Given this, we will hunt for unusual scheduled task creations.

If Windows Advanced Audit Policy is properly configured, we can use Event ID 4698 (Scheduled Task Creation). Else, we can use the following keywords for hunting commands related to scheduled tasks: `schtasks and Register-ScheduledTask (PowerShell)`

With this, we can use the following KQL query to hunt:

`host.name: WKSTN-* AND (winlog.event_id: 4698 OR (*schtasks* OR *Register-ScheduledTask*))`

In addition, ensure that the following fields are added as columns to aid us in our investigation:

- winlog.computer_name  
    
- user.name
- process.command_line
- winlog.event_id
- winlog.event_data.TaskName  
    

**Note: We have used the winlog.event_id field as a column since the query result might give events with different event IDs.**

![Scheduled task creation events.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/f54feaacae03235fa8b201fd733bce2d.png)  

_Click to enlarge the image_  

Based on the results, it can be observed that some of the scheduled tasks (OneDrive Reporting/Standalone Task) seem to be benign. On a quick look, the unusual task created is named "Windows Update" and executes a PowerShell command scheduled every minute. Tracing back the previous investigations, www[.]oneedirve[.]xyz was already identified as suspicious, confirming the suspicion on this newly-created scheduled task.

Following a threat hunter's mindset, the next step of this investigation is to identify the events generated by the parent process of cmd.exe that executed the malicious scheduled task creation. With this, we can backtrack the events before the persistence was implanted.  

Registry Key Modification

For our last scenario, we will still use the `winlogbeat-*` index and hunt for unusual registry modifications indicating malicious persistence on July 3, 2023. Ensure all queries to the Kibana console are set to look for the right index and timeframe.

The Windows registry is a database of information the operating system uses for its settings and configurations. Threat actors are abusing these settings and configurations to either hijack the normal flow of the operating system or store staged payloads for subsequent use. Given that the operating system commonly uses it, events generated by monitoring registry modifications are overwhelming and differentiating benign activity from malicious ones might be tedious. An example of this can be seen by using the following KQL query: 

`host.name: WKSTN-* AND winlog.event_id: 13 AND winlog.channel: Microsoft-Windows-Sysmon/Operational`

![Registry modification events.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/28eb9be84eae54f82b6782841d7337fa.png)  

_Click to enlarge the image_  

As shown in the image above, the query generated 1481 results, which makes hunting a threat feel like finding a needle in a haystack.

To ease the way of hunting, we can focus on known registry keys abused by threat actors to reduce the results:

- Software\Microsoft\Windows\CurrentVersion\Explorer\Shell (User Shell Folders)
- Software\Microsoft\Windows\CurrentVersion\Run (RunOnce)

**Note: Threat actors target more registry keys, but we will only use these for our example scenario.**

With this information, we will use an improved version of our previous KQL query to achieve better results:

`host.name: WKSTN-* AND winlog.event_id: 13 AND winlog.channel: Microsoft-Windows-Sysmon/Operational AND registry.path: (*CurrentVersion\\Run* OR *CurrentVersion\\Explorer\\User* OR *CurrentVersion\\Explorer\\Shell*)`  

In addition, ensure that the following fields are added as columns to aid us in our investigation:

- winlog.computer_name
- user.name
- process.name
- registry.path
- winlog.event_data.Details  
    

![Registry modification events focused on Autoruns registry keys.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/4ac7d3fa1402bafe019e15c403bdcc34.png)  

_Click to enlarge the image_  

Based on the results, it can be observed that there is one entry that is highly suspicious due to the following values:

- Registry Path: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend\1` 
- Registry Data: `C:\Windows\Temp\installer.exe`

This entry indicates that the binary `C:\Windows\Temp\installer.exe` will be executed on the machine's startup, which is the suspicious binary identified previously.

An alternative way of hunting unusual registry modifications is through process filtering. By specifying what process modified the registry, we can find notable changes based on the process used to execute it. The KQL query below hunts for registry modifications using `reg.exe` or `powershell.exe`.

`host.name: WKSTN-* AND winlog.event_id: 13 AND winlog.channel: Microsoft-Windows-Sysmon/Operational AND process.name: (reg.exe OR powershell.exe)`

Using this query, the modifications made via `reg.exe` was shown immediately. 

![Alternative way of hunting attempts to modify the registry.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/cbb4d15a05e542a228b3cddbfbe0d21a.png)  

_Click to enlarge the image_  

Note that this query cannot cover registry modifications made by other binaries interacting directly with the registry since it only hunts for the usage of reg.exe or powershell.exe. However, suspicious binaries interacting with the registry can still be hunted by excluding all known good binaries from the query.

Following a threat hunter's mindset, the next step of this investigation is to identify the events generated by the parent process of cmd.exe that executed the malicious registry modification. With this, we can backtrack the events before the persistence was implanted. Moreover, it is also good to hunt subsequent activities after the persistence was planted to see the following actions made by the attacker.

# Command and Control

Tactic: Command and Control

The [Command and Control Tactic (TA0011)](https://attack.mitre.org/tactics/TA0011/) involves the methods by which an adversary communicates with the compromised systems within a target network. This is the stage at which an attacker usually directs or continuously issues remote commands to the compromised system to fulfil the attacker's objectives, such as further internal network compromise. Communication can occur via various channels, such as:

- Standard network protocols, such as DNS, ICMP, HTTP/s.
- Known cloud-based services.
- Encrypted custom HTTP/s server.

Moreover, these methods provide a lifeline between the attacker and the infiltrated network, enabling two-way communication for the attacker to send commands and receive data. The Command and Control stage is particularly critical as the attacker solidifies their control over the compromised systems, adjusting their actions based on the information obtained or according to their ultimate goal.

Understanding the Tactic

The techniques adversaries use are not limited to the provided examples above, as there are more ways to establish continuous communication with the compromised machine. However, we will use these examples to understand this tactic and grasp how to hunt it.

The common intersection of the examples above is using a communication channel that typically blends in with regular network traffic, making the hunt for malicious activities more challenging.

|   |   |
|---|---|
|**Command and Control Technique**|**Examples**|
|Standard network protocols|Using the DNS protocol as a communication channel via its subdomain.|
|Known cloud-based services|Passing traffic through known web applications such as Google Drive, Telegram, and Discord.|
|Encrypted custom HTTP/s server|Using a self-hosted server with a well-groomed domain passing encrypted traffic.|

In determining unusual network traffic, it is also essential to understand the purpose of the traffic based on its contents, frequency and direction. A good example would be:  

- Egress traffic may indicate suspicious file uploads or connections to a C2 server.
- Ingress traffic may indicate intrusion attempts from external sources.
- Cleartext traffic containing host commands may indicate an established connection to a C2 server.
- A high count of connections or bandwidth of encrypted traffic may indicate unusual activity.

Hunting Command and Control

The hunt for Command and Control involves uncovering these covert communication channels amidst regular network traffic. Adversaries use standard protocols to blend in with typical network traffic or use cloud storage services as unconventional command channels to avoid raising suspicion. In the following sections, we will delve deeper into strategies and techniques for hunting Command and Control activities, interpreting network events, and recognising anomalies through the following scenarios:

- Command and Control over DNS.
- Command and Control over third-party cloud applications.
- Command and Control over encrypted HTTP traffic.

Command and Control over DNS

Starting with this scenario, we will use the `packetbeat-*` index and hunt for potential C2 over DNS on July 3, 2023. In addition, we will use the `winlogbeat-*` index to correlate the DNS queries to identify the malicious process generating it. Ensure all queries to the Kibana console are set to look for the right index and timeframe.

C2 over DNS, or more accurately Command and Control over DNS, is a technique used by adversaries where DNS protocols are utilised to establish a Command and Control channel. In this technique, adversaries can disguise their C2 communications as typical DNS queries and responses, bypassing network security measures. Given this, we will hunt for unusual DNS query patterns based on the following:

- High count of unique subdomains 
- Unusual DNS requests based on query types (MX, CNAME, TXT)

To start hunting, use the Visualize Library again and create a visualisation table using Lens. Ensure that the table is configured with the following:

- Set the Table Index (packetbeat), Rows (dns.question.registered_domain and host.name), and Metrics (Unique Count of dns.question.subdomain).
- Use the KQL query to list all DNS queries and exclude all reverse DNS lookups:  
      
    `network.protocol: dns AND NOT dns.question.name: *arpa`   
    

![Lens table view of DNS requests generated by each domain.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/865a9751c4a18147548b8cff01ab6a9a.png)  

_Click to enlarge the image_  

Upon checking the results above, it can be observed that an unusual domain (`golge[.]xyz`) queried 2191 unique subdomains, which may indicate a potential C2 over DNS activity coming from `WKSTN-1`. To better understand the attack, we can continue the investigation using the Discover tab with a query focused on this domain and the potentially compromised host. Let's use the following KQL query in the Discover tab on `packetbeat-*` index: 

`network.protocol: dns AND NOT dns.question.name: *arpa AND dns.question.registered_domain: golge.xyz AND host.name: WKSTN-1`   

We can also add the `query` field as a column to see its values.

![Events focused on the domain that generated a large number of unique subdomains via the Discover console.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/8e39190bffa7de54fd56bc460a592b4a.png)  

_Click to enlarge the image_  

Based on the results, the workstation seems to be continuously querying on *[.]golge[.]xyz, using different query types (CNAME, TXT and MX) and using hexadecimal subdomains. In addition, it was also seen that the workstation sends the DNS requests directly to an unknown nameserver, bypassing the DNS servers configured in the workstation.

![Destination IP of the unusual DNS traffic.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/f603f27024a4c2851fc5f93fde63826f.png)  

_Click to enlarge the image_  

Now that we have enough information, we can correlate this activity on `winlogbeat-*` to identify the process executing the DNS requests using the following KQL query:

`host.name: WKSTN-1* AND destination.ip: 167.71.198.43 AND destination.port: 53`

In addition, ensure that the following fields are added as columns to aid us in our investigation:

- host.name
- user.name
- process.parent.command_line
- process.name
- process.command_line

**Note: Add the field columns first before executing the KQL query.**

![Process related to the unusual DNS traffic.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/802fcf147063697602bc7fad5ac2e5ae.png)

_Click to enlarge the image_  

Based on the results, it can be observed that all connections to 167[.]71[.]198[.]43:53 are generated by `nslookup.exe`. To continue the event correlation, let's use View surrounding documents to see the subsequent events related to this activity.

![Details of the processes related to the unusual DNS traffic.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/85da84331a98a93fc99a29c7fc8f606a.png)

_Click to enlarge the image_  

The surrounding documents have provided the command line arguments of the parent process executing `nslookup.exe`. Based on its values, the suspicion of C2 over DNS is confirmed.

Following a threat hunter's mindset, the next step of this investigation is to identify the events generated by the parent process of nslookup.exe that established C2 over DNS. This can backtrack the events before a successful C2 connection was established. Moreover, observe the subsequent commands executed by the parent process as remote commands are expected to be executed since a C2 connection was confirmed to be running. 

On a footnote, the packet size (in this Kibana setup, the network.bytes field) may also indicate an unusual DNS traffic. DNS queries are typically short, and as shown in the example above, the subdomain was used to handle a long hex string for the C2 connection. Given this, it is highly recommended also to utilise the request/response size in determining potential anomalies within a DNS traffic.

Command and Control over Cloud Apps  

In the following scenario, we will still use the `packetbeat-*` index and hunt for Command and Control over known Cloud Applications from employee workstations on July 3, 2023. In addition, we will use the `winlogbeat-*` index to correlate the network connections to identify the malicious process generating it. Ensure all queries to the Kibana console are set to look for the right index and timeframe.

In C2 over Cloud Applications, adversaries use known cloud applications to establish a Command and Control channel. In this technique, adversaries can disguise their C2 communications as a typical web connection to a known-good cloud application, bypassing network security measures. We will search for cloud applications indicating a potential C2 channel.

To start hunting, we will use the same visualisation table of C2 over DNS. However, we will remove the unique subdomain metric and sort the count in ascending order. With this setup, we can see cloud application domains that workstations do not commonly access.

![Lens table view of connections made to unusual cloud services.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/d36f34dcc5077e39c9ebc2f47408d5fe.png)  

_Click to enlarge the image_  

Upon seeing the results, discord.gg, a known cloud application, is being used by WKSTN-1. Threat actors are using this application to host their C2 traffic. We can use this as a lead to investigate its unusual usage. With this information, we can pivot to `winlogbeat-*` index to correlate the associated process and use the following KQL query: `host.name: WKSTN-1* AND *discord.gg*`

![Process related to the unusual connection to Discord.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/b645a11f38ee71500d8db738fd313287.png)  

_Click to enlarge the image_  

Based on the results, it can be seen that the connections going to Discord are initiated by **C:\Windows\Temp\installer.exe**. We can investigate further by hunting all processes spawned by this process using the following KQL query:

`host.name: WKSTN-1* AND winlog.event_id: 1 AND process.parent.executable: "C:\\Windows\\Temp\\installer.exe"`

![Child processes spawned by the unusual process related to Discord.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/54a2a40ceae8f7e0646bf0233c2ea8b6.png)  

_Click to enlarge the image_  

Upon seeing the results, it can be observed that `installer.exe` has executed multiple cmd.exe commands, confirming the suspicion of C2 over Discord. Following a threat hunter's mindset, the next step of this investigation is to identify all events generated by installer.exe that established C2 over Discord. 

Command and Control over Encrypted HTTP Traffic

For the last scenario, we will still the `packetbeat-*` index and hunt for Command and Control over Encrypted HTTP traffic from employee workstations on July 3, 2023. In addition, we will use the `winlogbeat-*` index to correlate the network connections to identify the malicious process generating it. Ensure all queries to the Kibana console are set to look for the right index and timeframe.

Compared to the first two C2 techniques, C2 over Encrypted HTTP traffic is just a typical command and control type. The main notable thing about this technique is that attackers use their own C2 domain, including custom traffic encryption over HTTP. Given this, we will hunt for unusual HTTP traffic based on the following:

- High count of HTTP traffic to distinctive domains
- High outbound HTTP bandwidth to unique domains

To start hunting, use the Visualize Library again and create a visualisation table using Lens. Ensure that the table is configured with the following:

- Set the Table Index (packetbeat), Rows (host.name, destination.domain, http.request.method), and Metrics (count).
- Use the KQL query to list all outbound HTTP requests:  
      
    `network.protocol: http AND network.direction: egress`    
    

![Lens table view of high count of HTTP requests generated by each workstation.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/2e5532368e2226e225401380bb69a597.png)  

_Click to enlarge the image_  

Based on the results, it is highly notable that HTTP connections to cdn[.]golge[.]xyz from both workstations are numerous. This may indicate that a continuous C2 connection has been running for an extended time. We can modify the Lens table and focus the query to cdn[.]golge[.]xyz using this KQL query to understand better: 

`host.name: WKSTN-* AND network.protocol: http AND network.direction: egress AND destination.domain: cdn.golge.xyz`

In addition, we can modify the rows and focus only on `host.name` and `query` fields.

![Improved view of the Lens table, focusing on the unusual outbound traffic.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/f1a1675f4d83698f52696047561fa1e9.png)  

_Click to enlarge the image_  

Based on the results, it can be observed that the volume of requests is GET requests to 3 .php endpoints. Moreover, it can be inferred that the malware used to establish the C2 server is identical since the endpoints accessed by both workstations are similar. Given all this network information, we can now pivot to `winlogbeat-*` index and correlate this network activity to associated processes.

Using the following KQL query provided us with some insights regarding the associated process: `host.name: WKSTN-* AND *cdn.golge.xyz*`

![View of all HTTP traffic focused on the unusual domain via the Discover console.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/8fb64e55f142870cc480d204f4a10998.png)  

_Click to enlarge the image_  

Based on the results, it can be inferred that the C2 connection to cdn[.]golge[.]xyz was established using a malicious PowerShell command. 

Following a threat hunter's mindset, the next step of this investigation is to identify the extent of these malicious activities by correlating the subsequent events generated after the C2 connection to cdn[.]golge[.]xyz was established. Moreover, it is also good to trace back how the attacker gained initial access in the first place before attempting to develop continuous C2 access.

# TLDR

To conclude the room, let's summarise the different hunting methodologies that we discussed throughout the room:

|   |   |
|---|---|
|Tactic|Hunting Methodology|
|Initial Access|- Seek patterns of numerous failed login attempts to external services, followed by a successful authentication.<br>- Monitor intrusion attempts on web applications and potential code execution on web servers.<br>- Look for unusual file downloads and temporary files created by Outlook clients.<br>- Correlate all subsequent events after the successful intrusion attempt.|
|Execution|- Identify excessive usage of cmd.exe and powershell.exe.<br>- Spot misused legitimate operating system binaries and scripts (LOLBAS) and correlate their subsequent execution.<br>- Look for potential abuse of installed programming tools.<br>- Utilise the parent-child relationships of processes to connect associated events.|
|Defence Evasion|- Look for attempts to disable security software.<br>- Keep an eye out for log deletion events.<br>- Look for process injection activities.<br>- Correlate all evasion activities to their parent process and find subsequent events if the evasion attempt succeeded.|
|Persistence|- Watch out for the creation of scheduled tasks.<br>- Look for suspicious registry modifications on known registries used for persistence.<br>- Correlate all persistence activities back to their parent process.|
|Command and Control|- Look for a high count of unique subdomains on a single domain.<br>- Spot unusual outgoing connections to cloud services/applications.<br>- Look for an unusual number of outbound connections to an unfamiliar domain.<br>- Correlate all unusual activity back to its associated process.|

In essence, the list below generalises the usual progression of an attacker's thought process to obtain a foothold:

1. Intrusion into external assets or through deceptive tactics like phishing.
2. Triggering the initial payload chains multiple ways to execute commands, including evasion of various security controls.
3. Implanting persistence on compromised assets.
4. Establishing a reliable channel for command and control.

Bear in mind; hunting can commence at any phase of the attack. The key lies in correlating events across the attack chain to form a complete picture of the threat actor's actions.

This room covered the early steps an attacker takes post-establishing a foothold. Threat actors may further explore once inside the network, moving laterally across different systems. If you found this room valuable, continue enhancing your threat-hunting knowledge by proceeding to [Threat Hunting: Pivoting](https://tryhackme.com/room/threathuntingpivoting).
