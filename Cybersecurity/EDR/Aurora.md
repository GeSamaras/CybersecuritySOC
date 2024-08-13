https://www.nextron-systems.com/aurora/

![Aurora Icon](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/9c0c806c4fe32fce3ba7f90a3f11d1b5.png)


The main functions of an EDR are:

- Monitor and collect activity data from endpoints that could indicate a threat.
- Analyse this data to identify threat patterns.
- Automatically respond to identified threats, remove or contain them, and notify security personnel.
- Forensics and analysis tools to research identified threats and search for suspicious activities.

The functions of an EDR can be broken down into the aggregation of data on an endpoint and how the data is analysed and used to detect threats.

**Endpoint Data Recording**

- Aggregating network communication, events, process executions, file activities, commands, user operations, etc.
- Telemetry data points.
- Storage of data on endpoints, in a server, or in a hybrid approach.

**Investigation of Data & Responding**

- Sweep (search) for indicators of Compromise to understand the impact of detections.
- Find the root cause of detection and remediate/prevent/investigate again.
- Hunt for indicators of Attack based on behaviour rules or threat intelligence. Automatic (detection) or manual.

## Components of EDR solutions

EDR vendors would classify their capabilities differently. However, the following are the common classifications:

- **Detection:** Fundamentally, EDR solutions are tasked with threat detection. For example, with file analysis, EDRs can flag suspicious files at the sight of any malicious behaviour. The detection process is also based on how good the threat intelligence sources are.
- **Response/ Containment:** EDRs provide response features that help investigate, detect, remediate and contain threats. The actions here include host segmentation, file deletion/cleanup and conducting investigations through sandboxing conditions. Advanced EDR solutions have the capability to trigger an automated response based on a set of preconfigured rules.
- **Integration:** EDRs extend endpoint visibility through the collection and aggregation of data. Therefore, in addressing endpoint security, EDR solutions need to work smoothly with existing security solutions in an organisation.
- **Insights:** Real-time analysis of events is becoming very common, providing a rapid evaluation and correlation of threat data. Through complex machine learning and artificial intelligence algorithms, EDR solutions can automate threat identification and perform behavioural analysis, mapping them to frameworks such as the MITRE ATT&CK.
- **Forensics:** In-depth investigation of past threats provides valuable information on the inner workings of exploits and how a breach was successful. With this, EDR solutions can outline threat timelines and identify lurking threats that go undetected.

# Events in Windows


Event Tracing for Windows (ETW) is a Windows OS logging feature that provides a mechanism to trace and log events raised by user-mode applications and kernel-mode drivers. ETW provides the capability for applications and drivers to write events. For cybersecurity defenders, this becomes a vital source of detection information.

ETW is made up of three distinct parts:

- **Controllers:** These applications are used to configure event tracing sessions. They also initiate the providers. An example of a Controller is `logman.exe.`
- **Providers:** These are the applications that produce event logs.
- **Consumers:** These applications subscribe and listen to events in real-time or from a file.

## Windows Event Viewer

Windows systems and applications provide event logs that would be useful for troubleshooting and understanding the activities being performed. These logs include system access notifications, security changes, operating system errors, hardware failures, and driver malfunctions. We shall briefly examine how event logs are presented via the Windows Event Viewer.

The event information is categorised under these types of levels:

- **Information:** Describes the successful operation of a driver, application or service. Basically, a service is calling home.
- **Warning:** Describes an event that may not be a present issue but can cause problems in the future.
- **Error:** Describes a significant problem with a service or application.
- **Success Audit:** Outlines that an audited security access operation was successful. For example, a user’s successful login to the system.
- **Failure Audit:** Outlines that an audited security access operation failed. For example, a failed access to a network drive by a user.

Even a properly functioning host will show various logs under these classes, and as a security analyst, you will be required to comb through the logs. This ensures you can keep tabs on a system’s operations and troubleshoot any problems.

### Using the Event Viewer

Windows Event Viewer is mainly found as an application on the system. We can find it simply by searching for “Event Viewer” on the Start menu.

Windows logs are placed under different categories, with three major ones used for system troubleshooting and investigations:

- **Application:** Records log events associated with system components such as drivers and interface components that run an app.
- **System:** Records events related to programs installed and running on the system.
- **Security:** Records events associated with security, such as logon attempts and resource access.

On the main dialogue screen, we can see that the log events are presented in a tabular format which shows the levels, date and time, source of the events, event id and task category.

![Windows Event Viewer Summary](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/f36601d831d8a5917e50526d217adcde.gif)

  

When we select an event, the event properties window displays information related to the event under the “General” tab. We can dig deeper via the “Details” tab.

![Windows Event General & Details views.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/d505c16313f5f461290148256f29c6c2.gif)

  

Note that we shall focus on the application logs for the remainder of the room as Aurora writes its events in this category.

## Aurora  

Aurora is a Windows endpoint agent that uses Sigma rules and IOCs to detect threat patterns on local event streams using ETW. When a true-positive rule matches, Aurora triggers “response actions” that will be displayed under the Windows Event Log Viewer.

It has been designed to be customisable based on the Sigma rule set and function as an on-premises tool, with no data leaving the network.

Aurora comes in as an enterprise and free community version called Aurora Lite. The table below summarises the key differences in service offered by the two versions.

|Aurora|Aurora Lite|
|---|---|
|Sigma-based event matching on ETW data|Sigma-based event matching on ETW data|
|An open-source rule set (1300+ rules)|An open-source rule set (1300+ rules)|
|Nextron’s Sigma rule set|No Nextron’s Sigma rule set|
|Open-source IOC set|Open-source IOC set|
|Nextron’s IOC set|No Nextron’s IOC set|
|Alert output channels: Eventlog, File, UDP/TCP|Alert output channels: Eventlog, File, UDP/TCP|
|Comfortable management with ASGARD|-|
|Additional detection modules|-|
|Unlimited number of response actions|-|
|Rule encryption|-|

Features source: [Nextron Systems - Aurora](https://www.nextron-systems.com/aurora/)

  

Aurora obtains data from different ETW channels and adds live information (for the commercial version) to enrich and recreate events similar to those generated by Sysmon. It does not create tons of logs; it only populates the viewer with events of triggered rules. Below, we can look at a comparison between Aurora and Sysmon.


Aurora is supported on Windows 7/ Windows Server 2012 or newer versions and must run using administrator privileges. It must also be excluded from any running antivirus or EDR solutions. This is to avoid the application being blocked from executing its services.

Look at how to install and configure Aurora correctly via the [User Manual](https://aurora-agent-manual.nextron-systems.com/en/latest/index.html).

## Aurora Presets

Aurora can be configured to use four different configuration formats that dictate how the solution would fetch events and raise alerts. The four preset formats are:

- **Standard:** This configuration covers events at a medium level of severity.
- **Reduced:** This configuration looks at events considered to be at a high minimum reporting level.
- **Minimal:** This configuration looks at events considered to be at a high minimum reporting level.
- **Intense:** This configuration looks at events considered to be at a low minimum reporting level.

|Affected Setting|Standard|Reduced|Minimal|Intense|
|---|---|---|---|---|
|Deactivated sources|Registry, Raw Disk Access, Kernel Handles, Create Remote Thread|Registry, Raw Disk Access, Process Access|Registry, Raw Disk Access, Kernel Handles, Create Remote Thread, Process Access, Image Loads|-|
|CPU Limit|35%|30%|20%|100%|
|Process Priority|Normal|Normal|Low|Normal|
|Minimum Reporting Level|Medium|High|High|Low|
|Deactivated Modules|-|LSASS Dump Detector|LSASS Dump Detector, BeaconHunter|-|

## Running Aurora

Aurora can be started directly via the command line, with the option of selecting the preferred configuration.

Aurora Launch with Minimal Config

```shell-session
C:\Program Files\Aurora-Agent>aurora-agent.exe -c agent-config-minimal.yml
```

For continuous running, the agent can also run as a service through the `--install` flag.

Aurora Launch as a Service

```shell-session
C:\Program Files\Aurora-Agent>aurora-agent.exe --install -c agent-config-minimal.yml
```


## Output Options

Aurora supports the following output options:

- **Windows Eventlog:** On an earlier task, we looked at Event Tracing for Windows. Aurora writes its events using ETW; the details can be viewed via the EventViewer. Click the “Details” tab to see all fields and values.

![Windows Event Viewer showing Aurora Agent alerts and details.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/171be6b47de229eb03e7c53c8c1d7e06.png)  

- **Log File:** A log file can be written using the `--logfile` flag, which will be automatically rotated once the specified log size has been attained (by default, this is 10MB). The log files would be found under the directory where Aurora is running from.

Aurora Log file output

```shell-session
C:\Program Files\Aurora-Agent>aurora-agent.exe --logfile aurora-minimal.log
```

With this command, the Aurora status will include `Stdout: enabled` under its configuration **Active Outputs** section.

- **UDP/TCP Targets:** Network targets direct Aurora events to an internal repository via UDP or TCP using the flags `--udp-target` and `--tcp-target`. These options require arguments in the form of **`host: port,`** such as **`internal.repo:8443.`**

  

## Aurora Responses  

Responses extend the Sigma services and can be used to set specific actions to be performed and respond when an event matches. These actions can help contain a threat actor or limit their damage to the system host. The intended use cases for the responses are **worm containment, ransomware containment, and the hard blocking of applications.**

Aurora supports two responses: **Predefined** and **Custom.**

### Predefined Responses

The following responses are available by default with the installation of Aurora:

- **Suspend:** Used to stop a specified process.
- **Kill:** Used to kill a specified process.
- **Dump:** Used to create a dump file found in the `dump-path` folder.

### Custom Responses

Custom responses are meant to call an internal program to execute a function based on a raised alert. The program has to be available from `PATH` and the answer would be a command-line query.

With these responses, a set of flags can be used to modify and relay different types of information. The flags have been summarised in the table below:

|Flag|Definition|
|---|---|
|Simulate|Used to test out rules, and responses that won't be triggered. A log will be created to indicate the type of response that would be triggered.|
|Recursive|It is used to specify that the response will affect descendent processes. It is usually `true` by default.|
|Low privilege only|Marked by the flag `lowprivonly.` The flag specifies that the response will be triggered if the target process does not run as `LOCAL SYSTEM` or at an elevated role.|
|Ancestor|The `ancestors` flag specifies that the response will affect a process’s ancestor, not itself. The key: value pair is indicated by integers to show the level of ancestors, e.g. one (1) is for parent process, 2 for grand-parent, and so on.|
|Process ID field|The `processidfield` flag specifies the field contains the process ID that shall be affected by the response.|


#### Response examples

Aurora Kill Parent Process Response

```shell-session
response:
    type: predefined
    action: kill
    processidfield: ParentProcessId
```

  

Aurora Suspend Response

```shell-session
response:
    type: predefined
    action: suspend

```

  

Aurora Copy image to backup folder Custom Response

```shell-session
response:
    type: custom
    action: cmd /c copy %Image% "%%ProgramData%%\Aurora\Image-%ProcessId%.bin"
```

  

## Aurora Event IDs

If you may have noticed through the screenshots and navigating through the VM, Aurora uses event IDs to log to the Windows Eventlog. The tables below list the IDs related to Sigma, internal and other notable modules used.

  

|Event ID|Description|Event ID|Description|
|---|---|---|---|
|1|A process creation Sigma rule matched.|100|A license file was found.||
|2|A set file creation time sigma rule matched.|101|Status message (from --report-stats)||
|3|A network connection sigma rule matched.|102|Aurora Agent started.||
|4|A sysmon status Sigma rule matched.|103|Aurora Agent is terminating.||
|5|A process termination Sigma rule matched.|104|The current license expired.||
|6|A driver-loaded Sigma rule matched.|105|No valid license file was found.||
|7|An image-loaded Sigma rule matched.|107|A process created a large number of events.||
|8|A create remote thread Sigma rule matched.|108|An internal panic occurred.||
|9|A raw disk access Sigma rule matched.|200|BeaconHunter|

## Function Tests

Once Aurora has been installed and configured, several function tests can be executed to check its various functionalities. Let’s look at a few Sigma matching and IOC matching examples.

- **Listing user account privileges:** Running a simple command `whoami /priv` to list the current user privileges will trigger a Sigma rule with a level **high** and create a `WARNING` level message on the Eventlog. This will be a process creation alert.

![Event Viewer screenshot showing Aurora detection of a whoami /priv command](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/1ce641aa45e7f2d7b0c4b5247f6b6f4e.png)  

- **Suspicious network communication:** Running a suspicious DNS beaconing request will result in a critical rule being triggered. Below is an example that matches a suspicious cobalt strike DNS beaconing.

![Event Viewer screenshot showing Aurora detection of a suspicious CobaltStrike DNS beaconing command](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/c246b3ff357d7ef13826831b4ba682b6.png)


# Detection

Since Aurora uses ETW to observe and monitor Windows system events, there are some sections where ETW events aren’t available or not easily usable. These areas cover Aurora's detection gaps, and we shall look at them in this task.

## Named Pipes

Named pipes are a one-way communication channel between processes that are subject to security checks in the memory. ETW has no provider to gather information about the creation or connection to named pipes. Observing named pipe events is through the Kernel Object Handle, which is noisy and can provide unnecessary information.

### Solution

- Using Aurora under “Intense” configurations.
- Complement Aurora configuration with Sysmon to capture the events.

## Registry Events

Registry events are generated on the ETW by creating keys or writing values, primarily via the `Microsoft-Windows-Kernel-Registry.` However, this information may not be directly usable as all registry handles must be tracked individually as keys are referenced by their handle. For value setting too,

### Solution

- Using Aurora under “Intense” configurations.
- Complement Aurora configuration with Sysmon to capture the events.

## ETW Disabled

Attackers have the ability to disable ETW events by patching the system calls that Windows would use to create the events from user space. Writing detection rules based on events that originate from the process and are caused by a provider that is not `Microsoft-Windows-Kernel` should be done with care.

### Solution

- Aurora’s full version uses the ETW Canary module to detect any manipulations of ETW.
- Using the flag `--report-stats` allows for reporting the agent’s status to your SIEM and will include stats of the observed, processed and dropped events that can indicate signs of manipulations.


