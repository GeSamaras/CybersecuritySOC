**Intrusion Detection System (IDS)**

IDS is a passive monitoring solution for detecting possible malicious activities/patterns, abnormal incidents, and policy violations. It is responsible for generating alerts for each suspicious event. 

There are two main types of IDS systems;

- Network Intrusion Detection System (NIDS) - NIDS monitors the traffic flow from various areas of the network. The aim is to investigate the traffic on the entire subnet. If a signature is identified, an alert is created.
- Host-based Intrusion Detection System (HIDS) - HIDS monitors the traffic flow from a single endpoint device. The aim is to investigate the traffic on a particular device. If a signature is identified, an alert is created.

  
Intrusion Prevention System (IPS)

IPS is an active protecting solution for preventing possible malicious activities/patterns, abnormal incidents, and policy violations. It is responsible for stopping/preventing/terminating the suspicious event as soon as the detection is performed.

 **There are four main types of IPS systems;**

- Network Intrusion Prevention System (NIPS) - NIPS monitors the traffic flow from various areas of the network. The aim is to protect the traffic on the entire subnet. If a signature is identified, the connection is terminated.
- Behaviour-based Intrusion Prevention System (Network Behaviour Analysis - NBA) - Behaviour-based systems monitor the traffic flow from various areas of the network. The aim is to protect the traffic on the entire subnet. If a signature is identified, **the connection is terminated.**
- Wireless Intrusion Prevention System (WIPS) - WIPS monitors the traffic flow from of wireless network. The aim is to protect the wireless traffic and stop possible attacks launched from there. If a signature is identified, the connection is terminated.
- Host-based Intrusion Prevention System (HIPS) - HIPS actively protects the traffic flow from a single endpoint device. The aim is to investigate the traffic on a particular device. If a signature is identified, **the connection is terminated.**

**Now let's talk about Snort. [Here is the rest of the official description](https://www.snort.org/) of the snort;**

_"__Snort can be deployed inline to stop these packets, as well. Snort has three primary uses: As a packet sniffer like tcpdump, as a packet logger — which is useful for network traffic debugging, or it can be used as a full-blown network intrusion prevention system. Snort can be downloaded and configured for personal and business use alike."_  

SNORT is an open-source, rule-based Network Intrusion Detection and Prevention System (NIDS/NIPS). It was developed and still maintained by Martin Roesch, open-source contributors, and the Cisco Talos team. 

Capabilities of Snort;  

- Live traffic analysis
- Attack and probe detection
- Packet logging
- Protocol analysis
- Real-time alerting
- Modules & plugins
- Pre-processors
- Cross-platform support! (Linux & Windows)

Snort has three main use models;  

- Sniffer Mode - Read IP packets and prompt them in the console application.
- Packet Logger Mode - Log all IP packets (inbound and outbound) that visit the network.
- NIDS (Network Intrusion Detection System)  and NIPS (Network Intrusion Prevention System) Modes - Log/drop the packets that are deemed as malicious according to the user-defined rules.

|                    |                                                                                                                                                               |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Parameter**      | **Description**                                                                                                                                               |
| **-V / --version** | This parameter provides information about your instance version.                                                                                              |
| **-c**             | Identifying the configuration file                                                                                                                            |
| **-T**             | Snort's self-test parameter, you can test your setup with this parameter.                                                                                     |
| -**q**             | Quiet mode prevents snort from displaying the default banner and initial information about your setup.                                                        |
|                    |                                                                                                                                                               |
| **-v**             | Verbose. Display the TCP/IP output in the console.                                                                                                            |
| **-d**             | Display the packet data (payload).                                                                                                                            |
| **-e**             | Display the link-layer (TCP/IP/UDP/ICMP) headers.                                                                                                             |
| -**X**             | Display the full packet details in HEX.                                                                                                                       |
| -**i**             | This parameter helps to define a specific network interface to listen/sniff. Once you have multiple interfaces, you can choose a specific interface to sniff. |
**Sniffing with parameter “-v”**

Start the Snort instance in **verbose mode (-v)**; `sudo snort -v`

Now run the traffic-generator script as sudo and start **ICMP/HTTP traffic**. Once the traffic is generated, snort will start showing the packets in verbosity mode as follows;

sniffing with -v
```
user@ubuntu$ sudo snort -v  
                               
Running in packet dump mode
```

`sudo snort -d`

Now run the traffic-generator script **as sudo** and start **ICMP/HTTP traffic**.
**dump (-d)** and **link-layer header grabbing (-e)** mode; `snort -d -e`



**Snort in Logger Mode**  

You can use Snort as a sniffer and log the sniffed packets via logger mode. You only need to use the packet logger mode parameters, and Snort does the rest to accomplish this.

Packet logger parameters are explained in the table below;

|   |   |
|---|---|
|**Parameter**|**Description**|
|-l|Logger mode, target **log and alert** output directory. Default output folder is **/var/log/snort**<br><br>The default action is to dump as tcpdump format in **/var/log/snort**|
|**-K ASCII**|Log packets in ASCII format.|
|-r|Reading option, read the dumped logs in Snort.|
|**-n**|Specify the number of packets that will process/read. Snort will stop after reading the specified number of packets.|

Running a network dummy test with 
```
sudo ./traffic-generator.sh
```
and another terminal to capture the network flow
```
## to log files
sudo snort -dev -l

## to read logs
sudo snort -r snort.log.filenumber
```


**Snort in IDS/IPS Mode**  

NIDS mode parameters are explained in the table below;

|   |   |
|---|---|
|**Parameter**|**Description**|
|-c|Defining the configuration file.|
|-T|Testing the configuration file.|
|**-N**|Disable logging.|
|**-D**|Background mode.|
|**-A**|Alert modes;  <br><br>**full:** Full alert mode, providing all possible information about the alert. This one also is the default mode; once you use -A and don't specify any mode, snort uses this mode.<br><br>**fast:**  Fast mode shows the alert message, timestamp, source and destination IP, along with port numbers.<br><br>console: Provides fast style alerts on the console screen.<br><br>**cmg:** CMG style, basic header details with payload in hex and text format.<br><br>**none:** Disabling alerting.|

PCAPs with Snort

Capabilities of Snort are not limited to sniffing, logging and detecting/preventing the threats. PCAP read/investigate mode helps you work with pcap files. Once you have a pcap file and process it with Snort, you will receive default traffic statistics with alerts depending on your ruleset.

|   |   |
|---|---|
|**Parameter**|**Description**|
|**-r / --pcap-single=**|Read a single pcap|
|**--pcap-list=""**|Read pcaps provided in command (space separated).|
|**--pcap-show**|Show pcap name on console during processing.|


**Snort Rules!**

|   |   |
|---|---|
|Action|There are several actions for rules. Make sure you understand the functionality and test it before creating rules for live systems. The most common actions are listed below.<br><br>- alert: Generate an alert and log the packet.<br>- log: Log the packet.<br>- drop: Block and log the packet.<br>- reject: Block the packet, log it and terminate the packet session.|
|Protocol|Protocol parameter identifies the type of the protocol that filtered for the rule.<br><br>Note that Snort2 supports only four protocols filters in the rules (IP, TCP, UDP and ICMP). However, you can detect the application flows using port numbers and options. For instance, if you want to detect FTP traffic, you cannot use the FTP keyword in the protocol field but filter the FTP traffic by investigating TCP traffic on port 21.|

There are three main rule options in Snort;  

- General Rule Options - Fundamental rule options for Snort. 
- Payload Rule Options - Rule options that help to investigate the payload data. These options are helpful to detect specific payload patterns.
- Non-Payload Rule Options - Rule options that focus on non-payload data. These options will help create specific patterns and identify network issues.
**General Rule Options**

|   |   |
|---|---|
|Msg|The message field is a basic prompt and quick identifier of the rule. Once the rule is triggered, the message filed will appear in the console or log. Usually, the message part is a one-liner that summarises the event.|
|Sid|Snort rule IDs (SID) come with a pre-defined scope, and each rule must have a SID in a proper format. There are three different scopes for SIDs shown below.<br><br>- <100: Reserved rules<br>- 100-999,999: Rules came with the build.<br>- >=1,000,000: Rules created by user.<br><br>Briefly, the rules we will create should have sid greater than 100.000.000. Another important point is; SIDs should not overlap, and each id must be unique.|
|Reference|Each rule can have additional information or reference to explain the purpose of the rule or threat pattern. That could be a Common Vulnerabilities and Exposures (CVE) id or external information. Having references for the rules will always help analysts during the alert and incident investigation.|
|Rev|Snort rules can be modified and updated for performance and efficiency issues. Rev option help analysts to have the revision information of each rule. Therefore, it will be easy to understand rule improvements. Each rule has its unique rev number, and there is no auto-backup feature on the rule history. Analysts should keep the rule history themselves. Rev option is only an indicator of how many times the rule had revisions.<br><br>alert icmp any any <> any any (msg: "ICMP Packet Found"; sid: 100001; reference:cve,CVE-XXXX; rev:1;)|