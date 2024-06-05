[BRIM](https://www.brimdata.io/) is an open-source desktop application that processes pcap files and logs files. Its primary focus is providing search and analytics. In this room, you will learn how to use Brim, process pcap files and investigate log files to find the needle in the haystack! 

![Brim - interactive material](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/a5a19cd102e7e30a0ffa65bf6389d919.png)



![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/ff4d1d9dead9acca747fc48cc2f43ec2.png)

**What is Brim?**

Brim is an open-source desktop application that processes pcap files and logs files, with a primary focus on providing search and analytics. It uses the Zeek log processing format. It also supports Zeek signatures and Suricata Rules for detection.

It can handle two types of data as an input;

- Packet Capture Files: Pcap files created with tcpdump, tshark and Wireshark like applications.
- Log Files: Structured log files like Zeek logs.

Brim is built on open-source platforms:

- **Zeek:** Log generating engine.
- **Zed Language:** Log querying language that allows performing keywoırd searches with filters and pipelines.
- **ZNG Data Format:** Data storage format that supports saving data streams.
- **Electron and React:** Cross-platform UI.


**Why Brim?**

Ever had to investigate a big pcap file? Pcap files bigger than one gigabyte are cumbersome for Wireshark. Processing big pcaps with tcpdump and Zeek is efficient but requires time and effort. Brim reduces the time and effort spent processing pcap files and investigating the log files by providing a simple and powerful GUI application.

|   |   |   |   |
|---|---|---|---|
||Brim|Wireshark|Zeek|
|Purpose|Pcap processing; event/stream and log investigation.|Traffic sniffing. Pcap processing; packet and stream investigation.|Pcap processing; event/stream and log investigation.|
|GUI|✔|✔|✖|
|Sniffing|✖|✔|✔|
|Pcap processing|✔|✔|✔|
|Log processing|✔|✖|✔|
|Packet decoding|✖|✔|✔|
|Filtering|✔|✔|✔|
|Scripting|✖|✖|✔|
|Signature Support|✔|✖|✔|
|Statistics|✔|✔|✔|
|File Extraction|✖|✔|✔|
|Handling  pcaps over 1GB|Medium performance|Low performance|Good performance|
|Ease of Management|4/5|4/5|3/5|

Pools and Log Details  

Pools represent the imported files. Once you load a pcap, Brim processes the file and creates Zeek logs, correlates them, and displays all available findings in a timeline, as shown in the image below.   

![Brim - pools and log details](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/e429e9a957eef2c68ed6f7a84d004fd6.png)