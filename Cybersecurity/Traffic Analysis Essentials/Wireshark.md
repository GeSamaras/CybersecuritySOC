Wireshark is one of the most potent traffic analyser tools available in the wild. There are multiple purposes for its use:  

- Detecting and troubleshooting network problems, such as network load failure points and congestion.
- Detecting security anomalies, such as rogue hosts, abnormal port usage, and suspicious traffic.
- Investigating and learning protocol details, such as response codes and payload data.

![Wireshark - GUI](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/0a96b128d88d49f28e4b537b63bcfd3b.png)


**Packet Details**

You can click on a packet in the packet list pane to open its details (double-click will open details in a new window). Packets consist of 5 to 7 layers based on the OSI model. We will go over all of them in an HTTP packet from a sample capture. The picture below shows viewing packet number 27.

![Wireshark - packet details](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/a09f80da3fd63b32e47842d93ead7db5.png)

Each time you click a detail, it will highlight the corresponding part in the packet bytes pane.

![Wireshark - packet bytes](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/31f45c8e0e06d874d3826752839270df.png)  

Let's have a closer view of the details pane.  

![Wireshark - packet details](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/22a21052465fedc91fc4d1ec3beb6bd6.png)


Go to Packet

Packet numbers do not only help to count the total number of packets or make it easier to find/investigate specific packets. This feature not only navigates between packets up and down; it also provides in-frame packet tracking and finds the next packet in the particular part of the conversation. You can use the **"Go"** menu and toolbar to view specific packets.  

![Wireshark - go to packet](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/cdb1e1d12c63fc831c7d94db634bbe0d.png)


Packet Dissection of packet 38 (ctrl + g):

![[Pasted image 20240605152858.png]]


Expert Info  

Wireshark also detects specific states of protocols to help analysts easily spot possible anomalies and problems. Note that these are only suggestions, and there is always a chance of having false positives/negatives. Expert info can provide a group of categories in three different severities. Details are shown in the table below.

|   |   |   |
|---|---|---|
|**Severity**|**Colour**|**Info**|
|**Chat**|**Blue**|Information on usual workflow.|
|**Note**|**Cyan**|Notable events like application error codes.|
|**Warn**|**Yellow**|Warnings like unusual error codes or problem statements.|
|**Error**|**Red**|Problems like malformed packets.|

Frequently encountered information groups are listed in the table below. You can refer to Wireshark's official documentation for more information on the expert information entries.

|              |                           |                |                             |
| ------------ | ------------------------- | -------------- | --------------------------- |
| **Group**    | **Info**                  | **Group**      | **Info**                    |
| **Checksum** | Checksum errors.          | **Deprecated** | Deprecated protocol usage.  |
| **Comment**  | Packet comment detection. | **Malformed**  | Malformed packet detection. |

**Conversations**

Conversation represents traffic between two specific endpoints. This option provides the list of the conversations in five base formats; ethernet, IPv4, IPv6, TCP and UDP. Thus analysts can identify all conversations and contact endpoints for the event of interest. You can use the "Statistic --> Conversations" menu to view this info.

![Wireshark - conversations](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/c54cc40b174b5ee7540b063ae3b075ed.png)


**Capture Filter Syntax  

These filters use byte offsets hex values and masks with boolean operators, and it is not easy to understand/predict the filter's purpose at first glance. The base syntax is explained below:  

- Scope: host, net, port and portrange.
- Direction: src, dst, src or dst, src and dst,
- Protocol: ether, wlan, ip, ip6, arp, rarp, tcp and udp.
- Sample filter to capture port 80 traffic: `tcp port 80`  
    

You can read more on capture filter syntax from [here](https://www.wireshark.org/docs/man-pages/pcap-filter.html) and [here](https://gitlab.com/wireshark/wireshark/-/wikis/CaptureFilters#useful-filters). A quick reference is available under the **"Capture --> Capture Filters"** menu.

![Wireshark - capture filters](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/50a3e8a1cce46524f6de3ea14efd99e2.png)




**Packet Filter Toolbar

The filter toolbar is where you create and apply your display filters. It is a smart toolbar that helps you create valid display filters with ease. Before starting to filter packets, here are a few tips:  

- Packet filters are defined in lowercase.
- Packet filters have an autocomplete feature to break down protocol details, and each detail is represented by a "dot".
- Packet filters have a three-colour representation explained below.

|            |                                                                                                                |
| ---------- | -------------------------------------------------------------------------------------------------------------- |
| **Green**  | Valid filter                                                                                                   |
| **Red**    | Invalid filter                                                                                                 |
| **Yellow** | Warning filter. This filter works, but it is unreliable, and it is suggested to change it with a valid filter. |

![Wireshark - filter colours](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/98be05db82a2b7a2fd449c2155512f87.png)  

Filter toolbar features are shown below.

![Wireshark - toolbar features](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/b929ceb69199b99071fa95ce11d8ca44.png)




