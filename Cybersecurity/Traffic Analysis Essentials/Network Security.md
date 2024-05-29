|                                          |                                                                                                                                                                                                                       |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Firewall Protection  <br>**            | Controls incoming and outgoing network traffic with predetermined security rules. Designed to block suspicious/malicious traffic and application-layer threats while allowing legitimate and expected traffic.        |
| Network Access Control (NAC)             | Controls the devices' suitability before access to the network. Designed to verify device specifications and conditions are compliant with the predetermined profile before connecting to the network.                |
| **Identity and Access Management (IAM)** | Controls and manages the asset identities and user access to data systems and resources over the network.                                                                                                             |
| **Load Balancing**                       | Controls the resource usage to distribute (based on metrics) tasks over a set of resources and improve overall data processing flow.                                                                                  |
| **Network Segmentation  <br>**           | Creates and controls network ranges and segmentation to isolate the users' access levels, group assets with common functionalities, and improve the protection of sensitive/internal devices/data in a safer network. |
| **Virtual Private Networks (VPN)  <br>** | Creates and controls encrypted communication between devices (typically for secure remote access) over the network (including communications over the internet).                                                      |
| **Zero Trust Model**                     | Suggests configuring and implementing the access and permissions at a minimum level (providing access required to fulfil the assigned role). The mindset is focused on: "Never trust, always verify".                 |


|   |   |
|---|---|
|**Intrusion Detection and Prevention (IDS/IPS)  <br>**|Inspects the traffic and creates alerts (IDS) or resets the connection (IPS) when detecting an anomaly/threat.|
|**Data Loss Prevention (DLP)  <br>**|Inspects the traffic (performs content inspection and contextual analysis of the data on the wire) and blocks the extraction of sensitive data.|
|**Endpoint Protection  <br>**|Protecting all kinds of endpoints and appliances that connect to the network by using a multi-layered approach like encryption, antivirus, antimalware, DLP, and IDS/IPS.|
|**Cloud Security**|Protecting cloud/online-based systems resources from threats and data leakage by applying suitable countermeasures like VPN and data encryption.|
|**Security Information and Event Management (SIEM)  <br>**|Technology that helps threat detection, compliance, and security incident management, through available data (logs and traffic statistics) by using event and context analysis to identify anomalies, threats, and vulnerabilities.|
|**Security Orchestration Automation and Response (SOAR)  <br>**|Technology that helps coordinate and automates tasks between various people, tools, and data within a single platform to identify anomalies, threats, and vulnerabilities. It also supports vulnerability management, incident response, and security operations.|
|**Network Traffic Analysis & Network Detection and Response**|Inspecting network traffic or traffic capture to identify anomalies and threats.|


|   |   |   |   |   |
|---|---|---|---|---|
|Deployment|Configuration|Management|Monitoring|Maintenance|
|- Device and software installation<br>- Initial configuration<br>- Automation|- Feature configuration<br>- Initial network access configuration|- Security policy implementation<br>- NAT and VPN implementation<br>- Threat mitigation|- System monitoring<br>- User activity monitoring<br>- Threat monitoring  <br>    <br>- Log and traffic sample capturing|- Upgrades<br>- Security updates<br>- Rule adjustments<br>- Licence management<br>- Configuration updates|


|   |   |
|---|---|
|**Network Penetration Testing**|Assessing network security by simulating external/internal attacker techniques to breach the network.|
|**Vulnerability Assessment**|Assessing network security by discovering and analysing vulnerabilities in the environment.|
|**Incident Response  <br>**|An organised approach to addressing and managing a security breach. It contains a set of actions to identify, contain, and eliminate incidents.|
|**Behavioural Analysis**|An organised approach to addressing system and user behaviours, creating baselines and traffic profiles for specific patterns to detect anomalies, threats, vulnerabilities, and attacks.|

Network Analysis
- Network Sniffing and Packet Analysis (Covered in [**Wireshark room**](https://tryhackme.com/room/wiresharkthebasics))
- Network Monitoring (Covered in [**Zeek room**](https://tryhackme.com/room/zeekbro))
- Intrusion Detection and Prevention (Covered in [**Snort room**](https://tryhackme.com/room/snort))  
    
- Network Forensics (Covered in [**NetworkMiner room**](https://tryhackme.com/room/networkminer))
- Threat Hunting (Covered in [**Brim room**](https://tryhackme.com/room/brim))

|                                                                                                                                                                                                                                                                                                                                              |                                                                                                                                                                                                                                                                                                                                        |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Flow Analysis**                                                                                                                                                                                                                                                                                                                            | **Packet Analysis**                                                                                                                                                                                                                                                                                                                    |
| Collecting data/evidence from the networking devices. This type of analysis aims to provide statistical results through the data summary without applying in-depth packet-level investigation.<br><br>- **Advantage:** Easy to collect and analyse.<br>- **Challenge:** Doesn't provide full packet details to get the root cause of a case. | Collecting all available network data. Applying in-depth packet-level investigation (often called Deep Packet Inspection (DPI) ) to detect and block anomalous and malicious packets.<br><br>- **Advantage:** Provides full packet details to get the root cause of a case.<br>- **Challenge:** Requires time and skillset to analyse. |