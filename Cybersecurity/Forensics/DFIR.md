## The need for DFIR

DFIR helps security professionals in various ways, some of which are summarized below:

- Finding evidence of attacker activity in the network and sifting false alarms from actual incidents.
- Robustly removing the attacker,  so their foothold from the network no longer remains.
- Identifying the extent and timeframe of a breach. This helps in communicating with relevant stakeholders.
- Finding the loopholes that led to the breach. What needs to be changed to avoid the breach in the future?
- Understanding attacker behavior to pre-emptively block further intrusion attempts by the attacker.
- Sharing information about the attacker with the community.

- **Digital Forensics:** These professionals are experts in identifying forensic artifacts or evidence of human activity in digital devices. 
- **Incident Response:** Incident responders are experts in cybersecurity and leverage forensic information to identify the activity of interest from a security perspective.

The security industry has built various exciting tools to help with the DFIR process. These tools help save valuable time and enhance the capabilities of security professionals. Let's learn about some of these tools here. You can check out the rooms for these tools on TryHackMe to learn more about them.

  

## Eric Zimmerman's tools:![](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/1a89eb9ecd42f493fcdf7d105b41dba7.jpg)

Eric Zimmerman is a security researcher who has written a few tools to help perform forensic analysis on the Windows platform. These tools help the registry, file system, timeline, and many other analyses. To learn more about these tools, you can check out the [Windows Forensics 1](https://tryhackme.com/room/windowsforensics1) and [Windows Forensics 2](https://tryhackme.com/room/windowsforensics2) rooms, where these tools are discussed concerning the different artifacts found in the Windows Operating System.

  

## KAPE:![](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/0c82470617c7ebdbfcf956ee9d9547cf.png)

Kroll Artifact Parser and Extractor (KAPE) is another beneficial tool by Eric Zimmerman. This tool automates the collection and parsing of forensic artifacts and can help create a timeline of events. You can check out the [KAPE room](https://tryhackme.com/room/kape) to learn more about KAPE.

  

## Autopsy:![](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/ea383ef541cfaf0cbbc40a64af0f47ba.jpg)

Autopsy is an open-source forensics platform that helps analyze data from digital media like mobile devices, hard drives, and removable drives. Various plugins for autopsy speed up the forensic process and extract and present valuable information from the raw data sources. TryHackMe's [Autopsy room](https://tryhackme.com/room/btautopsye0) can help if you want to learn more about it.

  

## Volatility:![](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/c25405634d4fda8271d8df63a252d16a.jpg)

Volatility is a tool that helps perform memory analysis for memory captures from both Windows and Linux Operating Systems. It is a powerful tool that can help extract valuable information from the memory of a machine under investigation. You can learn more about Volatility in the [Volatility room](https://tryhackme.com/room/volatility).

  

## Redline:![](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/622d38cddd96ddcc98b8002da9920eec.jpg)

Redline is an incident response tool developed and freely distributed by FireEye. This tool can gather forensic data from a system and help with collected forensic information. You can learn more about Redline in the [Redline room](https://tryhackme.com/room/btredlinejoxr3d).

  

## Velociraptor:![](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/fca62b1d63bfcd0e11557606e451c412.png)

Velociraptor is an advanced endpoint-monitoring, forensics, and response platform. It is open-source but very powerful. TryHackMe has created a [Velociraptor room](https://tryhackme.com/room/velociraptorhp) for you to learn more about it.

  

While all these tools are helpful while performing DFIR, it is essential to understand the process followed to achieve our goals. The next task will focus on the Incident Response process and how we can leverage Digital Forensics in that process.


1. **Preparation**: Before an incident happens, preparation needs to be done so that everyone is ready in case of an incident. Preparation includes having the required people, processes, and technology to prevent and respond to incidents.
2. **Identification**: An incident is identified through some indicators in the identification phase. These indicators are then analyzed for False Positives, documented, and communicated to the relevant stakeholders.
3. **Containment**: In this phase, the incident is contained, and efforts are made to limit its effects. There can be short-term and long-term fixes for containing the threat based on forensic analysis of the incident that will be a part of this phase.
4. **Eradication**: Next, the threat is eradicated from the network. It has to be ensured that a proper forensic analysis is performed and the threat is effectively contained before eradication. For example, if the entry point of the threat actor into the network is not plugged, the threat will not be effectively eradicated, and the actor can gain a foothold again.
5. **Recovery**: Once the threat is removed from the network, the services that had been disrupted are brought back as they were before the incident happened.
6. **Lessons Learned**: Finally, a review of the incident is performed, the incident is documented, and steps are taken based on the findings from the incident to make sure that the team is better prepared for the next time an incident occurs.

