Wireshark, a tool used for creating and analyzing PCAPs (network packet capture files), is commonly used as one of the best packet analysis tools. In this room, we will look at the basics of installing Wireshark and using it to perform basic packet analysis and take a deep look at each common networking protocol.

![](https://assets.tryhackme.com/additional/wireshark101/1.png)
[Wireshark Documentation](https://www.wireshark.org/docs/).

# Collection Methods Overview

Some things to think about before going headfirst into attempting to collect and monitor live packet captures.

- Begin by starting with a sample capture to ensure that everything is correctly set up and you are successfully capturing traffic.
- Ensure that you have enough compute power to handle the number of packets based on the size of the network, this will obviously vary network by network.
- Ensure enough disk space to store all of the packet captures.

Once you meet all these criteria and have a collection method picked out you can begin to actively monitor and collect packets on a network.

  

Network Taps

Network taps are a physical implant in which you physically tap between a cable, these techniques are commonly used by Threat Hunting/DFIR teams and red teams in an engagement to sniff and capture packets.

There are two primary means of tapping a wire. The first is by using hardware to tap the wire and intercept the traffic as it comes across, an example of this would be a vampire tap as pictured below.

![](https://assets.tryhackme.com/additional/wireshark101/7.gif)  

  
Another option for planting a network tap would be an inline network tap, which you would plant between or 'inline' two network devices. The tap will replicate packets as they pass the tap. An example of this tap would be the very common Throwing Star LAN Tap

![](https://assets.tryhackme.com/additional/wireshark101/8.jpg)  


MAC Floods 

MAC Floods are a tactic commonly used by red teams as a way of actively sniffing packets. MAC Flooding is intended to stress the switch and fill the CAM table. Once the CAM table is filled the switch will no longer accept new MAC addresses and so in order to keep the network alive, the switch will send out packets to all ports of the switch.
_Note: This technique should be used with extreme caution and with explicit prior consent._

ARP Poisoning

ARP Poisoning is another technique used by red teams to actively sniff packets. By ARP Poisoning you can redirect the traffic from the host(s) to the machine you're monitoring from. This technique will not stress network equipment like MAC Flooding however should still be used with caution and only if other techniques like network taps are unavailable.
Combining these methods with your previous knowledge of capturing traffic from the previous task will allow you to proactively monitor and collect live packet captures from scratch.


# Filtering
Filtering Operators

Wireshark's filter syntax can be simple to understand making it easy to get a hold of quickly. To get the most out of these filters you need to have a basic understanding of boolean and logic operators.
Wireshark only has a few that you will need to be familiar with:
- and - operator: and / &&
- or - operator: or / ||
- equals - operator: eq / ==
- not equal - operator: ne / !=
- greater than - operator: gt /  >
- less than - operator: lt / < 

**Basic Filtering**

Filtering gives us a very large scope of what we can do with the packets, because of this there can be a lot of different filtering syntax options. We will only be covering the very basics in this room such as filtering by IP, protocol, etc. for more information on filtering check out the [Wireshark filtering documentation](https://wiki.wireshark.org/DisplayFilters).

There is a general syntax to the filter commands however they can be a little silly at times. The basic syntax of Wireshark filters is some kind of service or protocol like ip or tcp, followed by a dot then whatever is being filtered for example an address, MAC, SRC, protocol, etc.

Filtering by IP: The first filter we will look at is ip.addr, this filter will allow you to comb through the traffic and only see packets with a specific IP address contained in those packets, whether it be from the source or destination. 
Syntax: `ip.addr == <IP Address>
`
![](https://assets.tryhackme.com/additional/wireshark101/9.png)

Other useful filtering options: 
Syntax: `ip.src == <SRC IP Address> and ip.dst == <DST IP Address>`
Syntax: `tcp.port eq <Port #> or <Protocol Name>`


# Packet Dissection

  
![](https://assets.tryhackme.com/additional/wireshark101/12.png)



It is useful to note that most devices will identify themselves or Wireshark will identify it such as Intel_78, an example of suspicious traffic would be many requests from an unrecognized source. You need to enable a setting within Wireshark however to resolve physical addresses. To enable this feature, navigate to **View > Name Resolution > Ensure that Resolve Physical Addresses**  is checked.

Looking at the below screenshot we can see that a Cisco device is sending ARP Requests, meaning that we should be able to trust this device, however you should always stay on the side of caution when analyzing packets.

  

![](https://assets.tryhackme.com/additional/wireshark101/22.png)


# TCP 
TCP Overview

TCP or Transmission Control Protocol handles the delivery of packets including sequencing and errors. You should already have an understanding of how TCP works, if you need a refresher check out the [IETF TCP Documentation](https://tools.ietf.org/html/rfc793).

Below you can see a sample of a Nmap scan, scanning port 80 and 443. We can tell that the port is closed due to the RST, ACK packet in red.

![](https://assets.tryhackme.com/additional/wireshark101/25.png)  

  

When analyzing TCP packets, Wireshark can be very helpful and color code the packets in order of danger level. If you can't remember the color code go back to Task 3 and refresh on how Wireshark uses colors to match packets.  

TCP can give useful insight into a network when analyzing however it can also be hard to analyze due to the number of packets it sends. This is where you may need to use other tools like RSA NetWitness and NetworkMiner to filter out and further analyze the captures.

  

TCP Traffic Overview

A common thing that you will see when analyzing TCP packets is known as the TCP handshake, which you should already be familiar with. It includes a series of packets: syn, synack, ack; That allows devices to establish a connection.

  

![](https://assets.tryhackme.com/additional/wireshark101/26.png)  

  

Typically when this handshake is out of order or when it includes other packets like an RST packet, something suspicious or wrong is happening in the network. The Nmap scan in the section above is a perfect example of this.

  

TCP Packet Analysis

For analyzing TCP packets we will not go into the details of each individual detail of the packets; however, look at a few of the behaviors and structures that the packets have. 

Below we see packet details for an SYN packet. The main thing that we want to look for when looking at a TCP packet is the sequence number and acknowledgment number.

  

![](https://assets.tryhackme.com/additional/wireshark101/27.png)  

  

The acknowledgement number is not set in a TCP **SYN** packet because the client is not acknowledging any data from the server. It is typically **0** in the initial **SYN** packet.

Within Wireshark, we can also see the original sequence number by navigating to edit > preferences > protocols > TCP > relative sequence numbers (uncheck boxes).

  

![](https://assets.tryhackme.com/additional/wireshark101/28.png)  

  

![](https://assets.tryhackme.com/additional/wireshark101/29.png)  

  

Typically TCP packets need to be looked at as a whole to tell a story rather than one by one at the details.