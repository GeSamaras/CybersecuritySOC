Subnetting is the process of dividing a single IP network into multiple smaller, logical sub-networks (subnets). It improves network performance and security by segmenting a larger network into smaller, more manageable sections. Subnetting is commonly used in both IPv4 and IPv6 networking. Here, we'll focus on IPv4 subnetting.

### Key Concepts

1. **IP Address**: A unique identifier for a device on a network, consisting of 32 bits, typically written in decimal format as four octets (e.g., 192.168.1.1).

2. **Subnet Mask**: A 32-bit number used to divide an IP address into network and host parts. It is also written in decimal format (e.g., 255.255.255.0).

3. **Network Address**: The starting point of a subnet, representing the network segment (e.g., 192.168.1.0).

4. **Broadcast Address**: The ending point of a subnet, used to communicate with all devices within the subnet (e.g., 192.168.1.255).

5. **CIDR Notation**: A shorthand for the subnet mask, where the number of bits in the network portion of the address is specified (e.g., /24).

### Example of Subnetting

#### Example Scenario

Let's say we have a network with the IP address 192.168.1.0/24. This means:
- IP Range: 192.168.1.0 to 192.168.1.255
- Total Addresses: 256 (2^8)
- Subnet Mask: 255.255.255.0

Now, we want to divide this network into smaller subnets.

#### Step-by-Step Subnetting

1. **Determine the Number of Subnets**: Suppose we need 4 subnets.
2. **Calculate New Subnet Mask**: 
   - Original subnet mask is /24 (255.255.255.0).
   - We need 4 subnets, which requires 2 additional bits (since 2^2 = 4).
   - New subnet mask: /26 (255.255.255.192).

3. **Calculate Subnet Details**:
   - Each subnet will have 2^(32-26) = 64 addresses.
   - Subnet address increments by 64.

4. **Identify Subnet Ranges**:
   - **Subnet 1**: 192.168.1.0 to 192.168.1.63
     - Network Address: 192.168.1.0
     - First Usable Address: 192.168.1.1
     - Last Usable Address: 192.168.1.62
     - Broadcast Address: 192.168.1.63
   - **Subnet 2**: 192.168.1.64 to 192.168.1.127
     - Network Address: 192.168.1.64
     - First Usable Address: 192.168.1.65
     - Last Usable Address: 192.168.1.126
     - Broadcast Address: 192.168.1.127
   - **Subnet 3**: 192.168.1.128 to 192.168.1.191
     - Network Address: 192.168.1.128
     - First Usable Address: 192.168.1.129
     - Last Usable Address: 192.168.1.190
     - Broadcast Address: 192.168.1.191
   - **Subnet 4**: 192.168.1.192 to 192.168.1.255
     - Network Address: 192.168.1.192
     - First Usable Address: 192.168.1.193
     - Last Usable Address: 192.168.1.254
     - Broadcast Address: 192.168.1.255

### Resources for Further Learning

1. **Cisco Networking Academy**: Offers extensive courses on subnetting and other networking topics.
   - [Cisco NetAcad](https://www.netacad.com/)

2. **Subnetting Practice Sites**:
   - [Subnetting Practice](http://www.subnettingpractice.com/)

3. **Books**:
   - "TCP/IP Illustrated, Volume 1: The Protocols" by W. Richard Stevens.
   - "CCNA Routing and Switching Study Guide" by Todd Lammle.

4. **Online Tutorials and Articles**:
   - [Cisco Subnetting Tutorial](https://www.cisco.com/c/en/us/support/docs/ip/routing-information-protocol-rip/13788-3.html)
   - [Khan Academy Networking Course](https://www.khanacademy.org/computing/computer-science/informationtheory)

By mastering subnetting, network administrators can efficiently manage IP address allocations and improve network performance and security.