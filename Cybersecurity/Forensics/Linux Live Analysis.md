# Osquery Overview

To recap, osquery is a powerful endpoint monitoring tool developed by Facebook. It enables us to query the operating system as a relational database. We can use SQL-like queries to extract detailed and comprehensive information about the system, which can be helpful in the investigation. To learn more about osquery and how to write simple to complex queries to get answers from the OS, explore the [Osquery Basics](https://tryhackme.com/room/osqueryf8) room.

**Command: osqueryi**

This command will open the interactive session in osquery for us to interact. Run the `.help` command to display the help options.

osquery

```shell-session
root@cybertees:~# osqueryi
Using a virtual database. Need help, type '.help'
osquery> .help
Welcome to the osquery shell. Please explore your OS!
You are connected to a transient 'in-memory' virtual database.

.all [TABLE]     Select all from a table
.bail ON|OFF     Stop after hitting an error
.connect PATH    Connect to an osquery extension socket
.disconnect      Disconnect from a connected extension socket
.echo ON|OFF     Turn command echo on or off
.exit            Exit this program
.features        List osquery's features and their statuses
.headers ON|OFF  Turn display of headers on or off
.help            Show this message
.mode MODE       Set output mode where MODE is one of:
                   csv      Comma-separated values
                   column   Left-aligned columns see .width
                   line     One value per line
                   list     Values delimited by .separator string
                   pretty   Pretty printed SQL results (default)
.nullvalue STR   Use STRING in place of NULL values
.print STR...    Print literal STRING
.quit            Exit this program
.schema [TABLE]  Show the CREATE statements
.separator STR   Change separator used by output mode
.socket          Show the local osquery extensions socket path
.show            Show the current values for various settings
.summary         Alias for the show meta command
.tables [TABLE]  List names of tables
.types [SQL]     Show result of getQueryColumns for the given query
.width [NUM1]+   Set column widths for "column" mode
.timer ON|OFF      Turn the CPU timer measurement on or off
```

**Note:** Ensure you are running osquery using root.**  
  
Osquery Table Schemas  
**

﻿We can look at the [osquery website](https://osquery.io/schema/5.12.1/) and view table schemas, as shown below:  

![Shows Osquery table Schema on Official website](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1719236531944)

  
On the website, we can explore the tables supported, the columns in each table, etc.

Let's use osquery's search queries to get information from the host.

**Users Account  
**

The following search query uses the `users` table to retrieve information about the user accounts created on the host.**  
  
Search Query:** `Select username, uid, description from users;`  

Osquery

```shell-session
osquery> Select username, uid, description from users;
+----------------------+-------+------------------------------------+
| username             | uid   | description                        |
+----------------------+-------+------------------------------------+
| root                 | 0     | root                               |
| daemon               | 1     | daemon                             |
| bin                  | 2     | bin                                |
| sys                  | 3     | sys                                |
| mail                 | 8     | mail                               |
| news                 | 9     | news                               |
| uucp                 | 10    | uucp                               |
| proxy                | 13    | proxy                              |
+----------------------+-------+------------------------------------+
```

  
This query retrieves information about users currently logged into the system. The columns include:

- **uid**: User ID.
- **username**: Username.
- **tty**: Terminal type.
- **pid**: Process ID of the user's login shell.
- **type**: Type of login (user, login, remote).
- **host**: Hostname or IP address of the remote host.
- **time**: Login time.

**Process Information**

Use the following query to get the information about the running processes.  
**Query:** `Select pid, name, parent,path from processes;`  

  

Osquery

```shell-session
osquery> Select pid, name, parent,path from processes LIMIT 10;
+-----+----------------+--------+--------------------------+
| pid | name           | parent | path                     |
+-----+----------------+--------+--------------------------+
| 1   | systemd        | 0      | /usr/lib/systemd/systemd |
| 10  | mm_percpu_wq   | 2      |                          |
| 100 | xenwatch       | 2      |                          |
| 101 | nvme-wq        | 2      |                          |
| 102 | nvme-reset-wq  | 2      |                          |
| 103 | nvme-delete-wq | 2      |                          |
| 104 | scsi_eh_0      | 2      |                          |
| 105 | scsi_tmf_0     | 2      |                          |
| 106 | scsi_eh_1      | 2      |                          |
| 107 | scsi_tmf_1     | 2      |                          |
+-----+----------------+--------+--------------------------+
```

  
We can use the output to examine the running processes and their path and hunt down any odd processes from the list. We will get back to this in the later tasks.  

To recap how to create simple to complex queries by joining two tables, check out the [Osquery Basics](https://tryhackme.com/room/osqueryf8) Room.

The first important step in the investigation is to obtain as much detailed information as possible about the infected machine. This would give a clear understanding of what the system looks like and what its state is.

Finding system information from memory is crucial for understanding. Let’s start our investigation by gathering information about the system we are investigating.

# System Profiling

System profiling is a key step in any forensics investigation, which is used to identify and locate important information about the system, which includes gathering information like:

- System Configuration
- Logged in Users
- Installed Application
- Hardware Configuration

We will use Linux built-in commands to extract information about the system, as shown below. Make sure to switch to root by using the command `sudo su`.  

**Basic System Information**

**Explanation:** Use the following command to extract basic information about the system, as shown below. This command output provides comprehensive details about the system, including its kernel version, architecture, hostname, and the date and time when the kernel was compiled.  

**Command:** `uname -a`

System Profiling

```shell-session
root@cybertees:~# uname -a
Linux cybertees 5.15.0-1063-aws #69~20.04.1-Ubuntu SMP Fri May 10 19:20:12 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
```

  
This command output provides comprehensive details about the system, including its kernel version, architecture, hostname, and the date and time when the kernel was compiled. Let's break down the information we retrieved from this command:

- **`Linux`**: The operating system name.
- **`cybertees`**: This value shows the system hostname.
- **`5.15.0-1063-aws`**: The kernel version.
- **`#69~20.04.1-Ubuntu`**: The specific build number and Ubuntu version.
- **`SMP`**: Indicates that the kernel is an SMP (Symmetric Multi-Processing) kernel, which means it supports multiple CPUs.
- **`Fri May 10 19:20:12 UTC 2024`**: The date and time when the kernel was compiled.
- **`x86_64`**: These values indicate the architecture of the processor/kernel and hardware platform.
- **`GNU/Linux`**: Indicates that the system is a GNU/Linux system.

**Hostname**  

**Explanation:** The `hostnamectl` command in Linux is used to query and change the system hostname and related settings. When we run this command, it displays detailed information about the system's hostname and other related details, as shown below:  

The following command provides details about the hostname and related settings.

**Command**: `hostnamectl`

System Profiling

```shell-session
root@cybertees:~# hostnamectl
   Static hostname: cybertees
         Icon name: computer-vm
           Chassis: vm
        Machine ID: dc7c8ac5c09a4bbfaf3d09d399f10d96
           Boot ID: df686577b96042718d7c73c08bf6f7e7
    Virtualization: xen
  Operating System: Ubuntu 20.04.6 LTS
            Kernel: Linux 5.15.0-1063-aws
      Architecture: x86-64
```

Let's break down the information we retrieved from this command:

- **Static hostname**: This is the permanent hostname assigned to the system. It's set in `/etc/hostname` and remains consistent across reboots.
- **Icon name**: This is a standardized name that represents the type of computer, often used in desktop environments to show appropriate icons.
- **Chassis**: This indicates the chassis type of the machine. In this case, it is `vm`, meaning a virtual machine.
- **Machine ID**: This is a unique identifier for the machine, typically stored in `/etc/machine-id`.
- **Boot ID**: This is a unique identifier for the current boot session, which changes every time the system is rebooted.
- **Virtualization**: This indicates the virtualization technology in use. In this case, `xen` is used, which is a hypervisor providing virtualization.
- **Operating System**: This provides information about the OS, which is `Ubuntu 20.04.6 LTS`  
    

**uptime**  

**Explanation:** This `uptime` command gives you a quick snapshot of your system's current status, including the time, how long it's been running, how many users are logged in, and how busy the system is. An example is shown below:  

**Command**: **`uptime`**

System Profiling

```shell-session
root@cybertees:~# uptime
 19:28:46 up 9 days, 12:27,  0 users,  load average: 0.00, 0.00, 0.00
```

**  
Hardware Information**  

**Explanation:** The `lscpu` command in Linux displays detailed information about the CPU architecture.

**Command:** **`lscpu`**

System Profiling

```shell-session
root@cybertees:~# lscpu
Architecture:                       cybertees
CPU op-mode(s):                     32-bit, 64-bit
Byte Order:                         Little Endian
Address sizes:                      46 bits physical, 48 bits virtual
CPU(s):                             2
On-line CPU(s) list:                0,1
Thread(s) per core:                 1
Core(s) per socket:                 2
Socket(s):                          1
NUMA node(s):                       1
Vendor ID:                          GenuineIntel
CPU family:                         6
Model:                              63
Model name:                         Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz
Stepping:                           2
CPU MHz:                            2400.133
BogoMIPS:                           4800.03
Hypervisor vendor:                  Xen
Virtualization type:                full
L1d cache:                          64 KiB
L1i cache:                          64 KiB
L2 cache:                           512 KiB
L3 cache:                           30 MiB
NUMA node0 CPU(s):                  0,1
Vulnerability Gather data sampling: Not affected
Vulnerability Itlb multihit:        KVM: Mitigation: VMX unsupported
Vulnerability L1tf:                 Mitigation; PTE Inversion
Vulnerability Mds:                  Vulnerable: Clear CPU buffers attempted, no 
                                    microcode; SMT Host state unknown
Vulnerability Meltdown:             Mitigation; PTI
Vulnerability Mmio stale data:      Vulnerable: Clear CPU buffers attempted, no 
                                    microcode; SMT Host state unknown
Vulnerability Retbleed:             Not affected
Vulnerability Spec rstack overflow: Not affected
Vulnerability Spec store bypass:    Vulnerable
Vulnerability Spectre v1:           Mitigation; usercopy/swapgs barriers and __u
                                    ser pointer sanitization
Vulnerability Spectre v2:           Mitigation; Retpolines; STIBP disabled; RSB 
                                    filling; PBRSB-eIBRS Not affected; BHI Retpo
                                    line
Vulnerability Srbds:                Not affected
Vulnerability Tsx async abort:      Not affected
Flags:                              fpu vme de pse tsc msr pae mce cx8 apic sep 
                                    mtrr pge mca cmov pat pse36 clflush mmx fxsr
```

  

Some of the key information that could be important for us is explained below:

- **Architecture**: It shows the CPU architecture (e.g., `x86_64` for 64-bit processors).
- **CPU op-mode(s)**: This field shows the CPU modes supported (e.g., 32-bit and 64-bit).
- **CPU(s)**: The number of CPUs/cores available.
- **Model name**: This value shows the full name of the CPU.
- **Virtualization**: Whether the CPU supports virtualization

**Disk Free  
**

**Explanation:** This command reports the amount of disk space used and available on the system.

**Command:** `df -h`

System Profiling

```shell-session
root@cybertees:/home/ubuntu# df -h
Filesystem      Size  Used Avail Use% Mounted on
/dev/root        59G  7.2G   51G  13% /
devtmpfs        2.0G     0  2.0G   0% /dev
tmpfs           2.0G     0  2.0G   0% /dev/shm
tmpfs           391M  1.2M  390M   1% /run
tmpfs           5.0M     0  5.0M   0% /run/lock
tmpfs           2.0G     0  2.0G   0% /sys/fs/cgroup
/dev/loop1       25M   25M     0 100% /snap/amazon-ssm-agent/7628
/dev/loop3       56M   56M     0 100% /snap/core18/2812
/dev/loop7       56M   56M     0 100% /snap/core18/2823
/dev/loop5       64M   64M     0 100% /snap/core20/2318
/dev/loop4       64M   64M     0 100% /snap/core20/2105
/dev/loop6       68M   68M     0 100% /snap/lxd/22526
/dev/loop8      104M  104M     0 100% /snap/core/16928
/dev/loop9       92M   92M     0 100% /snap/lxd/24061
tmpfs           391M     0  391M   0% /run/user/1000
tmpfs           391M  8.0K  391M   1% /run/user/114
/dev/loop10      26M   26M     0 100% /snap/amazon-ssm-agent/7993
/dev/loop0      105M  105M     0 100% /snap/core/17200
```

  
The df command is crucial for monitoring disk usage. It helps you see how much space is used and how much is available, which is essential for managing storage resources.**  
  
List of Block Devices**  

**Explanation:** This `lsblk` command provides information about block devices, such as disks and partitions. The information includes their sizes, mount points, and other relevant details.  
   
**Command:** **`lsblk`**

System Profiling

```shell-session
root@cybertees:~# lsblk
NAME    MAJ:MIN RM   SIZE RO TYPE MOUNTPOINT
loop0     7:0    0  24.9M  1 loop /snap/amazon-ssm-agent/7628
loop1     7:1    0  25.2M  1 loop /snap/amazon-ssm-agent/7993
loop2     7:2    0     4K  1 loop /snap/bare/5
loop3     7:3    0 105.4M  1 loop /snap/core/16574
loop4     7:4    0   104M  1 loop /snap/core/16928
loop5     7:5    0  55.7M  1 loop /snap/core18/2812
loop6     7:6    0  55.7M  1 loop /snap/core18/2823
loop7     7:7    0    64M  1 loop /snap/core20/2318
loop8     7:8    0  74.2M  1 loop /snap/core22/1380
loop9     7:9    0 505.1M  1 loop /snap/gnome-42-2204/176
loop10    7:10   0    64M  1 loop /snap/core20/2264
loop11    7:11   0   7.4M  1 loop /snap/gedit/684
loop12    7:12   0  91.7M  1 loop /snap/gtk-common-themes/1535
loop13    7:13   0  67.9M  1 loop /snap/lxd/22526
loop14    7:14   0  91.9M  1 loop /snap/lxd/24061
xvda    202:0    0    60G  0 disk 
└─xvda1 202:1    0    60G  0 part /
```

  

**Free Storage**

**Command:**  **`free`**

**Explanation:** The `free -h` command in Linux is used to display memory usage information in a human-readable format.

System Profiling

```shell-session
root@cybertees:~# free -h
              total        used        free      shared  buff/cache   available
Mem:          3.8Gi       667Mi       2.2Gi        31Mi       957Mi       2.9Gi
Swap:            0B          0B          0B
```

  
It provides a quick snapshot of how your system's memory resources are being utilized.

**  
Debian Package Manager Packages**  

Like many Linux distributions, Debian uses package management systems to handle software installation, updates, and removals. The two main package management tools used in Debian and its variants are `dpkg` and `apt`.  

**1- dpkg**

**Command**:  **`dpkg -l`**

**Explanation:** `dpkg` is the lower-level package management tool used directly by the system to install, remove, and provide information about .deb packages. Let's use the following command to list down the installed packages.  
  

![Shows a list of installed packages](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1719953593024.png)  
  
This command can also help identify a package that seems odd and suspicious in the server context. We will return to this in a later task.  

**2 - apt**  

`apt` command handles dependencies, automatically downloads and installs packages from repositories, and resolves conflicts. We can use the following command to list down all the packages installed through apt.

APTInstalled packages

```shell-session
root@cybertees:/home/ubuntu# apt list --installed | head -n 30

WARNING: apt does not have a stable CLI interface. Use with caution in scripts.

Listing...
a11y-profile-manager-indicator/focal,now 0.1.11-0ubuntu4 amd64 [installed,automatic]
accountsservice-ubuntu-schemas/focal,now 0.0.7+17.10.20170922-0ubuntu1 all [installed,automatic]
accountsservice/focal-updates,focal-security,now 0.6.55-0ubuntu12~20.04.7 amd64 [installed,automatic]
acl/focal,now 2.2.53-6 amd64 [installed,automatic]
acpi-support/focal,now 0.143 amd64 [installed,automatic]
acpid/focal,now 1:2.0.32-1ubuntu1 amd64 [installed]
adduser/focal,now 3.118ubuntu2 all [installed,automatic]
adwaita-icon-theme/focal-updates,now 3.36.1-2ubuntu0.20.04.2 all [installed,automatic]
alsa-base/focal,now 1.0.25+dfsg-0ubuntu5 all [installed,automatic]
alsa-topology-conf/focal,now 1.2.2-1 all [installed,automatic]
alsa-ucm-conf/focal-updates,now 1.2.2-1ubuntu0.13 all [installed,automatic]
alsa-utils/focal-updates,now 1.2.2-1ubuntu2.1 amd64 [installed,automatic]
amd64-microcode/focal-updates,focal-security,now 3.20191218.1ubuntu1.2 amd64 [installed,automatic]
----------------------------------------------------------
```

The above command lists the top 30 packages installed on the system. These commands can also help identify a package that seems odd and suspicious in the server context. This is something that will come back to in a later task.  
  
Network Profiling

Explanation:  `ifconfig` or `ip a` displays the configuration details of all network interfaces on the system, including IP addresses, MAC addresses, network masks, and interface status. The following commands can be used to extract information about the network interface, connection configurations etc.  

Command:  **`ip a`** or **`ifconfig`**

Installed Packages

```shell-session
root@cybertees:/home/ubuntu# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc mq state UP group default qlen 1000
    link/ether 02:2d:b5:ef:de:b7 brd ff:ff:ff:ff:ff:ff
    inet 10.10.1.246/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2650sec preferred_lft 2650sec
    inet6 fe80::2d:b5ff:feef:deb7/64 scope link 
       valid_lft forever preferred_lft forever
```

  

**Command:**  **`ip r`** or **`route`**

**Explanation:** Displays routing table.

APTInstalled packages

```shell-session
root@cybertees:# route
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         ip-10-10-0-1.eu 0.0.0.0         UG    100    0        0 eth0
10.10.0.0       0.0.0.0         255.255.0.0     U     0      0        0 eth0
ip-10-10-0-1.eu 0.0.0.0         255.255.255.255 UH    100    0        0 eth0
```

**Command:**  **`ss`** or **`netstat`**

**Explanation:** Shows socket statistics and active connections.

![Shows active Network Connections](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1716999176190)  

Explore these commands and extract information about the system.

From a forensics point of view, finding out what process is running on the suspected host and narrowing it down to identify the odd-looking process is crucial. It helps understand what's happening in the system.  

In the previous [Linux Process Analysis](https://tryhackme.com/r/room/linuxprocessanalysis) room, we already covered various command-line tools for displaying and examining the running processes on the Linux host. Let's recap some commonly used built-in tools.

|Command|Explanation|
|---|---|
|`ps`|It provides a snapshot of the current processes. This is useful for an overview of all running processes, and various options allow you to display more detailed information.|
|`top`|Offers a dynamic, real-time view of running processes. It monitors system performance and resource usage, showing which processes consume the most CPU and memory.|
|`htop`|This command is similar to `top` but with an improved interface and additional features. It allows for easier process management and includes color coding for better readability.|
|`pstree`|It displays processes in a tree format, showing the parent-child relationships between processes. This helps us understand how processes are related and organized.|
|`pidof`|It is used to find a running program's process ID (PID) by name. This is useful when you know the process's name and need its PID for further investigation or action.|
|`pgrep`|This tool searches for processes based on name and other attributes. It is useful for filtering and finding specific processes.|
|`lsof`|This tool lists open files and the processes that opened them. This can help identify which processes use specific files, sockets, or network connections.|
|`netstat`|It provides network-related information, including active connections and listening ports. This is useful for identifying potentially malicious network activity by processes.|
|`strace`|Traces system calls and signals. This is advanced but very powerful for debugging and understanding exactly what a process is doing at a low level.|
|`vmstat`|Reports on virtual memory statistics. It's good for getting an overview of system performance, including process scheduling and resource usage.|

The above commands can provide detailed information about the process and help us identify suspicious processes.

# Hunting for Suspicious Process  

Let's now utilize the [processes](https://osquery.io/schema/5.12.1/#processes) table in osquery to investigate the processes and find suspicious ones. This table has various columns that we can include in the search query.  

**List Running Processes**

First, use the following command to list down all the running processes.

**Search Query:** `SELECT pid, name, path, state FROM processes;`  

**Explanation:** This command will display the list of the processes running on the host.  

Osquery: Reviewing Processes

```shell-session
osquery> SELECT pid, name, path, state FROM processes;
+------+----------------------+----------------------------------+-------+
| pid  | name                 | path                             | state |
+------+----------------------+----------------------------------+-------+
| 1    | systemd              |                                  | S     |
| 10   | mm_percpu_wq         |                                  | I     |
| 100  | xenwatch             |                                  | S     |
| 101  | nvme-wq              |                                  | I     |
| 102  | nvme-reset-wq        |                                  | I     |
| 1024 | gvfsd                | /usr/libexec/gvfsd               | S     |
| 103  | nvme-delete-wq       |                                  | I     |
| 1034 | gvfsd-fuse           | /usr/libexec/gvfsd-fuse          | S     |
| 104  | scsi_eh_0            |                                  | S     |
| 1047 | at-spi-bus-laun      | /usr/libexec/at-spi-bus-launcher | S     |
| 105  | scsi_tmf_0           |                                  | I     |
| 1053 | dbus-daemon          | /usr/bin/dbus-daemon             | S     |
| 106  | scsi_eh_1            |                                  | S     |
| 107  | scsi_tmf_1           |                                  | I     |
| 109  | vfio-irqfd-clea      |                                  | I     |
| 11   | rcu_tasks_rude_      |                                  | S     |
| 110  | mld                  |                                  | I     |
| 111  | ipv6_addrconf        |                                  | I     |
| 112  | kworker/1:1H-kblockd |                                  | I     |
| 1151 | dconf-service        | /usr/libexec/dconf-service       | S     |
+------+----------------------+----------------------------------+-------+
```

  
The command retrieves a list of all currently running processes on the system and provides the following details for each process:

- **pid**: The unique process ID
- **name**: The name of the executable
- **path**: The full filesystem path to the executable
- **state**: The current state of the process (Idle / Sleep, etc.)

Processes Running From the tmp Directory

It's very common for an intruder to run malicious programs from the tmp directories to avoid detection. Let's update the query to see if any process is being executed from the tmp directory.

**Query:** `SELECT pid, name, path FROM processes WHERE path LIKE '/tmp/%' OR path LIKE '/var/tmp/%';`

**Explanation:** This command will narrow down the result and only show the processes running from the /tmp/ or /var/tmp/ directory.

Processes from tmp directory  

```shell-session
osquery> SELECT pid, name, path FROM processes WHERE path LIKE '/tmp/%' OR path LIKE '/var/tmp/%';
+-----+----------------+-------------------------+
| pid | name           | path                    |
+-----+----------------+-------------------------+
| 556 | REDACTED       | /var/tmp/REDACTED       |
| 923 | .REDACTED      | /var/tmp/.REDACTED      |
+-----+----------------+-------------------------+
```

  
Two processes were initiated from the tmp directories, indicating the host is infected.

Hunting for Fileless Malware / Process

Adversaries tend to remove the binary from the disk after executing it to avoid leaving footprints on it. Rootkits and other stealth malware often use hidden processes to avoid detection.**  
  
Search Query:** `SELECT pid, name, path, cmdline, start_time FROM processes WHERE on_disk = 0;`

**Explanation:** This command will list the processes executing on the host but not on the disk. This could also indicate a potential fileless malware.  

Fileless Process  

```shell-session
osquery> SELECT pid, name, path, cmdline, start_time FROM processes WHERE on_disk = 0;
+-----+----------------+-------------------------+-------------------------+------------+
| pid | name           | path                    | cmdline                 | start_time |
+-----+----------------+-------------------------+-------------------------+------------+
| 923 | .REDACTED      | /var/tmp/.REDACTED      | /var/tmp/.REDACTED      | 1720565809 |
+-----+----------------+-------------------------+-------------------------+------------+
```

  
It is important to note that not every process without a presence on disk can be indicated as suspicious. We have to investigate them further to determine. In the above query, the column `on_disk` can have two values: `1` indicates it is on the disk, and `0` indicates the process is not on the disk.

A fileless malware can have the following characteristics that we can observe:

- **No Disk Footprint:** It does not leave files on the disk, making it harder to detect using traditional file-based antivirus and security solutions.
- **Memory-Resident:** Operates entirely in the system's memory.
- **Persistence:** You might use scheduled tasks or other means to achieve persistence without placing files on the disk.

Orphan Processes

Normally, every process in Linux has a parent process. This parent-child relationship forms a process tree that can be viewed by the tool `pstree`. Intruders can create a process that becomes an orphan. It can indicate suspicious intentions, as creating an orphan process can be a useful tool for attackers to hide their activities, maintain persistence, and evade detection.

The following query will look into the running processes and list the ones with the parent process missing.  
  
**Search Query:** `SELECT pid, name, parent, path FROM processes WHERE parent NOT IN (SELECT pid from processes);`

**Explanation:** This command will list the processes without parent processes and thus deemed orphan.  

Orphan Process  

```shell-session
osquery> SELECT pid, name, parent, path FROM processes WHERE parent NOT IN (SELECT pid from processes);
+-----+----------+--------+--------------------------+
| pid | name     | parent | path                     |
+-----+----------+--------+--------------------------+
| 1   | systemd  | 0      | /usr/lib/systemd/systemd |
| 2   | kthreadd | 0      |                          |
+-----+----------+--------+--------------------------+
```

  
This command shows that two processes are running without a parent process. The output shows legitimate processes, which can also be the case.  

Finding Processes Launched from User Directories

  
In the context of a server, if the process is running from the user directory, that process could be marked for further investigation. One of the main reasons is that, typically, system processes run from the standard system directories. Let's use the following search query to look for the processes running from the user directories.  

  

**Search Query:** `SELECT pid, name, path, cmdline, start_time FROM processes WHERE path LIKE '/home/%' OR path LIKE '/Users/%';`

**  
Explanation**: The following query will search in the list of running processes and see which method is running from the user directory, as shown in the result below:

System Profiling

```shell-session
osquery> SELECT pid, name, path, cmdline, start_time FROM processes WHERE path LIKE '/home/%' OR path LIKE '/Users/%';
+-----+-------------+--------------+-------------------------------------------------+------------+
| pid | name        | path                                            | cmdline    | start_time   |
+-----+-------------+-------------------------------------------------+---------------------------+
| 832 | REDACTED    | REDACTED                                        | REDACTED   | 1720628069    |
+-----+-------------+-------------------------------------------------+---------------------------+
```

The above search queries demonstrate a few angles of examining the running processes from a suspicious mindset. They could be good Indicators of Compromise (IOC) and can be used for further investigation and the creation of host-based detection rules.


# Listing Network Communication

To examine the network connections on the Linux host, there are various built-in command-line tools that we can use, as shown below:  

|**Command**|**Description**|
|---|---|
|`netstat`|It displays network connections, routing tables, interface statistics, masquerade connections, and multicast memberships, which are useful for getting a snapshot of the current network status.|
|`ss`|Similar to `netstat`, but faster and more detailed. It dumps socket statistics and shows active connections and listening ports.|
|`tcpdump`|Captures and analyzes network packets in real time. You can save these packets to a file for later analysis or filter them to focus on specific types of traffic.|
|`iftop`|It provides a real-time display of bandwidth usage on an interface. This is handy for seeing which connections are using the most bandwidth.|
|`lsof`|Lists open files, including network connections. It's useful for seeing which processes are connected to the network and what ports they're using.|
|`iptables`|It displays, sets up, and maintains IP packet filter rules, helps manage firewall rules, and monitors network traffic.|
|`nmap`|It scans networks to discover hosts and services. This is useful for identifying devices on the network and what ports they're using.|
|`ping`|It tests connectivity to other network devices by sending ICMP echo request packets. It's useful for checking whether a host is reachable.|
|`traceroute`|Traces the path packets take to reach a destination. It helps identify where network delays or issues might be occurring.|
|`dig`|Queries DNS servers for information about domain names. It helps diagnose DNS-related issues.|
|`hostname`|Displays or sets the system's hostname and associated IP address. It's useful for identifying the local system's network identity.|
|`ifconfig`|Configures network interfaces. While largely replaced by `ip` commands in modern systems, it's still useful for displaying information about network interfaces.|
|`ip`|More powerful and versatile replacement for `ifconfig`. It can be used to configure interfaces, routing, and tunnels.|
|`arp`|Displays and modifies the system's ARP (Address Resolution Protocol) table. It's useful for associating IP addresses with MAC addresses.|
|`route`|Displays or modifies the IP routing table. It helps understand how packets are routed through the network.|
|`curl`|Transfers data from or to a server using various protocols. It's useful for testing network connections and downloading files.|
|`wget`|Non-interactive network downloader. It's primarily used to download files from the web and can be useful for testing download speeds and connectivity.|
|`netcat`|Reads and writes data across network connections using TCP or UDP. It's a versatile tool for debugging and testing network connections.|
|`whois`|Queries the WHOIS database for domain registration information. It's useful for gathering information about domain owners.|
|`nslookup`|Queries DNS servers to obtain domain name or IP address mapping. It's useful for diagnosing DNS issues.|

Let's now use osquery to narrow our search to find suspicious network connections.

**Network Connections**

From an investigation point of view, examining ongoing network communication or past connections can be a vital piece of the puzzle in solving the case.  
**Query:** `SELECT pid, family, remote_address, remote_port, local_address, local_port, state FROM process_open_sockets LIMIT 20;`  

**Explanation:** This query retrieves information about network connections established by various processes on the system. It selects entries from the `process_open_sockets` table.

osquery

```shell-session
osquery> SELECT pid, family, remote_address, remote_port, local_address, local_port, state FROM process_open_sockets LIMIT 20;
+------+--------+----------------+-------------+---------------+------------+-------------+
| pid  | family | remote_address | remote_port | local_address | local_port | state       |
+------+--------+----------------+-------------+---------------+------------+-------------+
| 1918 | 2      | 0.0.0.0        | 0           | 0.0.0.0       | 25         | LISTEN      |
| 985  | 2      | 0.0.0.0        | 0           | 0.0.0.0       | 80         | LISTEN      |
| 894  | 2      | 0.0.0.0        | 0           | 127.0.0.1     | 5901       | LISTEN      |
| 537  | 2      | 0.0.0.0        | 0           | 127.0.0.53    | 53         | LISTEN      |
| 575  | 2      | 0.0.0.0        | 0           | 127.0.0.1     | 631        | LISTEN      |
| 4097 | 2      | 10.100.2.28    | 53900       | 10.10.26.146  | 80         | ESTABLISHED |
| 894  | 2      | 127.0.0.1      | 58844       | 127.0.0.1     | 5901       | ESTABLISHED |
| 4097 | 2      | 127.0.0.1      | 5901        | 127.0.0.1     | 58844      | ESTABLISHED |
| 1918 | 10     | ::             | 0           | ::            | 25         | LISTEN      |
| 575  | 10     | ::             | 0           | ::1           | 631        | LISTEN      |
| 894  | 10     | ::             | 0           | ::1           | 5901       | LISTEN      |
| 633  | 2      | 0.0.0.0        | 0           | 0.0.0.0       | 631        |             |
| 573  | 2      | 0.0.0.0        | 0           | 0.0.0.0       | 5353       |             |
| 573  | 2      | 0.0.0.0        | 0           | 0.0.0.0       | 57020      |             |
| 537  | 2      | 0.0.0.0        | 0           | 127.0.0.53    | 53         |             |
| 481  | 2      | 0.0.0.0        | 0           | 10.10.26.146  | 68         |             |
| 573  | 10     | ::             | 0           | ::            | 5353       |             |
| 573  | 10     | ::             | 0           | ::            | 49437      |             |
| 481  | 10     | ::             | 0           | ::            | 58         |             |
| 1053 | 1      |                | 0           |               | 0          |             |
+------+--------+----------------+-------------+---------------+------------+-------------+
```

  
The network connections can help identify malicious connections and link them to the processes that have initiated those connections.  

**Remote Connection**

The remote network connection established on this host could help identify potential C2 server communication. We will use the following command to list down all the network connections with a remote connection.

**Search Query:** `SELECT pid, fd, socket, local_address, remote_address, local_port, remote_port FROM process_open_sockets WHERE remote_address IS NOT NULL;`  

Remote Connection  

```shell-session
osquery> SELECT pid, fd, socket, local_address, remote_address, local_port, remote_port FROM process_open_sockets WHERE remote_address IS NOT NULL;
+------+-----+--------+---------------+----------------+------------+-------------+
| pid  | fd  | socket | local_address | remote_address | local_port | remote_port |
+------+-----+--------+---------------+----------------+------------+-------------+
| 547  | 7   | 23406  | 127.0.0.1     | 0.0.0.0        | 631        | 0           |
| 498  | 13  | 20903  | 127.0.0.53    | 0.0.0.0        | 53         | 0           |
| 834  | 3   | 27815  | 0.0.0.0       | 0.0.0.0        | 22         | 0           |
| 925  | 3   | 28472  | 0.0.0.0       | 0.0.0.0        | 80         | 0           |
| 885  | 7   | 29169  | 127.0.0.1     | 0.0.0.0        | 5901       | 0           |
| 885  | 22  | 33531  | 127.0.0.1     | 127.0.0.1      | 5901       | 55186       |
| 1404 | 4   | 33896  | 10.10.18.7    | 10.100.2.28    | 80         | 38648       |
| 1404 | 8   | 33530  | 127.0.0.1     | 127.0.0.1      | 55186      | 5901        |
| 885  | 8   | 29170  | ::1           | ::             | 5901       | 0           |
| 834  | 4   | 27826  | ::            | ::             | 22         | 0           |
| 547  | 6   | 23405  | ::1           | ::             | 631        | 0           |
| 498  | 12  | 20902  | 127.0.0.53    | 0.0.0.0        | 53         | 0           |
| 453  | 19  | 20050  | 10.10.18.7    | 0.0.0.0        | 68         | 0           |
| 633  | 7   | 24637  | 0.0.0.0       | 0.0.0.0        | 631        | 0           |
| 545  | 12  | 24157  | 0.0.0.0       | 0.0.0.0        | 5353       | 0           |
| 545  | 14  | 24159  | 0.0.0.0       | 0.0.0.0        | 34093      | 0           |
| 545  | 15  | 24160  | ::            | ::             | 33518      | 0           |
| 545  | 13  | 24158  | ::            | ::             | 5353       | 0           |
```

**  
Examining DNS Queries**

Use the following query to retrieve the information about the DNS queries on this host.  
  
**Search Query:** `SELECT * FROM dns_resolvers;`  

DNSQueries  

```shell-session
osquery> SELECT * FROM dns_resolvers;
+----+------------+----------------------------+---------+----------+
| id | type       | address                    | netmask | options  |
+----+------------+----------------------------+---------+----------+
| 0  | nameserver | 127.0.0.53                 | 32      | 68158145 |
| 0  | search     | eu-west-1.compute.internal |         | 68158145 |
+----+------------+----------------------------+---------+----------+
```

  

**Listing Down Network Interfaces**

Use the following query to retrieve the information about the network interface.  

**Search Query:** `SELECT * FROM interface_addresses;`  

Network Interfaces  

```shell-session
osquery> SELECT interface, address, mask, broadcast FROM interface_addresses;
+-----------+------------------------------+-----------------------------------------+---------------+
| interface | address                      | mask                                    | broadcast     |
+-----------+------------------------------+-----------------------------------------+---------------+
| lo        | 127.0.0.1                    | 255.0.0.0                               |               |
| eth0      | 10.10.18.7                   | 255.255.0.0                             | 10.10.255.255 |
| lo        | ::1                          | ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff |               |
| eth0      | fe80::7c:7eff:feb4:26c9%eth0 | ffff:ffff:ffff:ffff::                   |               |
+-----------+------------------------------+-----------------------------------------+---------------+
```

**  
List Network Connections**

Let's use the following command to list down the listening ports.  

**Search query:** `SELECT * FROM listening_ports;`  

Osquery: Listening Ports  

```shell-session
osquery> SELECT * FROM listening_ports;
+-----+------+----------+--------+------------+----+--------+------+---------------+
| pid | port | protocol | family | address    | fd | socket | path | net_namespace |
+-----+------+----------+--------+------------+----+--------+------+---------------+
| -1  | 25   | 6        | 2      | 0.0.0.0    | -1 | 33899  |      | 0             |
| -1  | 80   | 6        | 2      | 0.0.0.0    | -1 | 28450  |      | 0             |
| 894 | 5901 | 6        | 2      | 127.0.0.1  | 7  | 29108  |      | 0             |
| -1  | 53   | 6        | 2      | 127.0.0.53 | -1 | 21756  |      | 0             |
| -1  | 631  | 6        | 2      | 127.0.0.1  | -1 | 408045 |      | 0             |
| -1  | 25   | 6        | 10     | ::         | -1 | 33900  |      | 0             |
| -1  | 631  | 6        | 10     | ::1        | -1 | 408044 |      | 0             |
| 894 | 5901 | 6        | 10     | ::1        | 8  | 29109  |      | 0             |
| -1  | 631  | 17       | 2      | 0.0.0.0    | -1 | 408066 |      | 0             |
| -1  | 5353 | 17       | 2      | 0.0.0.0    | -1 | 24794  |      | 0             |
+-----+------+----------+--------+------------+----+--------+------+---------------+
```

  

Explore the network communication established on this host and see if we can find a suspicious connection or open port.

# Footprint on Disk

Open Files

﻿First, Let's use the following query to list all the files opened.  

**Search Query**: `SELECT pid, fd, path FROM process_open_files;`

**Explanation:** This query will list all files that have been opened and are associated with some process. We can locate them through their respective pid.  

Opened Files  

```shell-session
osquery> SELECT pid, fd, path FROM process_open_files;
+------+----+----------------------------------+
| pid  | fd | path                             |
+------+----+----------------------------------+
| 1    | 0  | /dev/null                        |
| 1    | 1  | /dev/null                        |
| 1    | 10 | /proc/1/mountinfo                |
| 1    | 14 | /proc/swaps                      |
| 1    | 2  | /dev/null                        |
| 1    | 26 | /dev/autofs                      |
| 1    | 3  | /dev/kmsg                        |
| 1    | 46 | /run/dmeventd-server             |
| 1    | 47 | /run/dmeventd-client             |
| 1    | 48 | /run/cloud-init/hook-hotplug-cmd |
| 1    | 52 | /run/initctl                     |
| 1    | 59 | /dev/rfkill                      |
| 1    | 7  | /sys/fs/cgroup/unified           |
+------+----+----------------------------------+
```

  

Files Being Accessed From the tmp Directory

We can narrow down the result by filtering the query to only show the files being accessed from the `/tmp/` directory.

**Search Query:** `SELECT pid, fd, path FROM process_open_files where path LIKE '/tmp/%';`  
  
**Explanation**: This query will search for the processes that have opened files on the system. For this query, we only look at the files accessed from the `/tmp/` directory. In an actual investigation, we will have to look at various other locations.

Opened Files  

```shell-session
osquery> SELECT pid, fd, path FROM process_open_files where path LIKE '/tmp/%';
+------+----+----------------------+
| pid  | fd | path                 |
+------+----+----------------------+
| 1636 | 15 | /tmp/#5741 (deleted) |
| 1636 | 16 | /tmp/#6542 (deleted) |
| 556  | 4  | /tmp/REDACTED.log    |
| 825  | 1  | /tmp/#1673 (deleted) |
| 825  | 2  | /tmp/#1673 (deleted) |
+------+----+----------------------+
```

  
From the output, it is clear that one of the files being accessed by process ID `556` looks suspicious, and the file's intended purpose is very clear from its name. But what is the name of the process associated with this pid? Let's use another query to identify the process name using this pid, as shown below:  

**Search Query:** `select pid, name, path from processes where pid = '556';`  

Process Hunting  

```shell-session
osquery> select pid, name, path from processes where pid = '556';
+-----+----------+------------------+
| pid | name     | path              |
+-----+----------+-------------------+
| 556 | REDACTED | /var/tmp/REDACTED |
+-----+-------+---------------------+
```

  
We have identified a process that looks similar to a system file. This could also be a case of suspicious processes masquerading as legitimate system files to avoid detection.

Hidden Files

Hiding files on the host is a common practice. However, adversaries may also change the mode of suspicious files to hide if they do not want the user to see them. We will use the following command to look at the root directory for any hidden files or directories.  

**Search Query:** `SELECT filename, path, directory, size, type FROM file WHERE path LIKE '/.%';`  

**Explanation:** This query will examine the root directory to track down hidden files or folders. In a real investigation, we will also need to examine other locations.

Hidden Files  

```shell-session
osquery> SELECT filename, path, directory, size, type FROM file WHERE path LIKE '/.%';
+------------+------------+-----------+-------+-----------+
| filename   | path       | directory | size  | type      |
+------------+------------+-----------+-------+-----------+
| .          | /../       | /..       | 4096  | directory |
| .          | /./        | /.        | 4096  | directory |
| .REDACTED  | /.REDACTED | /         | 17088 | regular   |
+------------+------------+-----------+-------+-----------+
```

  
It looks like we found an executable in the root directory, which looks suspicious.  

Similarly, we can update the query to look at other directories like `/tmp/`, `/etc/`, `/usr/bin/`, etc.  

Recently Modified Files

Let's use the following command to see which file was recently modified.

**Search Query**:`SELECT filename, path, directory, type, size FROM file WHERE path LIKE '/etc/%' AND (mtime > (strftime('%s', 'now') - 86400));`  

Recent Modified Files  

```shell-session
osquery> SELECT filename, path, directory, type, size FROM file WHERE path LIKE '/etc/%' AND (mtime > (strftime('%s', 'now') - 86400));
+----------+------------+-----------+-----------+------+
| filename | path       | directory | type      | size |
+----------+------------+-----------+-----------+------+
| .        | /etc/cups/ | /etc/cups | directory | 4096 |
| mtab     | /etc/mtab  | /etc      | regular   | 0    |
+----------+------------+-----------+-----------+------+
```

  
This query will look at the modified time (mtime) and list down the recently modified files. During a live investigation, this could be very useful in tracking down the system files or binaries that were recently modified.  
Recently Modified Binaries

Similar to files, adversaries tend to modify system binaries and ingest malicious code into them to avoid detection. This query will look at the modification time and see which binary was modified recently.

**Search Query:** `SELECT filename, path, directory, mtime FROM file WHERE path LIKE '/opt/%' OR path LIKE '/bin/' AND (mtime > (strftime('%s', 'now') - 86400));`  

Recent Modified Binaries

```shell-session
osquery> SELECT filename, path, directory, mtime FROM file WHERE path LIKE '/opt/%' OR path LIKE '/bin/' AND (mtime > (strftime('%s', 'now') - 86400));
+----------+---------------+--------------+------------+
| filename | path          | directory    | mtime      |
+----------+---------------+--------------+------------+
| hh.so    | /opt/hh.so    | /opt         | 1720550772 |
| .        | /opt/ll/      | /opt/ll      | 1720550795 |
| .        | /opt/osquery/ | /opt/osquery | 1719256660 |
+----------+---------------+--------------+------------+
```

  
The above query only looks at the files and binaries updated in the last 24 hours in the `/opt/` or `/bin/` directories. We can update the time to get the updated results.  
  
**Note:** There is expected to be no result when it is executed on the attached VM.  

Finding Suspicious Packages

Adversaries often install suspicious packages via apt or dpkg to gain and maintain access to compromised Linux systems. These packages can be used for various malicious purposes, such as establishing persistence, capturing data, or maintaining backdoor access.

Let's see if the suspect had installed any malicious packages on the host.

**Search for the Latest Installed Packages**  

Search for the term `install` in the `/var/log/dpkg.log` file, which contains all the information about installed / uninstalled packages.  

Installed Packages

```shell-session
ubuntu@cybertees:/home$ grep " install " /var/log/dpkg.log
2024-06-13 06:47:05 install linux-image-5.15.0-1063-aws:amd64 <none> 5.15.0-1063.69~20.04.1
2024-06-13 06:47:06 install linux-aws-5.15-headers-5.15.0-1063:all <none> 5.15.0-1063.69~20.04.1
2024-06-13 06:47:09 install linux-headers-5.15.0-1063-aws:amd64 <none> 5.15.0-1063.69~20.04.1
2024-06-24 19:17:39 install osquery:amd64 <none> 5.12.1-1.linux
2024-06-26 05:54:38 install sysstat:amd64 <none> 12.2.0-2ubuntu0.3
2024-06-26 14:32:05 install REDACTED:amd64 <none> 1.0
```

  

Here, we found a suspicious package installed on the 26th of June, 2024. Let's use this information to search, as shown below:

**Command:** `dpkg -l | grep <REDACTED>`  

Installed Packages

```shell-session
ubuntu@cybertees:/home$ dpkg -l | grep <<REDACTED>>
     Name   Version  Architecture      Description
===================================-=====================================-============-
ii  REDACTED   1.0  amd64  Package to collect the data.SecRET_Code: {REDACTED}
```

  
We have found our suspicious package installed on this host, and its name suggests clear intentions.  

In this task, we examined various interesting footprints that an adversary may leave behind on the host and how they can be traced.

# Persistence
Investigating the Initialization Services  

Out of many ways, adversaries would initiate the services on the infected host to stay persistent and avoid detection. All services are placed on the path `/etc/systemd/system`. One way of examining the installed services is to check the directory and see if we can find any odd-looking services.  
  

Services List  

```shell-session
root@cybertees:/etc/systemd/system# ls

dbus-org.freedesktop.ModemManager1.service   
multi-user.target.wants   
snap-core18-2812.mount                           
sshd.service          
snap-core20-2318.mount     
<REDACTED>.service 
<REDACTED>.service
default.target.wants
```

  
If we look at the output, we can see two suspicious services. We can use the `cat` command to read the content of the services and see if we can understand its intent.  
  
![Shows content of suspicious service](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1720623327859.png)  

It seems one of the services is using the `Netcat` utility to open a listening port that can be used as a backdoor entry.  
  
Hunting for a Backdoor Account

Creating a backdoor account is a common practice observed in various APT groups to gain a foothold in the network. Let's use the following command to examine the available users and see if we can find any odd accounts.

**Search Query**: `select username, directory from users;`  

Backdoor Account  

```shell-session
osquery> select username, directory from users;
+----------+-----------------+
| username | directory       |
+----------+-----------------+
| root     | /root           |
| daemon   | /usr/sbin       |
| badactor | /home/badactor  |
| sys      | /dev            |
| sync     | /bin            |
| games    | /usr/games      |
| man      | /var/cache/man  |
| lp       | /var/spool/lpd  |
| mail     | /var/mail       |
+----------+-----------------+
```

  
The above command queried the user's table and retrieved the usernames from it. You can see the suspicious user account created on this host.  

We can also list down the names of the users from the `/etc/passwd` file.

**Command**: `cut -d  : -f1 /etc/passwd`  

/etc/passwd

```shell-session
root@cybertees:/usr/bin# cut -d  : -f1 /etc/passwd
root
daemon
bin
-----
-----
----
--
man
badactor
attacker
```

  

Examining Cron Jobs  
  
As already covered in the [Linux Process Analysis](https://tryhackme.com/r/room/linuxprocessanalysis) room, Cron is a time-based job scheduler in Unix-like operating systems. Intruders can create cron jobs to execute malicious scripts regularly, ensuring their activity continues after rebooting. Let's examine the cron tables by running the following command:

**Command:** `crontab -l`

Cron Job  

```shell-session
root@cybertees:/home/ubuntu# crontab -l
# Edit this file to introduce tasks to be run by cron.
# 
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
# 
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').
# 
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
# 
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
# 
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
# 
# For more information see the manual pages of crontab(5) and cron(8)
# 
# m h  dom mon dow   command

@reboot /home/<REDACTED>
```

  

It looks like a process from a hidden directory located in the backdoor account's directory. We can examine the process for further investigation.  
  
In this task, we have looked at common ways an adversary would maintain persistence. It is also worth noting that, apart from these methods, there are so many different techniques that an adversary can perform to achieve this same goal.