![Zeek logo.](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/28e589bb58d154301e8b2f12b1d501d4.png)  

[The official description;](https://docs.zeek.org/en/master/about.html) "Zeek (formerly Bro) is the world's leading platform for network security monitoring. Flexible, open-source, and powered by defenders." "Zeek is a passive, open-source network traffic analyser. Many operators use Zeek as a network security monitor (NSM) to support suspicious or malicious activity investigations. Zeek also supports a wide range of traffic analysis tasks beyond the security domain, including performance measurement and troubleshooting."

**Zeek vs Snort**

|   |   |   |
|---|---|---|
|**Tool**|**Zeek**|**Snort**|
|**Capabilities**|NSM and IDS framework. It is heavily focused on network analysis. It is more focused on specific threats to trigger alerts. The detection mechanism is focused on events.|An IDS/IPS system. It is heavily focused on signatures to detect vulnerabilities. The detection mechanism is focused on signature patterns and packets.|
|**Cons**|Hard to use.<br><br>The analysis is done out of the Zeek, manually or by automation.|Hard to detect complex threats.|
|**Pros**|It provides in-depth traffic visibility.<br><br>Useful for threat hunting.<br><br>Ability to detect complex threats.<br><br>It has a scripting language and supports event correlation. <br><br>Easy to read logs.|Easy to write rules.<br><br>Cisco supported rules.<br><br>Community support.|
|**Common Use Case**|Network monitoring.  <br>In-depth traffic investigation.  <br>Intrusion detecting in chained events.|Intrusion detection and prevention.  <br>Stop known attacks/threats.|



**Zeek logs in a nutshell;**

|                      |                                                                          |                                                                                                                                                                                                                                                                                                                                    |
| -------------------- | ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Category             | Description                                                              | **Log Files**                                                                                                                                                                                                                                                                                                                      |
| Network              | Network protocol logs.                                                   | _conn.log, dce_rpc.log, dhcp.log, dnp3.log, dns.log, ftp.log, http.log, irc.log, kerberos.log, modbus.log, modbus_register_change.log, mysql.log, ntlm.log, ntp.log, radius.log, rdp.log, rfb.log, sip.log, smb_cmd.log, smb_files.log, smb_mapping.log, smtp.log, snmp.log, socks.log, ssh.log, ssl.log, syslog.log, tunnel.log._ |
| Files                | File analysis result logs.                                               | _files.log, ocsp.log, pe.log, x509.log._                                                                                                                                                                                                                                                                                           |
| NetControl           | Network control and flow logs.                                           | _netcontrol.log, netcontrol_drop.log, netcontrol_shunt.log, netcontrol_catch_release.log, openflow.log._                                                                                                                                                                                                                           |
| Detection            | Detection and possible indicator logs.                                   | _intel.log, notice.log, notice_alarm.log, signatures.log, traceroute.log._                                                                                                                                                                                                                                                         |
| Network Observations | Network flow logs.                                                       | _known_certs.log, known_hosts.log, known_modbus.log, known_services.log, software.log._                                                                                                                                                                                                                                            |
| Miscellaneous        | Additional logs cover external alerts, inputs and failures.              | _barnyard2.log, dpd.log, unified2.log, unknown_protocols.log, weird.log, weird_stats.log._                                                                                                                                                                                                                                         |
| Zeek Diagnostic      | Zeek diagnostic logs cover system messages, actions and some statistics. | _broker.log, capture_loss.log, cluster.log, config.log, loaded_scripts.log, packet_filter.log, print.log, prof.log, reporter.log, stats.log, stderr.log, stdout.log._                                                                                                                                                              |
 **==Cheatsheet==**

|   |   |   |   |
|---|---|---|---|
|Category|Command Purpose and Usage|Category|Command Purpose and Usage|
|Basics|View the command history:  <br>`ubuntu@ubuntu$ history`  <br><br>Execute the 10th command in history:  <br>`ubuntu@ubuntu$ !10`<br><br>Execute the previous command:  <br>`ubuntu@ubuntu$ !!`|Read **File**|Read sample.txt file:  <br>`ubuntu@ubuntu$ cat sample.txt`<br><br>Read the first 10 lines of the file:  <br>`ubuntu@ubuntu$ head sample.txt`  <br><br>Read the last 10 lines of the file:  <br>`ubuntu@ubuntu$ tail sample.txt`|
|Find  <br>&  <br>Filter|Cut the 1st field:  <br>`ubuntu@ubuntu$ cat test.txt \| cut -f 1`  <br><br>Cut the 1st column:  <br>`ubuntu@ubuntu$ cat test.txt \| cut -c1`  <br><br>Filter specific keywords:  <br>`ubuntu@ubuntu$ cat test.txt \| grep 'keywords'`  <br><br>Sort outputs alphabetically:  <br>`ubuntu@ubuntu$ cat test.txt \| sort`<br><br>Sort outputs numerically:  <br>`ubuntu@ubuntu$ cat test.txt \| sort -n`<br><br>Eliminate duplicate lines:  <br>`ubuntu@ubuntu$ cat test.txt \| uniq`  <br><br>Count line numbers:  <br>`ubuntu@ubuntu$ cat test.txt \| wc -l`  <br><br>Show line numbers  <br>`ubuntu@ubuntu$ cat test.txt \| nl`|Advanced|Print line 11:  <br>`ubuntu@ubuntu$ cat test.txt \| sed -n '11p'`  <br><br>Print lines between 10-15:  <br>`ubuntu@ubuntu$ cat test.txt \| sed -n '10,15p'`<br><br>Print lines below 11:  <br>`ubuntu@ubuntu$ cat test.txt \| awk 'NR < 11 {print $0}'`  <br><br>Print line 11:  <br>`ubuntu@ubuntu$ cat test.txt \| awk 'NR == 11 {print $0}'`|

|   |   |
|---|---|
|**Special**|Filter specific fields of Zeek logs:<br><br>`ubuntu@ubuntu$ cat signatures.log \| zeek-cut uid src_addr dst_addr`|

|                                                  |                                                                                                  |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| **Use Case**                                     | **Description**                                                                                  |
| `sort \| uniq`                                   | Remove duplicate values.                                                                         |
| `sort \| uniq -c`                                | Remove duplicates and count the number of occurrences for each value.                            |
| `sort -nr`                                       | Sort values numerically and recursively.                                                         |
| `rev`                                            | Reverse string characters.                                                                       |
| `cut -f 1`                                       | Cut field 1.                                                                                     |
| `cut -d '.' -f 1-2`                              | Split the string on every dot and print keep the first two fields.                               |
| `grep -v 'test'`                                 | Display lines that  don't match the "test" string.                                               |
| `grep -v -e 'test1' -e 'test2'`                  | Display lines that don't match one or both "test1" and "test2" strings.                          |
| `file`                                           | View file information.                                                                           |
| `grep -rin Testvalue1 * \| column -t \| less -S` | Search the "Testvalue1" string everywhere, organise column spaces and view the output with less. |

**Zeek Signatures**  

Zeek supports signatures to have rules and event correlations to find noteworthy activities on the network. Zeek signatures use low-level pattern matching and cover conditions similar to Snort rules. Unlike Snort rules, Zeek rules are not the primary event detection point. Zeek has a scripting language and can chain multiple events to find an event of interest. We focus on the signatures in this task, and then we will focus on Zeek scripting in the following tasks.  

Zeek signatures are composed of three logical paths; signature id, conditions and action. The signature breakdown is shown in the table below

|                  |                                                                                                                                                                                                                     |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Signature id** | **Unique** signature name.                                                                                                                                                                                          |
| **Conditions**   | **Header:** Filtering the packet headers for specific source and destination addresses, protocol and port numbers.<br><br>**<br><br>**Content:** Filtering the packet payload for specific value/pattern.<br><br>** |
| **Action**       | **Default action:** Create the "signatures.log" file in case of a signature match.<br><br>**Additional action:** Trigger a Zeek script.                                                                             |

Now let's dig more into the Zeek signatures. The below table provides the most common conditions and filters for the Zeek signatures.

|   |   |
|---|---|
|Condition Field|Available Filters|
|Header|src-ip: Source IP.<br><br>dst-ip: Destination IP.<br><br>src-port: Source port.<br><br>dst-port: Destination port.<br><br>ip-proto: Target protocol. Supported protocols; TCP, UDP, ICMP, ICMP6, IP, IP6|
|Content|**payload:** Packet payload.  <br>**http-request:** Decoded HTTP requests.  <br>**http-request-header:** Client-side HTTP headers.  <br>**http-request-body:** Client-side HTTP request bodys.  <br>**http-reply-header:** Server-side HTTP headers.  <br>**http-reply-body:** Server-side HTTP request bodys.  <br>**ftp:** Command line input of FTP sessions.|
|**Context**|**same-ip:** Filtering the source and destination addresses for duplication.|
|Action|**event:** Signature match message.|
|**Comparison  <br>Operators**|**==**, **!=**, **<**, **<=**, **>**, **>=**|
|**NOTE!**|Filters accept string, numeric and regex values.|


Sample Signature

```markdown
signature http-password {
     ip-proto == tcp
     dst-port == 80
     payload /.*password.*/
     event "Cleartext Password Found!"
}

# signature: Signature name.
# ip-proto: Filtering TCP connection.
# dst-port: Filtering destination port 80.
# payload: Filtering the "password" phrase.
# event: Signature match message.
```


Zeek signatures support regex. Regex ".*" matches any character zero or more times. The rule will match when a "password" phrase is detected in the packet payload. Once the match occurs, Zeek will generate an alert and create additional log files (signatures.log and notice.log).  

Signature Usage and Log Analysis

```markdown
ubuntu@ubuntu$ zeek -C -r http.pcap -s http-password.sig 
ubuntu@ubuntu$ ls
clear-logs.sh  conn.log  files.log  http-password.sig  http.log  http.pcap  notice.log  packet_filter.log  signatures.log

ubuntu@ubuntu$ cat notice.log  | zeek-cut id.orig_h id.resp_h msg 
10.10.57.178	44.228.249.3	10.10.57.178: Cleartext Password Found!
10.10.57.178	44.228.249.3	10.10.57.178: Cleartext Password Found!

ubuntu@ubuntu$ cat signatures.log | zeek-cut src_addr dest_addr sig_id event_msg 
10.10.57.178		http-password	10.10.57.178: Cleartext Password Found!
10.10.57.178		http-password	10.10.57.178: Cleartext Password Found!
```


Zeek Scripts  

Zeek has its own event-driven scripting language, which is as powerful as high-level languages and allows us to investigate and correlate the detected events. Since it is as capable as high-level programming languages, you will need to spend time on Zeek scripting language in order to become proficient. In this room, we will cover the basics of Zeek scripting to help you understand, modify and create basic scripts. Note that scripts can be used to apply a policy and in this case, they are called policy scripts.


Sample Script

```markdown
event dhcp_message (c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
{
print options$host_name;
}
```

extracting hostnames with tcpdump and tshark

```markdown
ubuntu@ubuntu$ zeek -C -r smallFlows.pcap dhcp-hostname.zeek 
student01-PC
vinlap01
```
