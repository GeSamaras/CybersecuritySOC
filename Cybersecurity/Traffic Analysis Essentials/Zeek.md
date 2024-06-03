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