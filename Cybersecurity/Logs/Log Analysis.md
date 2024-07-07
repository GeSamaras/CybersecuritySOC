Timeline

When conducting log analysis, creating a timeline is a fundamental aspect of understanding the sequence of events within systems, devices, and applications. At a high level, a timeline is a chronological representation of the logged events, ordered based on their occurrence. The ability to visualize a timeline is a powerful tool for contextualizing and comprehending the events that occurred over a specific period.

Within incident response scenarios, timelines play a crucial role in reconstructing security incidents. With an effective timeline, security analysts can trace the sequence of events leading up to an incident, allowing them to identify the initial point of compromise and understand the attacker's tactics, techniques and procedures (TTPs).

Timestamp

In most cases, logs will typically include timestamps that record when an event occurred. With the potential of many distributed devices, applications, and systems generating individual log events across various regions, it's crucial to consider each log's time zone and format. Converting timestamps to a consistent time zone is necessary for accurate log analysis and correlation across different log sources.

Many log monitoring solutions solve this issue through timezone detection and automatic configuration. [Splunk](https://docs.splunk.com/Documentation/Splunk/9.1.0/Search/Abouttimezones), for example, automatically detects and processes time zones when data is indexed and searched. Regardless of how time is specified in individual log events, timestamps are converted to UNIX time and stored in the `_time` field when indexed.

This consistent timestamp can then be converted to a local timezone during visualization, which makes reporting and analysis more efficient. This strategy ensures that analysts can conduct accurate investigations and gain valuable insights from their log data without manual intervention.

Super Timelines

A super timeline, also known as a consolidated timeline, is a powerful concept in log analysis and digital forensics. Super timelines provide a comprehensive view of events across different systems, devices, and applications, allowing analysts to understand the sequence of events holistically. This is particularly useful for investigating security incidents involving multiple components or systems.

Super timelines often include data from previously discussed log sources, such as system logs, application logs, network traffic logs, firewall logs, and more. By combining these disparate sources into a single timeline, analysts can identify correlations and patterns that need to be apparent when analyzing logs individually.

Creating a consolidated timeline with all this information manually would take time and effort. Not only would you have to record timestamps for every file on the system, but you would also need to understand the data storage methods of every application. Fortunately, [Plaso (Python Log2Timeline)](https://github.com/log2timeline/plaso) is an open-source tool created by Kristinn Gudjonsson and many contributors that automates the creation of timelines from various log sources. It's specifically designed for digital forensics and log analysis and can parse and process log data from a wide range of sources to create a unified, chronological timeline.

To learn more about Plaso and its capabilities, visit the [official documentation page here](https://plaso.readthedocs.io/en/latest/).

Data Visualization

Data visualization tools, such as Kibana (of the Elastic Stack) and Splunk, help to convert raw log data into interactive and insightful visual representations through a user interface. Tools like these enable security analysts to understand the indexed data by visualizing patterns and anomalies, often in a graphical view. Multiple visualizations, metrics, and graphic elements can be constructed into a tailored dashboard view, allowing for a comprehensive "single pane of glass" view for log analysis operations.

![An example of a tailored Splunk dashboard for monitoring and performance](https://tryhackme-images.s3.amazonaws.com/user-uploads/6490641ea027b100564fe00a/room-content/caeace06b70e4c6920d32ae0bf22e8f4.png)  

To create effective log visualizations, it's essential first to understand the data (and sources) being collected and define clear objectives for visualization.

For example, suppose the objective is to monitor and detect patterns of increased failed login attempts. In that case, we should look to visualize logs that audit login attempts from an authentication server or user device. A good solution would be to create a line chart that displays the trend of failed login attempts over time. To manage the density of captured data, we can filter the visualization to show the past seven days. That would give us a good starting point to visualize increased failed attempts and spot anomalies.

Log Monitoring and Alerting

In addition to visualization, implementing effective log monitoring and alerting allows security teams to _proactively_ identify threats and immediately respond when an alert is generated.

Many SIEM solutions (like Splunk and the Elastic Stack) allow the creation of custom alerts based on metrics obtained in log events. Events worth creating alerts for may include multiple failed login attempts, privilege escalation, access to sensitive files, or other indicators of potential security breaches. Alerts ensure that security teams are promptly notified of suspicious activities that require immediate attention.

Roles and responsibilities should be defined for escalation and notification procedures during various stages of the incident response process. Escalation procedures ensure that incidents are addressed promptly and that the right personnel are informed at each severity level.

For a hands-on walkthrough on dashboards and alerting within Splunk, it is recommended to check out the [Splunk: Dashboards and Reports](https://tryhackme.com/jr/splunkdashboardsandreports) room!

External Research and Threat Intel

Identifying what may be of interest to us in log analysis is essential. It is challenging to analyze a log if we're not entirely sure what we are looking for.

First, let's understand what threat intelligence is. In summary, threat intelligence are pieces of information that can be attributed to a malicious actor. Examples of threat intelligence include:

- IP Addresses
- File Hashes
- Domains

When analyzing a log file, we can search for the presence of threat intelligence. For example, take this Apache2 web server entry below. We can see that an IP address has tried to access our site's admin panel.

Outputting an Apache2 Access Log

```shell-session
cmnatic@thm cat access.log
54.36.149.64 - - [25/Aug/2023:00:05:36 +0000] "GET /admin HTTP/1.1" 200 8260 "-" "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)"
191.96.106.80 - - [25/Aug/2023:00:33:11 +0000] "GET /TryHackMe/rooms/docker-rodeo/dockerregistry/catalog1.png HTTP/1.1" 200 19594 "https://tryhackme.com/" "Mozi>
54.36.148.244 - - [25/Aug/2023:00:34:46 +0000] "GET /TryHackMe/?C=D;O=D HTTP/1.1" 200 5879 "-" "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot>
66.249.66.68 - - [25/Aug/2023:00:35:53 +0000] "GET /TryHackMe%20Designs/ HTTP/1.1" 200 5973 "-" "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) 200 19594 "https://tryhackme.com/" "Mozi>
```

Using a threat intelligence feed like [ThreatFox](https://threatfox.abuse.ch/), we can search our log files for known malicious actors' presence.

![Threatfox output, highlighting several indicators of compromise in our log file](https://tryhackme-images.s3.amazonaws.com/user-uploads/6490641ea027b100564fe00a/room-content/c3ad6571c689577d907026d8a75d73c7.png)

  

Using GREP to search a logfile for an IP address

```shell-session
cmnatic@thm grep "54.36.149.64" logfile.txt
54.36.149.64
```



Common Log File Locations

A crucial aspect of log analysis is understanding where to locate log files generated by various applications and systems. While log file paths can vary due to system configurations, software versions, and custom settings, knowing common log file locations is essential for efficient investigation and threat detection.

- **Web Servers:**
    - **Nginx:**
        - Access Logs: `/var/log/nginx/access.log`
        - Error Logs: `/var/log/nginx/error.log`
    - **Apache:**
        - Access Logs: `/var/log/apache2/access.log`
        - Error Logs: `/var/log/apache2/error.log`

- **Databases:**
    - **MySQL:**
        - Error Logs: `/var/log/mysql/error.log`
    - **PostgreSQL:**
        - Error and Activity Logs: `/var/log/postgresql/postgresql-{version}-main.log`

- **Web Applications:**
    - **PHP:**
        - Error Logs: `/var/log/php/error.log`

- **Operating Systems:**
    - **Linux:**
        - General System Logs: `/var/log/syslog`
        - Authentication Logs: `/var/log/auth.log`

- **Firewalls and IDS/IPS:**
    - **iptables:**
        - Firewall Logs: `/var/log/iptables.log`
    - **Snort:**
        - Snort Logs: `/var/log/snort/`

While these are common log file paths, it's important to note that actual paths may differ based on system configurations, software versions, and custom settings. It's recommended to consult the official documentation or configuration files to verify the correct log file paths to ensure accurate analysis and investigation.

Common Patterns

In a security context, recognizing common patterns and trends in log data is crucial for identifying potential security threats. These "patterns" refer to the identifiable artifacts left behind in logs by threat actors or cyber security incidents. Fortunately, there are some common patterns that, if learned, will improve your detection abilities and allow you to respond efficiently to incidents.

**Abnormal User Behavior**

One of the primary patterns that can be identified is related to unusual or anomalous user behavior. This refers to any actions or activities conducted by users that deviate from their typical or expected behavior.

To effectively detect anomalous user behavior, organizations can employ log analysis solutions that incorporate detection engines and machine learning algorithms to establish normal behavior patterns. Deviations from these patterns or baselines can then be alerted as potential security incidents. Some examples of these solutions include [_Splunk User Behavior Analytics (UBA)_](https://www.splunk.com/en_us/products/user-behavior-analytics.html), _[IBM QRadar UBA](https://www.ibm.com/docs/en/qradar-common?topic=app-qradar-user-behavior-analytics)_, and _[Azure AD Identity Protection](https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/overview-identity-protection)_.

The specific indicators can vary greatly depending on the source, but some examples of this that can be found in log files include:

- **Multiple failed login attempts**
    - Unusually high numbers of failed logins within a short time may indicate a brute-force attack.
- **Unusual login times**
    - Login events outside the user's typical access hours or patterns might signal unauthorized access or compromised accounts.
- **Geographic anomalies**
    - Login events from IP addresses in countries the user does not usually access can indicate potential account compromise or suspicious activity.
    - In addition, simultaneous logins from different geographic locations (or indications of impossible travel) may suggest account sharing or unauthorized access.
- **Frequent password changes**
    - Log events indicating that a user's password has been changed frequently in a short period may suggest an attempt to hide unauthorized access or take over an account.
- **Unusual user-agent strings**
    - In the context of HTTP traffic logs, requests from users with uncommon user-agent strings that deviate from their typical browser may indicate automated attacks or malicious activities.
    - For example, by default, the [Nmap scanner](https://tryhackme.com/room/furthernmap) will log a user agent containing "Nmap Scripting Engine." The [Hydra brute-forcing tool](https://tryhackme.com/room/hydra), by default, will include "(Hydra)" in its user-agent. These indicators can be useful in log files to detect potential malicious activity.

The significance of these anomalies can vary greatly depending on the specific context and the systems in place, so it is essential to fine-tune any automated anomaly detection mechanisms to minimize false positives.

Common Attack Signatures

Identifying common attack signatures in log data is an effective way to detect and quickly respond to threats. Attack signatures contain specific patterns or characteristics left behind by threat actors. They can include malware infections, web-based attacks (SQL injection, cross-site scripting, directory traversal), and more. As this is entirely dependent on the attack surface, some high-level examples include:

SQL Injection

SQL injection attempts to exploit vulnerabilities in web applications that interact with databases. Look for unusual or malformed SQL queries in the application or database logs to identify common SQL injection attack patterns.

Suspicious SQL queries might contain unexpected characters, such as single quotes (`'`), comments (`--`, `#`), union statements (`UNION`), or time-based attacks (`WAITFOR DELAY`, `SLEEP()`). A useful SQLi payload list to reference can be found [here](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection).

In the below example, an SQL injection attempt can be identified by the `' UNION SELECT` section of the `q=` query parameter. The attacker appears to have escaped the SQL query with the single quote and injected a union select statement to retrieve information from the `users` table in the database. Often, this payload may be URL-encoded, requiring an additional processing step to identify it efficiently.

sqli.log

```plaintext
10.10.61.21 - - [2023-08-02 15:27:42] "GET /products.php?q=books' UNION SELECT null, null, username, password, null FROM users-- HTTP/1.1" 200 3122
```

Cross-Site Scripting (XSS)

Exploiting cross-site scripting (XSS) vulnerabilities allow attackers to inject malicious scripts into web pages. To identify common XSS attack patterns, it is often helpful to look for log entries with unexpected or unusual input that includes script tags (`<script>`) and event handlers (`onmouseover`, `onclick`, `onerror`). A useful XSS payload list to reference can be found [here](https://github.com/payloadbox/xss-payload-list).

In the example below, a cross-site scripting attempt can be identified by the `<script>alert(1);</script>` payload inserted into the `search` parameter, which is a common testing method for XSS vulnerabilities.

xss.log

```plaintext
10.10.19.31 - - [2023-08-04 16:12:11] "GET /products.php?search=<script>alert(1);</script> HTTP/1.1" 200 5153
```

Path Traversal

Exploiting path traversal vulnerabilities allows attackers to access files and directories outside a web application's intended directory structure, leading to unauthorized access to sensitive files or code. To identify common traversal attack patterns, look for traversal sequence characters (`../` and `../../`) and indications of access to sensitive files (`/etc/passwd`, `/etc/shadow`). A useful directory traversal payload list to reference can be found [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Directory%20Traversal/README.md).

It is important to note, like with the above examples, that directory traversals are often URL encoded (or double URL encoded) to avoid detection by firewalls or monitoring tools. Because of this, `%2E` and `%2F` are useful URL-encoded characters to know as they refer to the `.` and `/` respectively.

In the below example, a directory traversal attempt can be identified by the repeated sequence of `../` characters, indicating that the attacker is attempting to "back out" of the web directory and access the sensitive `/etc/passwd` file on the server.

path-traversal.log

```plaintext
10.10.113.45 - - [2023-08-05 18:17:25] "GET /../../../../../etc/passwd HTTP/1.1" 200 505
```

