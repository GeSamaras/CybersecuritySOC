
#### 1. **Reconnaissance**
   - **Objective:** Gather as much information as possible.
   - **Tools & Technologies:**
     - [ ] **Nmap:** Net scanning 
     ``nmap -sS -sV -O -p- -A -T4 --script vuln -oA comprehensive_scan 192.168.1.1`	
	
     - [ ] **Nikto:** Web server scanning (`nikto -h target_ip`)
     - [ ] **Dirbuster/Dirb:** Directory brute-forcing
     - [ ] **Google Dorks:** Advanced search queries for finding information
     - [ ] **WHOIS:** Domain information (`whois target_domain`)
     - [ ] **nslookup/dig:** DNS queries

#### 2. **Enumeration**
   - **Objective:** Extract detailed information on services.
   - **Tools & Technologies:**
     - [ ] **Netcat:** Banner grabbing (`nc -v target_ip port`)
     - [ ] **Hydra:** Password brute-forcing (`hydra -L users.txt -P passwords.txt target_ip ssh`)
     - [ ] **SMBclient:** SMB enumeration (`smbclient -L \\target_ip`)
     - [ ] **Enum4linux:** Linux enumeration

#### 3. **Exploitation**
   - **Objective:** Gain access by exploiting vulnerabilities.
   - **Tools & Technologies:**
     - [ ] **Metasploit:** Framework for exploiting vulnerabilities (`msfconsole`)
     - [ ] **Searchsploit:** Search for exploits (`searchsploit service_name`)
     - [ ] **Burp Suite:** Web application testing and manipulation
     - [ ] **SQLmap:** Automated SQL injection (`sqlmap -u "target_url"`)

#### 4. **Privilege Escalation**
   - **Objective:** Gain higher-level permissions.
   - **Tools & Technologies:**
     - [ ] **LinPEAS:** Linux privilege escalation script
     - [ ] **Windows Exploit Suggester:** Suggests potential exploits for Windows
     - [ ] **GTFOBins:** Linux binaries for privilege escalation
     - [ ] **WinPEAS:** Windows privilege escalation script

#### 5. **Post-Exploitation**
   - **Objective:** Maintain access and gather further information.
   - **Tools & Technologies:**
     - [ ] **Mimikatz:** Extract passwords and tokens from memory (Windows)
     - [ ] **Metasploit:** Post-exploitation modules
     - [ ] **Empire:** Post-exploitation framework
     - [ ] **PowerShell Empire:** PowerShell post-exploitation

#### 6. **Capture the Flag (CTF)**
   - **Objective:** Locate and capture flags.
   - **Techniques:**
     - [ ] **Strings:** Search for readable text in files (`strings file`)
     - [ ] **Grep:** Search for specific patterns (`grep -r "flag" /`)
     - [ ] **Find:** Locate files (`find / -name flag*`)
     - [ ] **Decode:** Use online or local tools for decoding base64, hex, etc.

#### 7. **Reporting**
   - **Objective:** Document findings and processes.
   - **Tools & Technologies:**
     - **Markdown:** For well-formatted reports
     - **Joplin/Evernote:** Note-taking applications
     - **Screenshots:** Documenting evidence (e.g., `Scrot` for Linux)
     - **Video Capture:** Recording exploitation steps (e.g., `OBS Studio`)

1. **Reconnaissance:** Use Nmap to identify open ports and services.
2. **Enumeration:** Use Nikto to find vulnerabilities in the web server.
3. **Exploitation:** Use Metasploit to exploit a known vulnerability.
4. **Privilege Escalation:** Use LinPEAS to find a potential privilege escalation vector.
5. **Post-Exploitation:** Use Mimikatz to extract admin credentials.
6. **Capture the Flag:** Use grep to locate the flag in the file system.
7. **Reporting:** Document the steps taken and findings in Markdown.