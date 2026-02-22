# 🔍 Executive Summary

This project demonstrates the deployment and configuration of the Wazuh SIEM platform to implement File Integrity Monitoring (FIM) on a Windows 10 endpoint. The lab simulates unauthorized file changes and evaluates the detection capabilities of Wazuh from a SOC analyst perspective. Alerts were successfully generated for file creation, modification, and deletion, enabling real-time security monitoring and analysis.

---

# 🎯 Objectives

- Deploy Wazuh Manager, Indexer, and Dashboard on Ubuntu  
- Install and register Wazuh Agent on Windows 10  
- Configure real-time File Integrity Monitoring (FIM)  
- Generate and observe file activity alerts  
- Analyze FIM logs, hashes, metadata, and rule triggers  
- Simulate SOC investigation workflow  

---

# 🏗 Architecture


Windows 10 Endpoint → Wazuh Manager → Wazuh Indexer → Wazuh Dashboard
(Agent v4.x.x) (1514/1515) (9200/9600) (443)


---

# 🧰 Tools & Technologies Used

| Tool / Technology     | Purpose                               |
|----------------------|----------------------------------------|
| Wazuh 4.12 SIEM      | Log analysis, agent mgmt, FIM          |
| Windows 10 VM        | Monitored endpoint                     |
| Ubuntu Server        | Wazuh deployment                       |
| VMware Workstation   | Virtualization                         |
| PowerShell / CMD     | Troubleshooting                        |
| Notepad / Notepad++  | Change simulation                      |

---

# ⚙️ Methodology

### **1. Deploy Wazuh SIEM on Ubuntu**

curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh

sudo bash ./wazuh-install.sh -a -i

2. Install & Register Windows Agent

Installed MSI

Generated agent key via:

sudo /var/ossec/bin/manage_agents

Added Manager IP + Key in Wazuh Agent GUI

3. Configure File Integrity Monitoring

Edited:

C:\Program Files (x86)\ossec-agent\ossec.conf

Added:

<directories realtime="yes">C:\Users\Administrator\SensitiveFiles</directories>

Restarted the agent.

4. Generate File Activities

Created file

Modified file

Deleted file

5. Analyze Alerts in Wazuh Dashboard

Reviewed:

syscheck.event

syscheck.path

Hash changes

Rule IDs (550, 553, 554)

📊 Sample FIM Alert
syscheck.path: c:\users\administrator\sensitivefiles\secret_plan.txt
syscheck.event: modified

Old sha256sum: 8443edbbb7c000c36818966e198b8435b5dc81c12a58050d671ea8fa0c85669
New sha256sum: ff176899dc770c5705c1a8a48c21c8e0be1d6e3576f43070985e0c727a86d3b

rule.description: Integrity checksum changed
rule.id: 550

🚧 Challenges & Resolutions

1. Windows VM had no Internet (169.254.x.x)

Fix: Switched VMware adapter to NAT → renewed IP.

2. Authentication Key Invalid

Fix: Regenerated clean key via manage_agents.

3. Agent stuck at “Never Connected”

Fix: Corrected version mismatch and verified ports 1514/1515.

4. Unexpected Registry Alerts

Fix: Identified default Wazuh registry monitoring behavior.

📈 Results

Successful deployment of full Wazuh SIEM stack

Windows endpoint fully connected and monitored

FIM detected file creation, modification, and deletion

Alerts visible in dashboard with SHA1/SHA256 changes

Real-time visibility achieved across monitored directory

🧾 Conclusion

This lab successfully demonstrates the power of Wazuh’s File Integrity Monitoring capabilities for detecting unauthorized changes on endpoints. Through real-world simulation and SOC-style analysis, Wazuh proved to be a reliable and effective open-source SIEM solution for endpoint visibility, detection engineering, and security operations.
