# Microsoft Sentinel Hybrid SOC Lab

This project simulates a hybrid enterprise environment with cloud-hosted AD, VPN-connected on-premises devices, and Microsoft Sentinel SIEM logging.  
The lab includes simulated attacks, custom detection rules, and automated incident response.

## Key Features

- **Architecture & Infrastructure** – Hybrid Azure + on-premises setup with IPsec VPN, Azure Arc onboarding, and Sysmon logging.
- **Data Ingestion** – Azure Monitor Agent (AMA) forwarding logs from Windows and Ubuntu endpoints, Suricata IDS, and pfSense firewall logs via Logstash.
- **Custom Detection Rules** – Built KQL-based rules for persistence, reverse shell activity, brute-force, C2 traffic, privilege escalation, and more.
- **Incident Response Workflow** – Simulated full attack chain; analyzed alerts and investigation graphs in Microsoft Sentinel.
- **Automation** – Logic App playbook sending registry persistence alerts to Discord.

---
- **Full Report:** [Sentinel Lab Report (PDF)](Sentinel-Lab/legacy-sentinel-lab/SentinelLab_NM.pdf)
- **See all my home-lab projects here:** [cybersecurity-projects](https://github.com/Oligo12/cybersecurity-projects/tree/main)
