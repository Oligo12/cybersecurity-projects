### Cybersecurity Projects – Nikola Marković
Hands-on cybersecurity projects and technical write-ups from real-world-style labs.

### Projects
- **[Sentinel x Velociraptor - Detection & Response Lab)](./Sentinel-Lab/sentinel-velociraptor-detection-lab/README.md)** – Alert -> Playbook -> Host action pipeline (Sentinel -> Logic App -> token-protected webhook via Cloudflare -> Velociraptor API). KQL detections (AgentTesla, QuasarRAT) + demo **kill by PID**.                                                                                                                                                                      
   **[Legacy lab](./Sentinel-Lab/legacy-sentinel-lab/README.md)** – Hybrid SOC (IPsec + Sysmon)

- **[QuasarRAT Analysis](./malware-analysis/QuasarRAT/README.md)** – Native C++ dropper + .NET launcher; AES-256 (PBKDF2) config decryption, TLS pinning, Run-key persistence, Pastebin bootstrap, TCP/4444 beacons.

- **[Agent Tesla Analysis](./malware-analysis/AgentTesla/README.md)** – AutoIt loader using **RegSvcs.exe** as host (injection), creds theft + keylogging, SMTP exfil; process trees, API monitor, ATT&CK mapping.                                                                                                                                           
- **[WannaCry Ransomware Analysis](./malware-analysis/wannacry/README.md)** – Static + dynamic in isolated lab; dropped files, process chains, persistence, targeted extensions, Tor C2 attempts.

### Contact
**[Email](mailto:nikola.z.markovic@pm.me)**  |  **[LinkedIn](https://linkedin.com/in/nikolazmarkovic)**
