# Sentinel + Velociraptor — Detection & Response Lab

Alert -> Playbook -> Host action. Microsoft Sentinel triggers a Logic App that calls a token-protected Flask webhook (via Cloudflare Tunnel), which hits the **Velociraptor** API to act on the endpoint.

- **Full write-up:** [sentinel-velociraptor-detection-lab.md](sentinel-velociraptor-detection-lab.md)  
- **All projects:** [cybersecurity-projects](https://github.com/Oligo12/cybersecurity-projects/tree/main)

---

## Highlights
- **Detections (KQL):** AgentTesla dropper writes in `%Temp%/%AppData%`; first-seen EXE in `AppData\Local\<folder>`; QuasarRAT UAC attempt (`-Verb RunAs` + 4672 within ~1m).
- **Automations:** Logic App -> **Flask webhook (X-Auth-Token)** -> **Velociraptor**.
- **Demo action:** **Kill by PID** (JSON confirmation returned).

**Flow:** Sentinel -> Logic App -> Cloudflare Tunnel -> Webhook -> Velociraptor -> Endpoint

*Lab only. Tokened webhook; minimal hardening applied.*
