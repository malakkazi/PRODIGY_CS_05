# PRODIGY_CS_05 - Network Packet Analyzer (Task 05)
This project is a simple **real-time network packet sniffer** built using Python and the `scapy` library.  
Developed as part of my **Cybersecurity Internship at Prodigy InfoTech**.


## 🔍 About the Project
The packet analyzer captures live network traffic and logs key details such as:
- ✅ Source and destination IP addresses
- ✅ Protocol used (TCP/UDP)
- ✅ Source and destination ports
- ✅ Timestamps for each packet

All data is saved in a structured `.txt` file (`packets_log.txt`) for review and analysis.


## 🛠️ Technologies Used
- **Python 3.x**
- [`Scapy`](https://scapy.net/) – for packet sniffing and analysis
- **Npcap** (for Windows users) – to support packet capture on Windows


## 🚀 How to Run

### 1. Install Dependencies

```bash
pip install scapy
