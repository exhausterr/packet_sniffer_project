# 🔍 Cross-Platform Packet Sniffer (Python GUI)

## 🧠 Overview

This is a cross-platform packet sniffer tool built with Python and Tkinter for educational and internship purposes. It captures network packets in real time, parses key information (source IP, destination IP, protocol, payload), and displays logs in a GUI interface. Users can apply filters, run commands, and export logs. The tool is compatible with both Windows and Linux systems.

---

## 🧰 Features

- Real-time packet capture
- GUI with live scrollable output
- Interface and protocol filter selection
- Command-line input (`clear`, `status`, `help`, `filter`, `export`)
- Logging to JSON, CSV, and TXT
- Built-in test TCP server for safe traffic simulation
- Cross-platform support (Windows/Linux)
- Minimal dependencies

---

## 💻 Installation

```bash
git clone https://github.com/exhausterr/packet_sniffer_project
cd packet_sniffer_project
pip install psutil
```
## Usage 
- on Windows
```bash
python networkTracer.py
```
- on Linux
```bash
sudo python3 networkTracer.py
```
## 🧪 Built-in Commands
| Command        | Description                               |
| -------------- | ----------------------------------------- |
| clear          | Clears the GUI console                    |
| status         | Shows current interface and filter status |
| help           | Lists available commands                  |
| export         | Exports visible log to .txt               |
| filter <value> | Filters packets by IP or payload keyword  |

## 🌐 Logging
| File                 | Description                          |
| -------------------- | ------------------------------------ |
| packets\_log.json    | Captured packets in JSON format      |
| packets\_log.csv     | Same logs in CSV format              |
| tcp\_log.txt         | Logs received by the test TCP server |
| visible\_log\_\*.txt | Manual exports from GUI console      |

## 🧪 Test TCP Server
Click "Run Local Test Server" in the GUI:

Starts a local server on port 9999

Accepts 1 client connection

Logs all received messages to tcp_log.txt

Accepts clear, status, export, help, filter <value>

## ⚠️ Legal Use
This tool is intended for educational use only. Do not use it on networks without explicit permission. The author is not responsible for any misuse.

## 🧑‍💻 Author

Developed by [exhausterr](https://github.com/exhausterr) as the final project for a cybersecurity internship.  
Built using Python with raw sockets, threading, protocol dissection, and a Tkinter-based GUI interface. 

## 🖼️ Screenshots

### GUI Interface  
![GUI](screenshots/gui-interface.png)

### Clear Command  
![Clear](screenshots/command-clear-example.png)

### Interface and Filter Options  
![Filter](screenshots/interface-selection.png)




