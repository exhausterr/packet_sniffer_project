# networkTracer.py - Packet Sniffer with Test Server (Final Internship Project)

import socket
import struct
import json
import csv
import threading
import platform
from datetime import datetime
from tkinter import Tk, Label, Button, Text, Scrollbar, END, messagebox, Frame, StringVar, OptionMenu, Entry
import psutil

IS_WINDOWS = platform.system().lower().startswith("win")

class PacketSniffer:
    def __init__(self, gui, iface):
        self.gui = gui
        self.iface = iface
        self.sniffing = False
        self.cache = []
        self.flush_after = 50

        if IS_WINDOWS:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            local_ip = socket.gethostbyname(socket.gethostname())
            self.sock.bind((local_ip, 0))
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            self.sock.bind((iface, 0))

    def start(self):
        self.sniffing = True
        while self.sniffing:
            try:
                raw, _ = self.sock.recvfrom(65536)
                self.handle(raw)
            except Exception as err:
                self.gui.append_to_text_area(f"[!] Error: {err}")

    def stop(self):
        self.sniffing = False
        if IS_WINDOWS:
            self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

    def handle(self, raw):
        if IS_WINDOWS:
            iphdr = raw[0:20]
        else:
            if len(raw) < 34:
                return
            eth_type = struct.unpack('!H', raw[12:14])[0]
            if eth_type != 0x0800:
                return
            raw = raw[14:]
            iphdr = raw[0:20]

        iph = struct.unpack('!BBHHHBBH4s4s', iphdr)
        ihl = (iph[0] & 0xF) * 4
        src = socket.inet_ntoa(iph[8])
        dst = socket.inet_ntoa(iph[9])
        proto = iph[6]

        proto_names = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        name = proto_names.get(proto, str(proto))

        payload = raw[ihl:]
        try:
            readable = payload.decode(errors='ignore')
        except:
            readable = "<unreadable>"

        info = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': src,
            'dest_ip': dst,
            'protocol': name,
            'payload': readable
        }

        self.cache.append(info)

        if self.gui.protocol_filter.get() in ('All', name):
            if not self.gui.custom_filter or self.gui.custom_filter.lower() in (src.lower(), dst.lower(), readable.lower()):
                self.gui.append_to_text_area(f"[{info['timestamp']}] {src} -> {dst} | {name}")

        if len(self.cache) >= self.flush_after:
            self.flush()

    def flush(self):
        with open('packets_log.json', 'a') as jf:
            for row in self.cache:
                json.dump(row, jf)
                jf.write('\n')

        with open('packets_log.csv', 'a', newline='') as cf:
            w = csv.writer(cf)
            for row in self.cache:
                w.writerow([row['timestamp'], row['source_ip'], row['dest_ip'], row['protocol'], row['payload']])

        self.cache.clear()

class GUI:
    def __init__(self, root):
        self.master = root
        root.title("Sniffer Tool")

        self.label = Label(root, text="Basic Packet Sniffer (for Educational Use)", fg="darkred")
        self.label.pack()

        self.protocol_filter = StringVar(value="All")
        self.interface_choice = StringVar()
        self.custom_filter = ""

        f = Frame(root)
        f.pack(pady=5)

        iface_list = list(psutil.net_if_addrs().keys())
        self.interface_choice.set(iface_list[0] if iface_list else "")

        Label(f, text="Interface:").pack(side='left')
        OptionMenu(f, self.interface_choice, *iface_list).pack(side='left')

        Label(f, text="  Protocol:").pack(side='left')
        OptionMenu(f, self.protocol_filter, "All", "TCP", "UDP", "ICMP").pack(side='left')

        self.scrollbar = Scrollbar(root)
        self.scrollbar.pack(side='right', fill='y')

        self.text = Text(root, height=25, width=100, bg="black", fg="lime", font=("Courier", 10), yscrollcommand=self.scrollbar.set)
        self.text.pack()

        self.scrollbar.config(command=self.text.yview)

        self.command_entry = Entry(root, width=100)
        self.command_entry.pack(pady=5)
        self.command_entry.bind("<Return>", lambda event: self.handle_local_command(event))

        Button(root, text="Start Sniffing", command=self.start_sniffer).pack(pady=2)
        Button(root, text="Stop Sniffing", command=self.stop_sniffer).pack(pady=2)
        Button(root, text="Run Local Test Server", command=self.run_test_server).pack(pady=2)

        self.sniffer = None

    def append_to_text_area(self, msg):
        self.text.insert(END, msg + "\n")
        self.text.see(END)

    def start_sniffer(self):
        messagebox.showinfo("Reminder", "Use networks you have permission to inspect.")
        iface = self.interface_choice.get()
        self.sniffer = PacketSniffer(self, iface)
        t = threading.Thread(target=self.sniffer.start)
        t.daemon = True
        t.start()
        self.append_to_text_area(f"[*] Sniffing on {iface}...")

    def stop_sniffer(self):
        if self.sniffer:
            self.sniffer.stop()
            self.append_to_text_area("[*] Sniffing stopped.")

    def handle_local_command(self, event):
        try:
            cmd = self.command_entry.get().strip().lower()
            self.command_entry.delete(0, END)

            if cmd == "clear":
                self.text.delete(1.0, END)
                self.append_to_text_area("[*] Console cleared.")
            elif cmd == "help":
                self.append_to_text_area("[*] Available commands: clear, help, export, status, filter <value>, scan <ip>")
            elif cmd == "export":
                self.export_visible_log()
            elif cmd.startswith("filter"):
                parts = cmd.split(" ", 1)
                if len(parts) == 2:
                    self.custom_filter = parts[1]
                    self.append_to_text_area(f"[*] Custom filter set to: {self.custom_filter}")
            elif cmd == "status":
                self.append_to_text_area(f"[*] Sniffing on {self.interface_choice.get()} | Protocol: {self.protocol_filter.get()}")
            elif cmd.startswith("scan"):
                parts = cmd.split()
                if len(parts) == 2:
                    target = parts[1]
                    threading.Thread(target=self.tcp_port_scan, args=(target,), daemon=True).start()
                else:
                    self.append_to_text_area("[!] Usage: scan <ip>")
            else:
                self.append_to_text_area(f"[*] Unknown command: {cmd}")
        except Exception as e:
            self.append_to_text_area(f"[!] Error executing command: {e}")

    def tcp_port_scan(self, target_ip):
        self.append_to_text_area(f"[*] Starting full TCP scan on {target_ip} (ports 0–65535)")
        open_ports = []

        def scan_range(start, end):
            for port in range(start, end):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.2)
                    result = s.connect_ex((target_ip, port))
                    if result == 0:
                        self.append_to_text_area(f"[+] Port {port} is OPEN")
                        open_ports.append(port)
                    s.close()
                except:
                    pass

        threads = []
        chunk = 1000
        for i in range(0, 65536, chunk):
            t = threading.Thread(target=scan_range, args=(i, min(i + chunk, 65536)))
            t.daemon = True
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.append_to_text_area(f"[*] TCP scan complete. Open ports: {open_ports}")

    def run_test_server(self):
        def handle_single_client():
            s = socket.socket()
            s.bind(('0.0.0.0', 9999))
            s.listen(1)
            self.append_to_text_area("[+] Test TCP server on port 9999 (1 client only)")
            conn, addr = s.accept()
            self.append_to_text_area(f"[+] Connected: {addr}")
            while True:
                try:
                    data = conn.recv(1024)
                    if not data:
                        break
                    decoded = data.decode(errors='ignore').strip()

                    if decoded.lower() == "clear":
                        self.text.delete(1.0, END)
                        self.append_to_text_area("[*] Console cleared by remote command.")
                    elif decoded.lower() == "help":
                        self.append_to_text_area("[*] Available commands: clear, help, export, status, filter <value>, scan <ip>")
                    elif decoded.lower() == "export":
                        self.export_visible_log()
                    elif decoded.lower().startswith("filter"):
                        parts = decoded.split(" ", 1)
                        if len(parts) == 2:
                            self.custom_filter = parts[1]
                            self.append_to_text_area(f"[*] Custom filter set to: {self.custom_filter}")
                    elif decoded.lower() == "status":
                        self.append_to_text_area(f"[*] Sniffing on {self.interface_choice.get()} | Protocol: {self.protocol_filter.get()}")
                    elif decoded.lower().startswith("scan"):
                        parts = decoded.split()
                        if len(parts) == 2:
                            threading.Thread(target=self.tcp_port_scan, args=(parts[1],), daemon=True).start()
                    else:
                        self.append_to_text_area(f"[TestServer] {addr[0]}: {decoded}")
                        with open('tcp_log.txt', 'a') as log:
                            log.write(f"{addr[0]}: {decoded}\n")
                except:
                    break
            conn.close()
            self.append_to_text_area(f"[-] Disconnected: {addr}")

        t = threading.Thread(target=handle_single_client)
        t.daemon = True
        t.start()

    def export_visible_log(self):
        data = self.text.get(1.0, END).strip()
        filename = f"visible_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            f.write(data)
        self.append_to_text_area(f"[*] Exported visible log to {filename}")

if __name__ == "__main__":
    root = Tk()
    app = GUI(root)
    root.mainloop()
