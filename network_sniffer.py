import threading
import tkinter as tk
from scapy.all import sniff, IP
from tkinter.scrolledtext import ScrolledText

# Global flag to control sniffing
sniffing = False
sniffer_thread = None

# Packet processing function
def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = ip_layer.proto
        payload = bytes(packet.payload)

        # Protocol number to name
        proto_name = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }.get(proto, str(proto))

        display = f"Src: {src} | Dst: {dst} | Proto: {proto_name} | Payload: {payload[:20]}\n"
        output_text.insert(tk.END, display)
        output_text.yview(tk.END)

# Background sniffing function
def sniff_packets():
    sniff(filter="ip", prn=process_packet, store=False, stop_filter=lambda x: not sniffing)

# Start sniffing
def start_sniffing():
    global sniffing, sniffer_thread
    if not sniffing:
        sniffing = True
        sniffer_thread = threading.Thread(target=sniff_packets, daemon=True)
        sniffer_thread.start()
        output_text.insert(tk.END, "Sniffing started...\n")

# Stop sniffing
def stop_sniffing():
    global sniffing
    sniffing = False
    output_text.insert(tk.END, "Sniffing stopped.\n")

# GUI setup
root = tk.Tk()
root.title("Network Sniffer")

frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

start_button = tk.Button(frame, text="Start Sniffing", command=start_sniffing, width=20)
start_button.pack(side=tk.LEFT, padx=5)

stop_button = tk.Button(frame, text="Stop Sniffing", command=stop_sniffing, width=20)
stop_button.pack(side=tk.LEFT, padx=5)

output_text = ScrolledText(root, width=100, height=30)
output_text.pack(padx=10, pady=10)

root.mainloop()

