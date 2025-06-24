📌 Objective
To create a graphical tool that allows users to monitor and inspect IP network traffic in real time. The application captures and displays source and destination IPs, protocol types, and a snippet of packet payloads.

⚙️ Tools & Libraries Used
Python: Programming language.

Tkinter: For creating the GUI.

Scapy: For capturing and parsing network packets.

threading: To run the sniffer without freezing the GUI.

🧱 How It Works
User Interface (Tkinter)

Two buttons: Start Sniffing and Stop Sniffing.

A scrollable text box to display captured packet data in real-time.

Packet Sniffing (Scapy)

Uses scapy.sniff() to listen for IP packets on the network.

Extracts key details:

Source IP

Destination IP

Protocol (ICMP, TCP, UDP, or others)

First 20 bytes of the packet payload

Multithreading

Sniffing runs in a background thread to prevent the GUI from freezing.

A global sniffing flag controls when to start/stop sniffing.

This project is a Python-based network sniffer application with a graphical user interface, designed to capture and analyze 
real-time network traffic. It utilizes the Scapy library for low-level packet inspection and Tkinter for the GUI. The tool displays
essential packet details such as source and destination IP addresses, protocol types (TCP, UDP, ICMP), and a snippet of the payload.
It features start and stop controls for user-managed packet capture, offering a simple yet powerful introduction to network monitoring 
and protocol analysis.

🛰️ Where Do the Source and Destination IPs Come From?
The source (src) and destination (dst) IP addresses are captured directly from the IP headers of packets traveling across the network interface of your computer.

🔍 Here's how it works in detail:
Scapy listens to network traffic using your system's network interface (e.g., Wi-Fi or Ethernet).

Every packet on the network contains a network layer header — typically an IPv4 header in this case.

When a packet is captured, Scapy checks if it contains an IP layer:


if IP in packet:
If so, it extracts the source and destination IPs from the IP header:


ip_layer = packet[IP]
src = ip_layer.src  # Source IP
dst = ip_layer.dst  # Destination IP
📡 What Kind of Traffic Does It Capture?
It captures any IP-based traffic visible to your machine's network interface, which includes:

Packets sent by your computer (e.g., browsing the web).

Packets received by your computer (e.g., incoming data from servers).

Possibly, local network traffic between other devices (if your network supports promiscuous mode).

🧪 Example
Suppose your machine sends a request to Google DNS (8.8.8.8). The sniffer might capture:

Src: 192.168.1.5 | Dst: 8.8.8.8 | Proto: UDP | Payload: ...

And the response:

Src: 8.8.8.8 | Dst: 192.168.1.5 | Proto: UDP | Payload: ...


Need to Install: pip install scapy

Run Command: python network_sniffer.py
