CLIENT_IP = "192.168.2.2"
SERVER_IP = "192.168.2.3"

SERVER_PORT = 22

STABILITY_TIME = 30


def print_headers(ip, tcp):
    print("\n========== IP HEADER ==========")
    print(f"Version          : {ip.version}")
    print(f"IHL              : {ip.ihl}")
    print(f"TOS              : {ip.tos}")
    print(f"Total Length     : {ip.len}")
    print(f"Identification   : {ip.id}")
    print(f"Flags            : {ip.flags}")
    print(f"Fragment Offset  : {ip.frag}")
    print(f"TTL              : {ip.ttl}")
    print(f"Protocol         : {ip.proto}")
    print(f"Checksum         : {ip.chksum}")
    print(f"Source           : {ip.src}")
    print(f"Destination      : {ip.dst}")

    print("\n========== TCP HEADER ==========")
    print(f"Source Port      : {tcp.sport}")
    print(f"Destination Port : {tcp.dport}")
    print(f"Sequence Number  : {tcp.seq}")
    print(f"ACK Number       : {tcp.ack}")
    print(f"Data Offset      : {tcp.dataofs}")
    print(f"Reserved         : {tcp.reserved}")
    print(f"Flags            : {tcp.flags}")
    print(f"Window           : {tcp.window}")
    print(f"Checksum         : {tcp.chksum}")
    print(f"Urgent Pointer   : {tcp.urgptr}")
    print(f"Options          : {tcp.options}")
    print("================================\n")
