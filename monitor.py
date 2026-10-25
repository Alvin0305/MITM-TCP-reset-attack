import threading
import time

from scapy.all import IP, TCP, sniff

from util import CLIENT_IP, SERVER_IP, SERVER_PORT, STABILITY_TIME, print_headers


class NetworkMonitor:
    def __init__(self):
        self.client_port = None

        self.client_next_seq = 0
        self.client_expected_server_seq = 0
        self.server_next_seq = 0
        self.server_expected_client_seq = 0

        self.server_syn_seq = None

        self.handshake_complete = False
        self.connection_stable = False

        self.last_packet_time = None

        self.state_lock = threading.Lock()
        self.stabilized_event = threading.Event()

    def packet_handler(self, packet):
        if not packet.haslayer(IP):
            return

        if not packet.haslayer(TCP):
            return

        ip = packet[IP]
        tcp = packet[TCP]

        # if the packet is not from client or server, avoid it
        if not (
            (ip.src == CLIENT_IP and ip.dst == SERVER_IP)
            or (ip.src == SERVER_IP and ip.dst == CLIENT_IP)
        ):
            return

        if ip.src == CLIENT_IP:
            direction = "CLIENT_TO_SERVER"
        else:
            direction = "SERVER_TO_CLIENT"

        # when the first SYN comes from the client, set the client_port variable
        if (
            direction == "CLIENT_TO_SERVER"
            and str(tcp.flags) == "S"
            and self.client_port is None
        ):
            self.client_port = tcp.sport
            print(
                f"\n[+] SSH connection detected: {CLIENT_IP}:{self.client_port} -> {SERVER_IP}:{SERVER_PORT}"
            )

        # if a packet is not from the SSH connection between the server and client, avoid it
        if self.client_port is not None:
            valid_connection = (
                ip.src == CLIENT_IP
                and tcp.sport == self.client_port
                and ip.dst == SERVER_IP
                and tcp.dport == SERVER_PORT
            ) or (
                ip.src == SERVER_IP
                and tcp.sport == SERVER_PORT
                and ip.dst == CLIENT_IP
                and tcp.dport == self.client_port
            )

            if not valid_connection:
                return

        payload_size = len(bytes(tcp.payload))

        syn = 1 if "S" in tcp.flags else 0
        fin = 1 if "F" in tcp.flags else 0

        next_seq = tcp.seq + payload_size + syn + fin

        # when the server sends SYN-ACK, save it so that, when the ACK comes, we can compare the seq(SYN_ACK) + 1 == seq(ACK)
        if direction == "SERVER_TO_CLIENT" and str(tcp.flags) == "SA":
            self.server_syn_seq = tcp.seq

        # when the last ACK of the 3 way handshake comes, mark the handshake as complete and set the time
        if (
            direction == "CLIENT_TO_SERVER"
            and str(tcp.flags) == "A"
            and payload_size == 0
            and self.server_syn_seq is not None
            and tcp.ack == self.server_syn_seq + 1
            and not self.handshake_complete
        ):
            with self.state_lock:
                self.handshake_complete = True
                self.last_packet_time = time.time()

            print("[+] TCP connection established.")
            print("[+] Starting 30-second inactivity timer.")

        # calculate the next sequence number
        if direction == "CLIENT_TO_SERVER":
            self.client_next_seq = max(self.client_next_seq, next_seq)
            self.client_expected_server_seq = max(
                self.client_expected_server_seq, tcp.ack
            )
        else:
            self.server_next_seq = max(self.server_next_seq, next_seq)
            self.server_expected_client_seq = max(
                self.server_expected_client_seq, tcp.ack
            )

        # For each packet, reset the timer
        if self.handshake_complete:
            with self.state_lock:
                self.last_packet_time = time.time()

        print(
            f"{ip.src}:{tcp.sport} -> "
            f"{ip.dst}:{tcp.dport}"
            f" | Flags: {tcp.flags}"
            f" | SEQ: {tcp.seq}"
            f" | ACK: {tcp.ack}"
            f" | Payload Size: {payload_size}"
            f" | Next Seq: {next_seq}"
            f" | Direction: {direction}"
        )

        print(
            f"Current state:\n"
            f"  Client->Server: SEQ={self.client_next_seq}, "
            f"ACK={self.client_expected_server_seq}\n"
            f"  Server->Client: SEQ={self.server_next_seq}, "
            f"ACK={self.server_expected_client_seq}"
        )

        if payload_size == 0:
            print_headers(ip, tcp)

    def stability_monitor(self):
        while True:
            time.sleep(1)
            with self.state_lock:
                if not self.handshake_complete:
                    continue

                if self.connection_stable:
                    return

                if self.last_packet_time is None:
                    continue

                inactive_time = time.time() - self.last_packet_time

            # when timeouts, trigger the attack by setting the connection stable flag and setting the event
            print(f"[STABILITY] Inactive for {inactive_time:.1f} seconds")
            if inactive_time >= STABILITY_TIME:
                with self.state_lock:
                    self.connection_stable = True
                print("\n[+] CONNECTION STABILIZED")
                print("[+] No packets transferred for {STABILITY_TIME} seconds.")

                self.stabilized_event.set()
                return

    def start(self):
        packet_thread = threading.Thread(
            target=lambda: sniff(filter="tcp", prn=self.packet_handler, store=False),
            daemon=True,
        )

        stability_thread = threading.Thread(target=self.stability_monitor, daemon=True)

        packet_thread.start()
        stability_thread.start()

    def wait_for_stability(self):
        self.stabilized_event.wait()

    def get_state(self, target):
        with self.state_lock:
            if target == "SERVER":
                return {
                    "source_ip": CLIENT_IP,
                    "source_port": self.client_port,
                    "destination_ip": SERVER_IP,
                    "destination_port": SERVER_PORT,
                    "seq": self.server_expected_client_seq,
                    "ack": self.server_next_seq,
                }

            return {
                "source_ip": SERVER_IP,
                "source_port": SERVER_PORT,
                "destination_ip": CLIENT_IP,
                "destination_port": self.client_port,
                "seq": self.client_expected_server_seq,
                "ack": self.client_next_seq,
            }
