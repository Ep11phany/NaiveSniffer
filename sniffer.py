
from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import *
import threading
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP


class Sniffer(QThread):
    update_table = pyqtSignal(list, object)

    def __init__(self, iface, filter):
        super().__init__()
        self.iface = iface
        self.filter = filter
        self.stop_flag = threading.Event()

    def run(self):
        sniff(iface=self.iface, prn=self.sniff_analyzer, store=0, stop_filter=lambda _: self.stop_flag.is_set(),filter=self.filter)

    def sniff_analyzer(self, pkt):
        # TODO: Add analysis logic here
        pkt_info = []

        ip = pkt.getlayer(IP)
        if ip:
            pkt_info.append(ip.src)
            pkt_info.append(ip.dst)
            pkt_info.append(str(len(pkt)))
            tcp = pkt.getlayer(TCP)
            if tcp:
                if tcp.dport == 80 or tcp.sport == 80:
                    pkt_info.insert(0, "HTTP")
                elif tcp.dport == 443 or tcp.sport == 443:
                    pkt_info.insert(0, "HTTPS")
                else:
                    pkt_info.insert(0, "TCP")
            else:
                udp = pkt.getlayer(UDP)
                if udp:
                    pkt_info.insert(0, "UDP")
                else:
                    icmp = pkt.getlayer(ICMP)
                    if icmp:
                        pkt_info.insert(0, "ICMP")
                    else:
                        pkt_info.insert(0, "IPv4")
        else:
            arp = pkt.getlayer(ARP)
            if arp:
                pkt_info.extend(["ARP", arp.psrc, arp.pdst, "28"])
            else:
                ipv6 = pkt.getlayer(IPv6)
                if ipv6:
                    pkt_info.append("IPv6")
                    pkt_info.append(ipv6.src)
                    pkt_info.append(ipv6.dst)
                    pkt_info.append(str(len(pkt)))
                else:
                    return

        self.update_table.emit(pkt_info, pkt)
