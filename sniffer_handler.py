from PyQt5 import QtWidgets, QtCore
from scapy.utils import hexdump
from scapy.arch.windows import get_windows_if_list



from sniffer import Sniffer

ProtocalMap = {
    "Default": "",
    "HTTP": "tcp port 80",
    "HTTPS": "tcp port 443",
    "TCP": "tcp",
    "UDP": "udp",
    "ICMP": "icmp",
    "IPv6": "ip6"
}

class SnifferHandler:

    def __init__(self, ui):
        self.ui = ui
        self.filter = None

    def connect_ui(self):
        # Get Adapter Names
        for adapter in get_windows_if_list():
            self.ui.NICBox.addItem(adapter["name"])
        self.ui.NICBox.setCurrentIndex(0)
        self.ui.FilterBox.addItems(["Default", "HTTP", "HTTPS", "TCP", "UDP", "ICMP", "IPv6"])
        self.ui.FilterBox.setCurrentIndex(0)
        self.ui.PacketTable.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.ui.PacketTable.setHorizontalHeaderLabels(["Protocol", "Src", "Dst", "Length"])
        self.ui.FilterDIY.editingFinished.connect(self.update_filter)
        # Button Connections
        self.ui.BeginButton.clicked.connect(self.begin_sniffing)
        self.ui.StopButton.clicked.connect(self.stop_sniffing)
        self.ui.ResetButton.clicked.connect(self.reset_sniffing)
        self.ui.PacketTable.cellClicked.connect(self.show_packet_info)

    def update_filter(self):
        self.filter = self.ui.FilterDIY.text()


    def begin_sniffing(self):
        if self.filter is None:
            self.filter = ProtocalMap[self.ui.FilterBox.currentText()]
        self.sniffer = Sniffer(self.ui.NICBox.currentText(), self.filter)
        self.sniffer.update_table.connect(self.update_table)
        self.ui.BeginButton.setEnabled(False)
        self.sniffer.start()
        self.ui.StopButton.setEnabled(True)

    def update_table(self, pkt_info, pkt):
        row_cnt = self.ui.PacketTable.rowCount()
        self.ui.PacketTable.insertRow(row_cnt)
        for index, info in enumerate(pkt_info):
            self.ui.PacketTable.setItem(row_cnt, index, QtWidgets.QTableWidgetItem(str(info)))
        self.ui.PacketTable.item(self.ui.PacketTable.rowCount() - 1, 0).setData(QtCore.Qt.UserRole, pkt)
        self.ui.PacketTable.scrollToBottom()

    def stop_sniffing(self):
        if self.sniffer:
            self.sniffer.stop_flag.set()
            self.sniffer.wait()
        self.ui.BeginButton.setEnabled(True)
        self.filter = None

    def reset_sniffing(self):
        self.ui.PacketTable.clearContents()
        self.ui.PacketTable.setRowCount(0)
        self.ui.PacketInfoText.clear()
        self.ui.PacketHexText.clear()

    def show_packet_info(self, row_index):
        pkt = self.ui.PacketTable.item(row_index, 0).data(QtCore.Qt.UserRole)
        if pkt:
            self.ui.PacketInfoText.clear()
            self.ui.PacketHexText.clear()
            self.ui.PacketHexText.append(hexdump(pkt, dump=True))
            self.ui.PacketInfoText.append(pkt.summary())