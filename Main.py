import re
import sys
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QApplication, QMainWindow, QDialog, QVBoxLayout, QMessageBox, QFileDialog, QLineEdit
from PyQt5 import QtCore, QtGui
from threading import Thread, Event, Lock
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.tls import *
import time
from scapy.contrib.igmp import IGMP
import binascii

TCP_FLAGS = {'S': 'SYN', 'A': 'ACK', 'F': 'FIN', 'P': 'PSH', 'R': 'RST', 'U': 'URG'}
DHCP_TYPES = {1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline', 5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Decline'}
IGMP_TYPES = {
    1: {17: "Membership Query", 18: "Membership Report"},
    2: {17: "Membership Query", 22: "Membership Report", 23: "Leave Group"},
    3: {17: "Membership Query, general", 18: "Membership Query, group-specific",
        19: "Membership Reduction Message", 34: "Membership Report (Join)",
        35: "Membership Report (Leave)"}}
TLS_VERSIONS = {b'\x03\x01': '1', b'\x03\x02': '1.1', b'\x03\x03': '1.2', b'\x03\x04': '1.3'}
TLS_TYPES = {20: 'Change Cipher Spec', 21: 'Alert', 22: 'Handshake', 23: 'Application Data', 24: 'Heartbeat'}


class MyWindow(QMainWindow):
    def __init__(self):
        super(MyWindow, self).__init__()
        self.setGeometry(100, 100, 1000, 625)
        self.setWindowTitle("Sniffer")
        self.initUI()
        self.pdws = []
        self.setMinimumWidth(1000)
        self.setMinimumHeight(625)

    def initUI(self):
        # Start recording button
        self.startRecord = QtWidgets.QPushButton(self)
        self.startRecord.setObjectName("StartRecord")
        self.startRecord.setGeometry(QtCore.QRect(170, 20, 23, 23))
        self.startRecord.setStyleSheet(u"background-color:rgb(9, 195, 9)")
        self.startRecord.clicked.connect(self.start_sniffing)
        self.start_recording_again = 0
        self.save_file_name = ""

        # Stop recording button
        self.stopRecord = QtWidgets.QPushButton(self)
        self.stopRecord.setObjectName("StopRecord")
        self.stopRecord.setGeometry(QtCore.QRect(210, 20, 23, 23))
        self.stopRecord.setStyleSheet(u"background-color:rgb(125, 112, 112)")
        self.stopRecord.clicked.connect(self.send_stop_packet)

        # Save button
        self.saveButton = QtWidgets.QPushButton(self)
        self.saveButton.setObjectName("SaveButton")
        self.saveButton.setGeometry(QtCore.QRect(80, 17, 60, 30))
        self.saveButton.setStyleSheet(u"background-color:transparent;")
        font = QtGui.QFont("Circular", 10)
        self.saveButton.setFont(font)
        self.saveButton.clicked.connect(self.save_recording)
        save_icon = QtGui.QIcon('Images/save_icon.png')
        self.saveButton.setIcon(save_icon)
        self.saveButton.setIconSize(save_icon.actualSize(QtCore.QSize(32, 32)))

        # Import Button
        self.importButton = QtWidgets.QPushButton(self)
        self.importButton.setObjectName("ImportButton")
        self.importButton.setGeometry(QtCore.QRect(10, 12, 70, 40))
        self.importButton.setStyleSheet(u"background-color:transparent")
        font = QtGui.QFont("Circular", 10)
        self.importButton.setFont(font)
        self.importButton.clicked.connect(self.import_recording)
        import_icon = QtGui.QIcon('Images/import_icon.png')
        self.importButton.setIcon(import_icon)
        self.importButton.setIconSize(import_icon.actualSize(QtCore.QSize(35, 35)))

        # View filter search bar
        self.search_bar = QLineEdit(self)
        self.search_bar.setGeometry(QtCore.QRect(10, 140, 230, 30))
        self.search_bar.setStyleSheet("border-radius: 15px; padding: 5px;background-color:rgb(92, 94, 130)")
        self.search_bar.setPlaceholderText("Filter by protocol...")
        self.search_bar.setVisible(True)
        self.search_bar.returnPressed.connect(self.handle_filter_search)

        # table
        self.tableWidget = QtWidgets.QTableWidget(self)
        self.tableWidget.setStyleSheet(
            "QTableWidget { background-color: #313242; border: 1px solid #313242; }"
            "QTableCornerButton::section { background-color: #5c5e82; }"
        )
        self.tableWidget.setColumnCount(5)
        self.tableWidget.setRowCount(0)

        column_names = ["#", "Protocol", "Source", "Destination", "Summary"]
        self.tableWidget.setHorizontalHeaderLabels(column_names)

        self.font_summary = self.font = QtGui.QFont("Circular")
        self.font.setPointSize(11)

        # Set font for header
        self.font = QtGui.QFont("Circular")
        self.font.setPointSize(13)
        self.tableWidget.horizontalHeader().setFont(self.font)

        header_stylesheet = "QHeaderView::section { background-color: #5c5e82; }"
        self.tableWidget.horizontalHeader().setStyleSheet(header_stylesheet)
        self.tableWidget.verticalHeader().setStyleSheet(header_stylesheet)

        self.tableWidget.itemDoubleClicked.connect(self.open_packet_details)
        self.tableWidget.horizontalHeader().sectionClicked.connect(self.header_clicked)
        self.tableWidget.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        self.tableWidget.verticalHeader().setVisible(False)

        self.tableWidget.setColumnWidth(0, 100)
        self.tableWidget.setColumnWidth(1, 100)
        self.tableWidget.setColumnWidth(2, 267)
        self.tableWidget.setColumnWidth(3, 267)
        self.tableWidget.horizontalHeader().setSectionResizeMode(4, QtWidgets.QHeaderView.Stretch)

        # Set up the table widget's properties
        self.tableWidget.setObjectName(u"tableWidget")
        self.tableWidget.setGeometry(QtCore.QRect(0, 180, 1001, 380))
        self.tableWidget.horizontalHeader().setCascadingSectionResizes(False)
        self.tableWidget.setColumnWidth(0, 100)
        self.tableWidget.setColumnWidth(0, 200)

        for i in range(2, 5):
            self.tableWidget.setColumnWidth(i, 237)

        # Align column titles to the left
        for i in range(len(column_names)):
            item = QtWidgets.QTableWidgetItem(column_names[i])
            item.setTextAlignment(QtCore.Qt.AlignLeft)
            self.tableWidget.setHorizontalHeaderItem(i, item)

    def add_to_table(self, packet):
        row_number = self.tableWidget.rowCount()
        self.tableWidget.insertRow(row_number)
        self.tableWidget.setRowHeight(row_number, 50)

        number = str(packet.number)
        protocol = packet.protocol
        src = packet.src
        dst = packet.dst
        summary = packet.summary

        item_number = QtWidgets.QTableWidgetItem(number)
        item_number.setForeground(QtGui.QColor(QtCore.Qt.white))  # Change text color to white
        item_number.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable)  # Make item read-only
        item_number.setFont(self.font)
        self.tableWidget.setItem(row_number, 0, item_number)

        item_protocol = QtWidgets.QTableWidgetItem(protocol)
        item_protocol.setForeground(QtGui.QColor(QtCore.Qt.white))  # Change text color to white
        item_protocol.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable)  # Make item read-only
        item_protocol.setFont(self.font)
        self.tableWidget.setItem(row_number, 1, item_protocol)

        item_src = QtWidgets.QTableWidgetItem(src)
        item_src.setForeground(QtGui.QColor(QtCore.Qt.white))  # Change text color to white
        item_src.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable)  # Make item read-only
        item_src.setFont(self.font)
        self.tableWidget.setItem(row_number, 2, item_src)

        item_dst = QtWidgets.QTableWidgetItem(dst)
        item_dst.setForeground(QtGui.QColor(QtCore.Qt.white))  # Change text color to white
        item_dst.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable)  # Make item read-only
        item_dst.setFont(self.font)
        self.tableWidget.setItem(row_number, 3, item_dst)
        if (self.tableWidget.verticalScrollBar().maximum() - self.tableWidget.verticalScrollBar().value() <= 7):
            self.tableWidget.verticalScrollBar().setValue(self.tableWidget.verticalScrollBar().maximum())

        item_summary = QtWidgets.QTableWidgetItem(summary)
        item_summary.setForeground(QtGui.QColor(QtCore.Qt.white))  # Change text color to white
        item_summary.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable)  # Make item read-only
        item_summary.setFont(self.font_summary)
        self.tableWidget.setItem(row_number, 4, item_summary)
        if (self.tableWidget.verticalScrollBar().maximum() - self.tableWidget.verticalScrollBar().value() <= 7):
            self.tableWidget.verticalScrollBar().setValue(self.tableWidget.verticalScrollBar().maximum())

    def resizeEvent(self, event: QtGui.QResizeEvent) -> None:
        super().resizeEvent(event)
        width = event.size().width()
        height = event.size().height()
        self.adjust_table_size(width, height)
        self.search_bar.setFixedWidth(width - 20)

    def adjust_table_size(self, width, height):
        self.tableWidget.setColumnWidth(0, 100)
        self.tableWidget.setColumnWidth(1, 100)
        self.tableWidget.setColumnWidth(2, 267)
        self.tableWidget.setColumnWidth(3, 267)
        self.tableWidget.setGeometry(QtCore.QRect(0, 180, width, height - 180))

    def change_record_buttons_color(self, is_pressed):
        start_color = "(9, 195, 9)" if not is_pressed else "(109, 125, 109)"
        start_string = "background-color:rgb" + start_color
        self.startRecord.setStyleSheet(start_string)
        stop_color = "(255, 19, 19)" if is_pressed else "(125, 112, 112)"
        stop_string = "background-color:rgb" + stop_color
        self.stopRecord.setStyleSheet(stop_string)

    def open_packet_details(self, item):
        packet_number = self.tableWidget.item(item.row(), 0)
        packet_number = int(packet_number.text())
        layers_dict = self.packets[packet_number - 1].get_layer_info()
        pd = self.packets[packet_number - 1].info.show(dump=True)
        pdw = PacketDetailsWindow(layers_dict, packet_number)
        self.pdws.append(pdw)
        pdw.setStyleSheet("background-color: #313242;")
        pdw.show()

    def show_popup(self):
        msg = QMessageBox()
        msg.setWindowTitle("Recording not saved!")
        msg.setText("Would you like to save this recording before starting a new one?")
        msg.setIcon(QMessageBox.Question)
        msg.setStandardButtons(QMessageBox.Save | QMessageBox.Ignore | QMessageBox.Cancel)
        msg.setDefaultButton(QMessageBox.Save)
        msg.buttonClicked.connect(self.popup_button)
        msg.rejected.connect(self.popup_rejected)
        x = msg.exec_()

    def popup_button(self, i):
        if i.text() == "Save":
            self.start_recording_again = 1
            self.file_save_menu()

        if i.text() == "Ignore":
            self.start_recording_again = 2
        if i.text() == "Cancel":
            self.start_recording_again = 0

    def popup_rejected(self):
        self.start_recording_again = 0

    def file_save_menu(self):
        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
        filename = QFileDialog.getSaveFileName(self, 'Save Recording', os.path.join(desktop_path),
                                               "PCAP files (*.pcap)")
        self.save_file_name = filename[0]

    def file_import_menu(self):
        file_filter = "PCAP files (*.pcap)"
        file_name, _ = QFileDialog.getOpenFileName(filter=file_filter)
        return file_name

    def clear_table(self):
        self.tableWidget.clearContents()
        self.tableWidget.setRowCount(0)

    def header_clicked(self, col_num):
        if col_num == 4:  # if parameter is summary, which is not sortable
            return
        parameter_list = ["number", "protocol", "src", "dst"]
        parameter = parameter_list[col_num]
        if self.parameters_list[0] == parameter:
            self.parameters_list[1] = not self.parameters_list[1]
        else:
            self.parameters_list[0] = parameter
            self.parameters_list[1] = False
        self.sort_and_show()

    def handle_filter_search(self):
        search_string = self.search_bar.text()
        search_string = search_string.replace(' ', '')
        search_list = search_string.split('or')
        self.find_matching_packets(search_list)


class PacketDetailsWindow(QtWidgets.QWidget):
    def __init__(self, layers_dict, number):
        super().__init__()
        self.layers_dict = layers_dict
        self.number = number
        self.initUI()

    def initUI(self):
        self.setWindowTitle(f'Packet {self.number}')
        self.setGeometry(400, 100, 500, 400)
        self.buttons = []
        num1 = int((500 / len(self.layers_dict.keys())))
        num2 = num1 * -1
        for key in self.layers_dict.keys():
            button = QtWidgets.QPushButton(self)
            num2 += num1
            button.setGeometry(QtCore.QRect(num2, 5, num1, 30))
            button.setStyleSheet("background-color: #5c5e82;")
            button.setText(key)
            # Use a default argument in lambda to capture the current value of key
            button.clicked.connect(lambda checked, key=key: self.layer_clicked(self.layers_dict[key]))
            self.buttons.append(button)

    def layer_clicked(self, info):
        fields = QVBoxLayout()
        rows = info.split('\n')
        for row in rows:
            print(row)





class Packet:
    def __init__(self, count, packet_body):
        self.number = count
        self.info = packet_body
        self.length = self.__get_length()
        self.protocol = self.__get_protocol()
        self.src, self.dst = self.__get_ends()
        self.summary = ""
        self.__configure_get_summary()

    def __get_length(self):
        return len(self.info)

    def __get_protocol(self):
        if self.info.haslayer(TCP):
            if self.info.haslayer(Raw):
                raw_data = self.info.getlayer(Raw).load
                version = raw_data[1:3]
                if version in TLS_VERSIONS.keys():
                    return "TLSv" + TLS_VERSIONS[version]
        if TCP in self.info and self.info.haslayer(Raw):
            raw_data = self.info[Raw].load.decode('utf-8', 'ignore')
            if "HTTP" in raw_data:
                return "HTTP"
        if UDP in self.info:
            if self.info[UDP].dport == 1900 or self.info[UDP].sport == 1900:
                return "SSDP"
        if ICMP in self.info:
            return "ICMP"
        if IPv6 in self.info:
            if self.info[IPv6].nh == 58:
                return "ICMPv6"
        if "DHCP" in str(self.info):
            if self.info[UDP].sport == 546 or self.info[UDP].sport == 547:
                return "DHCPv6"
            return "DHCP"
        if IP in self.info:
            proto_number = self.info[IP].proto
            if proto_number == 2:
                return "IGMPv2"
            if proto_number == 58:
                return "IGMPv3"
        if UDP in self.info:
            if self.info[UDP].dport == 5353:
                return "MDNS"
        if "DNS" in str(self.info):
            return "DNS"
        if TCP in self.info:
            return "TCP"
        if UDP in self.info:
            return "UDP"
        if IP in self.info or IPv6 in self.info:
            return "UNKNOWN"
        return "ARP"

    def __get_ends(self):
        if IPv6 in self.info:
            return self.info[IPv6].src, self.info[IPv6].dst
        if IP in self.info:
            return self.info[IP].src, self.info[IP].dst
        return self.info.src, self.info.dst if self.info.dst != 'ff:ff:ff:ff:ff:ff' else 'Broadcast'

    def __configure_get_summary(self):
        if self.protocol == "ARP":
            self.__get_summary_arp()
        if self.protocol == "UDP":
            self.__get_summary_udp()
        if self.protocol == "TCP":
            self.__get_summary_tcp()
        if self.protocol == "DNS":
            self.__get_summary_dns()
        if self.protocol == "ICMP":
            self.__get_summary_icmp()
        if self.protocol == "ICMPv6":
            self.__get_summary_icmp6()
        if self.protocol == "MDNS":
            self.__get_summary_mdns()
        if "DHCP" in self.protocol:
            self.__get_summary_dhcp()
        if self.protocol == "SSDP":
            self.__get_summary_ssdp()
        if "IGMP" in self.protocol:
            self.__get_summary_igmp()
        if "TLS" in self.protocol:
            self.__get_summary_tls()
        if self.protocol == "HTTP":
            self.__get_summary_http()

    def __get_summary_arp(self):
        opcode = self.info.op
        summary_string = ""
        if opcode == 1:
            requested_ip = self.info.pdst
            tell_to_ip = self.info.psrc
            summary_string = f"Who has {requested_ip}? Tell {tell_to_ip}"
        if opcode == 2:
            requested_ip_answer = self.info.psrc
            mac_of_ip = self.info.hwsrc
            summary_string = f"{requested_ip_answer} is at {mac_of_ip}"
        self.summary = summary_string

    def __get_summary_udp(self):
        udp_segment = self.info[UDP]
        payload_size = len(udp_segment)
        source_port = udp_segment.sport
        destination_port = udp_segment.dport
        summary_string = f"{source_port} -> {destination_port}, Payload size: {payload_size}"
        self.summary = summary_string

    def __get_summary_tcp(self):
        tcp_segment = self.info[TCP]
        payload_size = len(tcp_segment)
        source_port = tcp_segment.sport
        destination_port = tcp_segment.dport
        flags = tcp_segment.flags
        flags_string_list = []
        for flag in flags:
            flags_string_list.append(TCP_FLAGS[flag])
        flags_string = ", ".join(flags_string_list)
        summary_string = f"{source_port} -> {destination_port}, [{flags_string}], Payload size: {payload_size} "
        self.summary = summary_string

    def __get_summary_dns(self):
        dns_segment = self.info[DNS]
        summary_string = ""
        if dns_segment.opcode == 0:
            if dns_segment.qr == 0:
                summary_string = "Standard Query"
            else:
                summary_string = "Standard Query Response"
        if dns_segment.opcode == 4:
            summary_string = "Notify"
        if dns_segment.opcode == 5:
            summary_string = "Update"
        is_error = dns_segment.rcode != 0
        if is_error:
            summary_string = "DNS Error"
        self.summary = summary_string

    def __get_summary_icmp(self):
        icmp_segment = self.info[ICMP]
        pattern = r'type {1,}=.{1,}'
        icmp_type_text = re.findall(pattern, icmp_segment.show(dump=True))[0]
        icmp_type_text = icmp_type_text[icmp_type_text.index('=') + 2:]
        icmp_type_text = icmp_type_text.replace('-', ' ')
        icmp_type_text = icmp_type_text.title()
        ip_segment = self.info[IP]
        ttl = ip_segment.ttl
        summary_string = f"{icmp_type_text}, ttl: {ttl}"
        self.summary = summary_string

    def __get_summary_icmp6(self):
        pattern = r'type {1,}=.{1,}'
        icmp6_type_text = re.findall(pattern, self.info.show(dump=True))[1]
        icmp6_type_text = icmp6_type_text[icmp6_type_text.index('=') + 2:]
        self.summary = icmp6_type_text

    def __get_summary_mdns(self):
        summary_string = ""
        if self.info[DNS].qr == 0:
            summary_string = "Query"
        else:
            summary_string = "Query Response"
        self.summary = summary_string

    def __get_summary_dhcp(self):
        summary_string = ""
        if self.info.haslayer(DHCP):
            options = self.info[DHCP].options
            for option in options:
                if option[0] == 'message-type':
                    summary_string = "DHCP " + DHCP_TYPES[option[1]]
        else:
            dhcp6_fields = str(self.info)
            dhcp6_type = dhcp6_fields.split('/')[3]
            dhcp6_type = "DHCPv6 " + dhcp6_type[7:]
            self.summary = dhcp6_type

    def __get_summary_ssdp(self):
        summary_string = ""
        payload = self.info.load.decode('utf-8', 'ignore')
        summary_string = payload.splitlines()[0]
        self.summary = summary_string

    def __get_summary_igmp(self):
        igmp_version = int(self.protocol[-1])
        summary_string = ""
        igmp_type = self.info[IGMP].type
        try:
            summary_string = IGMP_TYPES[igmp_version][igmp_type]
        except Exception:
            summary_string = ""
        self.summary = summary_string

    def __get_summary_tls(self):
        summary_string = ""
        raw_data = self.info.getlayer(Raw).load
        type_field = raw_data[0]
        if type_field in TLS_TYPES.keys():
            summary_string += TLS_TYPES[type_field]
        else:
            print(self.info)
        if type_field == 22:  # handshake
            if raw_data[5] == 1:
                summary_string = "Client Hello"
            else:
                summary_string = "Server Hello"
        self.summary = summary_string

    def __get_summary_http(self):
        http_data = self.info.getlayer(Raw).load.decode('utf-8', 'ignore')
        self.summary = http_data.splitlines()[0]

    def get_layer_info(self):
        layers_dict = {}
        pattern = r'###\[.{1,}]###'
        show = self.info.show(dump=True)
        layers = [x[5:-5] for x in re.findall(pattern, show)]
        parts = re.split(pattern, show)[1:]  # 0 index in None
        layers_dict['Ethernet'] = parts[0]
        layers_dict[layers[1]] = parts[1]
        return layers_dict


class SnifferWindow(MyWindow):
    def __init__(self):
        super().__init__()
        self.is_start_pressed = False
        self.packets = []
        self.recording_type = ''
        self.is_recording_saved = False
        self.stop_recording = False
        self.packet_count = 0
        self.parameters_list = ['a', False]
        self.is_original = True
        self.check = True
        self.filtered_packets = []
        self.filter = None

    def send_stop_packet(self):
        self.stop_recording = True
        self.is_start_pressed = False
        self.check = False
        if not self.is_original:
            self.sort_and_show()
        self.change_record_buttons_color(self.is_start_pressed)

    def stopfilter(self, x):
        return self.stop_recording

    def sniffing(self):
        scapy.config.sniff_promisc = 0
        sniff(filter="arp or tcp or udp or icmp or icmp6", prn=self.process_packet,
              stop_filter=self.stopfilter)

    def process_packet(self, new_packet):
        new_packet = self.register_packet(new_packet)
        self.add_packet(new_packet)

    def register_packet(self, new_packet):
        self.packet_count += 1
        new_packet = Packet(self.packet_count, new_packet)
        self.packets.append(new_packet)
        return new_packet

    def add_packet(self, new_packet):
        if self.filter is None:
            self.add_to_table(new_packet)
        else:
            self.add_packet_if_matching(new_packet)

    def start_sniffing(self):
        if self.is_start_pressed is False:
            if self.packets != [] and self.is_recording_saved is False and self.recording_type == 'live':
                self.show_popup()
                if self.start_recording_again == 0 or self.save_file_name != "":
                    return
                if self.start_recording_again == 1:
                    self.save_recording_to_file()
            self.packet_count = 0
            self.stop_recording = False
            self.clear_packets()
            self.is_original = True  # reset sort parameters
            self.parameters_list = ['a', False]  # reset sort parameters
            self.is_start_pressed = True
            sniff_thread = Thread(target=self.sniffing)
            sniff_thread.start()
            self.change_record_buttons_color(self.is_start_pressed)
            self.recording_type = 'live'
            self.is_recording_saved = False

    def clear_packets(self):
        self.packets = []
        self.clear_table()

    def save_recording(self):
        if not self.is_start_pressed and self.packets != []:
            self.file_save_menu()
            if self.save_file_name == "":
                return
            self.save_recording_to_file()
            self.is_recording_saved = True

    def save_recording_to_file(self):
        self.reset_packet_order()
        save_list = [x.info for x in self.packets]
        wrpcap(self.save_file_name, save_list)

    def import_recording(self):
        if self.is_start_pressed:
            return
        if not self.is_recording_saved and self.packets != [] and self.recording_type == 'live':
            self.show_popup()
            if (self.start_recording_again == 0 or self.save_file_name == "") and self.start_recording_again != 2:
                return
            if self.start_recording_again == 1:
                self.save_recording_to_file()
        file_name = self.file_import_menu()
        if '.pcap' not in file_name:
            return
        self.clear_packets()
        scapy_cap = rdpcap(file_name)
        self.packet_count = 0
        for packet in scapy_cap:
            self.packet_count += 1
            packet = Packet(self.packet_count, packet)
            self.add_to_table(packet)
            self.packets.append(packet)
        self.recording_type = 'import'

    def sort_and_show(self):
        if self.parameters_list[0] == 'a':
            return
        self.sort_by_parameter()
        self.show_sorted_packets()
        self.is_original = self.parameters_list[0] == "number" and self.parameters_list[1] is False

    def sort_by_parameter(self):
        if not self.filtered_packets:
            self.packets = sorted(self.packets, key=lambda obj: getattr(obj, self.parameters_list[0]),
                                  reverse=self.parameters_list[1])
        else:
            self.filtered_packets = sorted(self.filtered_packets, key=lambda obj: getattr(obj, self.parameters_list[0]),
                                           reverse=self.parameters_list[1])

    def show_sorted_packets(self):
        self.clear_table()
        if not self.filtered_packets:
            for packet in self.packets:
                self.add_to_table(packet)
        else:
            for packet in self.filtered_packets:
                self.add_to_table(packet)

    def reset_packet_order(self):
        temp1 = self.parameters_list[0]
        temp2 = self.parameters_list[1]
        self.parameters_list = ["number", False]
        self.sort_by_parameter()
        self.parameters_list = [temp1, temp2]

    def find_matching_packets(self, search_list: list):
        if search_list == ['']:
            self.filter = None
            self.filtered_packets = []
            self.restore_packets()
            return
        self.filter = search_list
        self.clear_table()
        for packet in self.packets:
            self.add_packet_if_matching(packet)

    def add_packet_if_matching(self, packet):
        if packet.protocol.lower() in self.filter:
            self.filtered_packets.append(packet)
            self.add_to_table(packet)

    def restore_packets(self):
        self.clear_table()
        for packet in self.packets:
            self.add_to_table(packet)


def window():
    # set window and window properties
    app = QApplication(sys.argv)
    win = SnifferWindow()
    win.setStyleSheet("background-color: #1d1e29;")
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    window()
