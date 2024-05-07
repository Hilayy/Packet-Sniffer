import re
import sys
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QApplication, QMainWindow, QDialog, QVBoxLayout, QMessageBox, QFileDialog
from PyQt5 import QtCore, QtGui
from threading import Thread
from scapy.all import *
from scapy.layers.inet import *
import time

class MyWindow(QMainWindow):
    def __init__(self):
        super(MyWindow, self).__init__()
        self.setGeometry(100, 100, 800, 500)
        self.setWindowTitle("Sniffer")
        self.initUI()
        self.pdws = []

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
        self.saveButton.setGeometry(QtCore.QRect(90, 20, 70, 23))
        self.saveButton.setStyleSheet(u"background-color:rgb(92, 94, 130)")
        self.saveButton.setText("Save")
        font = QtGui.QFont("Circular", 10)
        self.saveButton.setFont(font)
        self.saveButton.clicked.connect(self.save_recording)

        # Import Button
        self.importButton = QtWidgets.QPushButton(self)
        self.importButton.setObjectName("ImportButton")
        self.importButton.setGeometry(QtCore.QRect(10, 20, 70, 23))
        self.importButton.setStyleSheet(u"background-color:rgb(92, 94, 130)")
        self.importButton.setText("Import")
        font = QtGui.QFont("Circular", 10)
        self.importButton.setFont(font)
        self.importButton.clicked.connect(self.import_recording)

        self.tableWidget = QtWidgets.QTableWidget(self)
        self.tableWidget.setStyleSheet(
            "QTableWidget { background-color: #313242; border: 1px solid #313242; }"
            "QTableCornerButton::section { background-color: #5c5e82; }"
        )
        self.tableWidget.setColumnCount(4)
        self.tableWidget.setRowCount(0)

        column_names = ["#", "Protocol", "Source", "Destination"]
        self.tableWidget.setHorizontalHeaderLabels(column_names)
        row_names = ["1"]
        self.tableWidget.setVerticalHeaderLabels(row_names)

        # Set font for header
        self.font = QtGui.QFont("Circular")
        self.font.setPointSize(14)
        self.tableWidget.horizontalHeader().setFont(self.font)

        header_stylesheet = "QHeaderView::section { background-color: #5c5e82; }"
        self.tableWidget.horizontalHeader().setStyleSheet(header_stylesheet)
        self.tableWidget.verticalHeader().setStyleSheet(header_stylesheet)

        self.tableWidget.itemDoubleClicked.connect(self.open_packet_details)
        self.tableWidget.horizontalHeader().sectionClicked.connect(self.header_clicked)
        self.tableWidget.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        self.tableWidget.verticalHeader().setVisible(False)

        for i in range(self.tableWidget.columnCount()):
            self.tableWidget.horizontalHeader().setSectionResizeMode(i, QtWidgets.QHeaderView.Stretch)

        # Set up the table widget's properties
        self.tableWidget.setObjectName(u"tableWidget")
        self.tableWidget.setGeometry(QtCore.QRect(0, 180, 801, 380))
        self.tableWidget.horizontalHeader().setCascadingSectionResizes(False)
        self.tableWidget.setColumnWidth(0, 100)
        for i in range(1, 4):
            self.tableWidget.setColumnWidth(i, 233)

        # Align column titles to the left
        for i in range(len(column_names)):
            item = QtWidgets.QTableWidgetItem(column_names[i])
            item.setTextAlignment(QtCore.Qt.AlignLeft)
            self.tableWidget.setHorizontalHeaderItem(i, item)

    def add_to_table(self, number, protocol, src, dst):
        row_number = self.tableWidget.rowCount()
        self.tableWidget.insertRow(row_number)
        self.tableWidget.setRowHeight(row_number, 50)

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

    def resizeEvent(self, event: QtGui.QResizeEvent) -> None:
        super().resizeEvent(event)
        width = event.size().width()
        height = event.size().height()
        self.adjust_table_size(width, height)

    def adjust_table_size(self, width, height):
        for i in range(1, 4):
            self.tableWidget.setColumnWidth(i, int((width - 100) / 3))
        self.tableWidget.setGeometry(QtCore.QRect(0, 180, width, height - 130))

    def change_record_buttons_color(self, is_pressed):
        start_color = "(9, 195, 9)" if not is_pressed else "(109, 125, 109)"
        start_string = "background-color:rgb" + start_color
        self.startRecord.setStyleSheet(start_string)
        stop_color = "(255, 19, 19)" if is_pressed else "(125, 112, 112)"
        stop_string = "background-color:rgb" + stop_color
        self.stopRecord.setStyleSheet(stop_string)

    def open_packet_details(self, item):
        pd = self.packets[item.row()].info.show(dump=True)
        number = self.packets[item.row()].number
        pdw = PacketDetailsWindow(pd, number)
        self.pdws.append(pdw)
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
        parameter_list = ["number", "protocol", "src", "dst"]
        parameter = parameter_list[col_num]
        if self.parameters_list[0] == parameter:
            self.parameters_list[1] = not self.parameters_list[1]
        else:
            self.parameters_list[0] = parameter
            self.parameters_list[1] = False
        self.sort_by_parameter()



class PacketDetailsWindow(QtWidgets.QWidget):
    def __init__(self, text, number):
        super().__init__()
        self.text = str(text)
        self.number = number
        self.initUI()

    def initUI(self):
        self.setWindowTitle(f'Packet {self.number}')
        self.setGeometry(400, 100, 500, 400)
        self.label = QtWidgets.QLabel(self.text, self)



class Packet:
    def __init__(self, count, packet_body):
        self.number = count
        self.info = packet_body
        self.protocol = self.__get_protocol()
        self.src, self.dst = self.__get_ends()

    def __get_protocol(self):
        if "DNS" in str(self.info):
            return "DNS"
        if ICMP in self.info:
            return "ICMP"
        if IPv6 in self.info:
            if self.info[IPv6].nh == 58:
                return "ICMPV6"
        if TCP in self.info:
            return "TCP"
        if UDP in self.info:
            return "UDP"
        return "ARP"

    def __get_ends(self):
        if IPv6 in self.info:
            return self.info[IPv6].src, self.info[IPv6].dst
        if IP in self.info:
            return self.info[IP].src, self.info[IP].dst
        return self.info.src, self.info.dst if self.info.dst != 'ff:ff:ff:ff:ff:ff' else 'Broadcast'


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

    def send_stop_packet(self):
        self.stop_recording = True
        self.is_start_pressed = False
        self.change_record_buttons_color(self.is_start_pressed)

    def stopfilter(self, x):
        return self.stop_recording

    def sniffing(self):
        sniff(filter=" arp or tcp or udp or icmp or icmp6", prn=self.process_packet,
              stop_filter=self.stopfilter)

    def process_packet(self, packet):
        if True:
            self.packet_count += 1
            packet = Packet(self.packet_count, packet)
            self.packets.append(packet)
            self.add_to_table(str(packet.number), packet.protocol, packet.src, packet.dst)




    def start_sniffing(self):
        if self.is_start_pressed == False:
            if self.packets != [] and self.is_recording_saved is False and self.recording_type == 'live':
                self.show_popup()
                if self.start_recording_again == 0 or self.save_file_name != "":
                    return
                if self.start_recording_again == 1:
                    self.save_recording_to_file()
            self.packet_count = 0
            self.stop_recording = False
            self.clear_packets()
            sniff_thread = Thread(target=self.sniffing)
            sniff_thread.start()
            self.is_start_pressed = True
            self.change_record_buttons_color(self.is_start_pressed)
            self.recording_type = 'live'
            self.is_recording_saved = False

    def clear_packets(self):
        self.packets = []
        self.clear_table()

    def save_recording(self):
        if not self.is_start_pressed:
            self.file_save_menu()
            if self.save_file_name == "":
                return
            self.save_recording_to_file()
            self.is_recording_saved = True

    def save_recording_to_file(self):
        l = [x.info for x in self.packets]
        wrpcap(self.save_file_name, l)

    def import_recording(self):
        if self.is_start_pressed:
            return
        if not self.is_recording_saved and self.packets != [] and self.recording_type == 'live':
            self.show_popup()
            if self.start_recording_again == 0 or self.save_file_name == "":
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
            self.add_to_table(str(packet.number), packet.protocol, packet.src, packet.dst)
            self.packets.append(packet)
        self.recording_type = 'import'

    def sort_by_parameter(self):
        self.packets = sorted(self.packets, key=lambda obj: getattr(obj, self.parameters_list[0]), reverse=self.parameters_list[1])
        self.show_sorted_packets()
        self.is_original = self.parameters_list[0] == "number" and self.parameters_list[1] is False



    def show_sorted_packets(self):
        self.clear_table()
        for packet in self.packets:
            self.add_to_table(str(packet.number), packet.protocol, packet.src, packet.dst)














def window():
    # set window and window properties
    app = QApplication(sys.argv)
    win = SnifferWindow()
    win.setStyleSheet("background-color: #1d1e29;")
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    window()
