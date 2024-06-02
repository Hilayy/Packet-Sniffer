from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QApplication, QMainWindow, QDialog, QVBoxLayout, QMessageBox, QFileDialog, QLineEdit
from PyQt5 import QtCore, QtGui
from PacketDetailsWindow import *
PROTOCOLS = ['arp', 'udp', 'tcp', 'dns', 'icmp', 'icmpv6', 'mdns', 'ssdp', 'igmp', 'tls', 'http']


class Gui(QMainWindow):
    def __init__(self):
        super(Gui, self).__init__()
        self.setGeometry(100, 100, 1000, 625)
        self.setWindowTitle("CableDolphin")
        self.initUI()
        self.pdws = []
        self.setMinimumWidth(1000)
        self.setMinimumHeight(625)
        self.is_search_valid = False
        self.dialog_result = 0
        self.save_file_name = ''
        self.packet_number = -1
        self.search_list = ''
        self.is_start_pressed = False
        self.is_closed = False
        self.temp = 1

    def initUI(self):
        # Start recording button
        self.startRecord = QtWidgets.QPushButton(self)
        self.startRecord.setObjectName("StartRecord")
        self.startRecord.setGeometry(QtCore.QRect(160, 15, 30, 30))
        self.startRecord.setStyleSheet(u"background-color:rgb(9, 195, 9);border-radius: 15px;")

        # Stop recording button
        self.stopRecord = QtWidgets.QPushButton(self)
        self.stopRecord.setObjectName("StopRecord")
        self.stopRecord.setGeometry(QtCore.QRect(210, 15, 30, 30))
        self.stopRecord.setStyleSheet(u"background-color:rgb(125, 112, 112);border-radius: 15px;")

        # Save button
        self.saveButton = QtWidgets.QPushButton(self)
        self.saveButton.setObjectName("SaveButton")
        self.saveButton.setGeometry(QtCore.QRect(80, 17, 60, 30))
        self.saveButton.setStyleSheet(u"background-color:transparent;")
        font = QtGui.QFont("Circular", 10)
        self.saveButton.setFont(font)
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
        import_icon = QtGui.QIcon('Images/import_icon.png')
        self.importButton.setIcon(import_icon)
        self.importButton.setIconSize(import_icon.actualSize(QtCore.QSize(35, 35)))

        # View filter search bar
        self.search_bar = QLineEdit(self)
        self.search_bar.setGeometry(QtCore.QRect(10, 140, 230, 30))
        self.search_bar.setStyleSheet("border-radius: 15px; padding: 5px;background-color:rgb(92, 94, 130)")
        self.search_bar.setPlaceholderText("Filter by protocol...")
        self.search_bar.setVisible(True)

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

        self.tableWidget.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        self.tableWidget.verticalHeader().setVisible(False)

        self.tableWidget.setColumnWidth(0, 100)
        self.tableWidget.setColumnWidth(1, 100)
        self.tableWidget.setColumnWidth(2, 267)
        self.tableWidget.setColumnWidth(3, 267)
        self.tableWidget.horizontalHeader().setSectionResizeMode(4, QtWidgets.QHeaderView.Stretch)
        stylesheet = """
            QWidget{ background-color: #313242 } 
            QScrollBar{ background-color: none } 
            """
        self.tableWidget.verticalScrollBar().setStyleSheet(stylesheet)

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
        self.is_start_pressed = is_pressed
        start_color = "(9, 195, 9)" if not is_pressed else "(109, 125, 109)"
        self.startRecord.setStyleSheet(f"background-color:rgb{start_color};border-radius: 15px;")
        stop_color = "(255, 19, 19)" if is_pressed else "(125, 112, 112)"
        self.stopRecord.setStyleSheet(f"background-color:rgb{stop_color};border-radius: 15px;")

    def open_packet_details(self, item, packets):
        packet_number = self.tableWidget.item(item.row(), 0)
        packet_number = int(packet_number.text())
        layers_dict = packets[packet_number - 1].get_layer_info()
        pd = packets[packet_number - 1].info.show(dump=True)
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
        return self.dialog_result

    def popup_button(self, i):
        if i.text() == "Save":
            self.file_save_menu()
            self.dialog_result = 1

        if i.text() == "Ignore":
            self.dialog_result = 2
        if i.text() == "Cancel":
            self.dialog_result = 0

    def popup_rejected(self):
        self.dialog_result = 0

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

    def check_valid_search_term(self):
        search_string = self.search_bar.text()
        if all([x == ' ' or x == '' for x in search_string]):
            self.reset_search_bar()
            return
        if not all([x.islower() or x.isnumeric() or x == ' ' for x in search_string]):
            self.handle_invalid_search_term()
            return
        search_string = search_string.replace(' ', '')
        search_list = search_string.split('or')
        if not all([x in PROTOCOLS for x in search_list]):
            self.handle_invalid_search_term()
            return
        self.handle_valid_search_term()

    def handle_invalid_search_term(self):
        self.is_search_valid = False
        self.search_bar.setStyleSheet("border-radius: 15px; padding: 5px;background-color:#ff2929;")

    def handle_valid_search_term(self):
        self.is_search_valid = True
        self.search_bar.setStyleSheet("border-radius: 15px; padding: 5px;background-color:#37f05c")

    def reset_search_bar(self):
        self.is_search_valid = True
        self.search_bar.setStyleSheet("border-radius: 15px; padding: 5px;background-color:rgb(92, 94, 130)")

    def closeEvent(self, event):
        if self.is_start_pressed:
            dialog = QDialog(self)
            msgBox = QMessageBox(dialog)
            msgBox.setWindowTitle("Quitting?")
            msgBox.setText("A recording is currently live, are you sure you want to exit the application?")
            reply = msgBox.question(self, 'Quitting?', 'A recording is currently live, are you sure you want to '
                                                       'exit the application?',
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.is_closed = True
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()
        print(1)
