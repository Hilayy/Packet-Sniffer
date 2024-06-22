from PyQt5 import QtWidgets
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import QApplication, QMainWindow, QDialog, QVBoxLayout, QMessageBox, QFileDialog, QLineEdit, \
    QLabel, QWidget, QPushButton, QStackedWidget, QHBoxLayout
from PyQt5 import QtCore, QtGui
import sys
import os
from PacketDetailsWindow import *
from DBClient import DBClient

PROTOCOLS = ['arp', 'udp', 'tcp', 'dns', 'icmp', 'icmpv6', 'mdns', 'ssdp', 'igmp', 'tls', 'http']
THEMES = [['#1d1e29', '#313242', '#5c5e82'],
          ['#c1e2db', '#9fc7d4', '#78a6b4'],
          ['#ffecd1', '#ffb085', '#e28743'],
          ['#d3e4cd', '#a3cfa7', '#789e80'],
          ['#e9e7fd', '#c4b8ea', '#8b82d1']
          ]


def get_themes_index():
    with open('Users Theme.txt', 'r') as file:
        line = file.readline()
        ti = int(line[3:])
        if ti == 5:
            ti = 0
        return ti


class LoginWindow(QDialog):
    def __init__(self):
        super(LoginWindow, self).__init__()
        self.setWindowTitle("Login")
        self.setWindowIcon(QtGui.QIcon('Images/dolphin.png'))
        self.setGeometry(200, 200, 400, 200)
        self.setMaximumSize(400, 200)
        self.themes_index = get_themes_index()
        self.client = DBClient()

        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)

        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)

        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)

        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.login)
        layout.addWidget(self.login_button)

        self.signup_button = QPushButton("Sign Up")
        self.signup_button.clicked.connect(self.signup)
        layout.addWidget(self.signup_button)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.login_button)
        button_layout.addWidget(self.signup_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {THEMES[self.themes_index][1]};
            }}
            QLabel {{
                color: white;
            }}
            QLineEdit {{
                background-color: {THEMES[self.themes_index][2]};
                color: white;
                border-radius: 5px;
                padding: 5px;
            }}
            QPushButton {{
                background-color: #37f05c;
                color: white;
                border-radius: 5px;
                padding: 5px;
            }}
            QPushButton:hover {{
                background-color: #45b86c;
            }}
        """)

    def login(self):

        username = self.username_input.text()
        password = self.password_input.text()
        result = self.client.ask_login(username, password)
        if result is True:
            self.accept()
        else:
            QMessageBox.warning(self, "Login Failed", "Invalid username or password.")

    def signup(self):
        username = self.username_input.text()
        password = self.password_input.text()
        result = self.client.ask_signup(username, password)
        if result is True:
            self.accept()
        if result is False:
            QMessageBox.warning(self, "Signup Failed", "Username already exists")
        if result is None:
            QMessageBox.warning(self, "Signup Failed", "Password must contain the following:\n-At least 8 characters"
                                                       "\n-At least 1 Uppercase letter\n-At least 1 digit")






class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.login_window = LoginWindow()
        if self.login_window.exec_() == QDialog.Accepted:
            self.themes_index = get_themes_index()
            self.initUI()
        self.setWindowIcon(QtGui.QIcon('Images/dolphin.png'))
        self.setGeometry(100, 100, 1000, 625)
        self.setWindowTitle("CableDolphin")
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


    def set_themes_index(self, ti):
        with open('Users Theme.txt', 'w') as file:
            new_line = f'ti={ti}'
            file.write(new_line + '\n')


    def initUI(self):
        self.setStyleSheet(f"background-color: {THEMES[self.themes_index][0]};")
        # Start recording button
        self.start_record = QtWidgets.QPushButton(self)
        self.start_record.setObjectName("StartRecord")
        self.start_record.setGeometry(QtCore.QRect(160, 15, 30, 30))
        self.start_record.setStyleSheet(u"background-color:rgb(9, 195, 9);border-radius: 15px;")

        # Stop recording button
        self.stop_record = QtWidgets.QPushButton(self)
        self.stop_record.setObjectName("StopRecord")
        self.stop_record.setGeometry(QtCore.QRect(210, 15, 30, 30))
        self.stop_record.setStyleSheet(u"background-color:rgb(125, 112, 112);border-radius: 15px;")

        # Save button
        self.save_button = QtWidgets.QPushButton(self)
        self.save_button.setObjectName("SaveButton")
        self.save_button.setGeometry(QtCore.QRect(80, 17, 60, 30))
        self.save_button.setStyleSheet(u"background-color:transparent;")
        font = QtGui.QFont("Circular", 10)
        self.save_button.setFont(font)
        save_icon = QtGui.QIcon('Images/save_icon.png')
        self.save_button.setIcon(save_icon)
        self.save_button.setIconSize(save_icon.actualSize(QtCore.QSize(32, 32)))

        # Import Button
        self.import_button = QtWidgets.QPushButton(self)
        self.import_button.setObjectName("ImportButton")
        self.import_button.setGeometry(QtCore.QRect(10, 10, 70, 40))
        self.import_button.setStyleSheet(u"background-color:transparent")
        font = QtGui.QFont("Circular", 10)
        self.import_button.setFont(font)
        import_icon = QtGui.QIcon('Images/import_icon.png')
        self.import_button.setIcon(import_icon)
        self.import_button.setIconSize(import_icon.actualSize(QtCore.QSize(37, 37)))

        self.theme_button = QtWidgets.QPushButton(self)
        self.theme_button.setObjectName("ThemeButton")
        self.theme_button.setGeometry(QtCore.QRect(935, 10, 70, 40))
        self.theme_button.setStyleSheet(u"background-color:transparent")
        theme_icon = QtGui.QIcon('Images/theme_icon.png')
        self.theme_button.setIcon(theme_icon)
        self.theme_button.setIconSize(import_icon.actualSize(QtCore.QSize(40, 40)))
        self.theme_button.clicked.connect(self.change_theme)

        # View filter search bar
        self.search_bar = QLineEdit(self)
        self.search_bar.setGeometry(QtCore.QRect(10, 140, 230, 30))
        self.search_bar.setStyleSheet(f"border-radius: 15px; padding: 5px;background-color:{THEMES[self.themes_index][2]}")
        self.search_bar.setPlaceholderText("Filter by protocol...")
        self.search_bar.setVisible(True)

        # table
        self.table = QtWidgets.QTableWidget(self)
        self.table.setStyleSheet(
            f"QTableWidget {{ background-color: {THEMES[self.themes_index][1]}; border: 1px solid #313242; }}"

        )
        self.table.setColumnCount(5)
        self.table.setRowCount(0)

        column_names = ["#", "Protocol", "Source", "Destination", "Summary"]
        self.table.setHorizontalHeaderLabels(column_names)

        self.font_summary = self.font = QtGui.QFont("Circular")
        self.font.setPointSize(11)

        # Set font for header
        self.font = QtGui.QFont("Circular")
        self.font.setPointSize(13)
        self.table.horizontalHeader().setFont(self.font)

        header_stylesheet = f"QHeaderView::section {{ background-color: {THEMES[self.themes_index][2]}; }}"
        self.table.horizontalHeader().setStyleSheet(header_stylesheet)
        self.table.verticalHeader().setStyleSheet(header_stylesheet)

        self.table.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        self.table.verticalHeader().setVisible(False)

        self.table.setColumnWidth(0, 100)
        self.table.setColumnWidth(1, 100)
        self.table.setColumnWidth(2, 267)
        self.table.setColumnWidth(3, 267)
        self.table.horizontalHeader().setSectionResizeMode(4, QtWidgets.QHeaderView.Stretch)
        stylesheet = """
            QWidget{ background-color: #313242 } 
            QScrollBar{ background-color: none } 
            """
        self.table.verticalScrollBar().setStyleSheet(stylesheet)

        # Set up the table widget's properties
        self.table.setObjectName(u"tableWidget")
        self.table.setGeometry(QtCore.QRect(0, 180, 1001, 380))
        self.table.horizontalHeader().setCascadingSectionResizes(False)
        self.table.setColumnWidth(0, 100)
        self.table.setColumnWidth(0, 200)

        for i in range(2, 5):
            self.table.setColumnWidth(i, 237)

        # Align column titles to the left
        for i in range(len(column_names)):
            item = QtWidgets.QTableWidgetItem(column_names[i])
            item.setTextAlignment(QtCore.Qt.AlignLeft)
            self.table.setHorizontalHeaderItem(i, item)

    def add_to_table(self, packet):
        row_number = self.table.rowCount()
        self.table.insertRow(row_number)
        self.table.setRowHeight(row_number, 50)

        number = str(packet.number)
        protocol = packet.protocol
        src = packet.src
        dst = packet.dst
        summary = packet.summary

        item_number = QtWidgets.QTableWidgetItem(number)
        item_number.setForeground(QtGui.QColor(QtCore.Qt.white))  # Change text color to white
        item_number.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable)  # Make item read-only
        item_number.setFont(self.font)
        self.table.setItem(row_number, 0, item_number)

        item_protocol = QtWidgets.QTableWidgetItem(protocol)
        item_protocol.setForeground(QtGui.QColor(QtCore.Qt.white))  # Change text color to white
        item_protocol.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable)  # Make item read-only
        item_protocol.setFont(self.font)
        self.table.setItem(row_number, 1, item_protocol)

        item_src = QtWidgets.QTableWidgetItem(src)
        item_src.setForeground(QtGui.QColor(QtCore.Qt.white))  # Change text color to white
        item_src.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable)  # Make item read-only
        item_src.setFont(self.font)
        self.table.setItem(row_number, 2, item_src)

        item_dst = QtWidgets.QTableWidgetItem(dst)
        item_dst.setForeground(QtGui.QColor(QtCore.Qt.white))  # Change text color to white
        item_dst.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable)  # Make item read-only
        item_dst.setFont(self.font)
        self.table.setItem(row_number, 3, item_dst)
        if (self.table.verticalScrollBar().maximum() - self.table.verticalScrollBar().value() <= 7):
            self.table.verticalScrollBar().setValue(self.table.verticalScrollBar().maximum())

        item_summary = QtWidgets.QTableWidgetItem(summary)
        item_summary.setForeground(QtGui.QColor(QtCore.Qt.white))  # Change text color to white
        item_summary.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable)  # Make item read-only
        item_summary.setFont(self.font_summary)
        self.table.setItem(row_number, 4, item_summary)
        if (self.table.verticalScrollBar().maximum() - self.table.verticalScrollBar().value() <= 7):
            self.table.verticalScrollBar().setValue(self.table.verticalScrollBar().maximum())

    def resizeEvent(self, event: QtGui.QResizeEvent) -> None:
        super().resizeEvent(event)
        width = event.size().width()
        height = event.size().height()
        self.adjust_table_size(width, height)
        self.search_bar.setFixedWidth(width - 20)
        self.theme_button.setGeometry(QtCore.QRect(width - 65, 10, 70, 40))

    def adjust_table_size(self, width, height):
        self.table.setColumnWidth(0, 100)
        self.table.setColumnWidth(1, 100)
        self.table.setColumnWidth(2, 267)
        self.table.setColumnWidth(3, 267)
        self.table.setGeometry(QtCore.QRect(0, 180, width, height - 180))

    def change_record_buttons_color(self, is_pressed):
        self.is_start_pressed = is_pressed
        start_color = "(9, 195, 9)" if not is_pressed else "(109, 125, 109)"
        self.start_record.setStyleSheet(f"background-color:rgb{start_color};border-radius: 15px;")
        stop_color = "(255, 19, 19)" if is_pressed else "(125, 112, 112)"
        self.stop_record.setStyleSheet(f"background-color:rgb{stop_color};border-radius: 15px;")

    def open_packet_details(self, item, packets):
        packet_number = self.table.item(item.row(), 0)
        packet_number = int(packet_number.text())
        layers_dict = packets[packet_number - 1].get_layer_info()
        pd = packets[packet_number - 1].info.show(dump=True)
        pdw = PacketDetailsWindow(layers_dict, packet_number, THEMES[self.themes_index])
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
        self.table.clearContents()
        self.table.setRowCount(0)

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
        colors = THEMES[self.themes_index]
        sb_color = colors[2]
        self.is_search_valid = True
        self.search_bar.setStyleSheet(f"border-radius: 15px; padding: 5px;background-color: {sb_color}")

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

    def change_theme(self):
        self.themes_index += 1
        self.set_themes_index(self.themes_index)
        if self.themes_index == len(THEMES):
            self.themes_index = 0
        colors = THEMES[self.themes_index]
        self.setStyleSheet(F"background-color: {colors[0]};")
        self.table.setStyleSheet(
            f"QTableWidget {{ background-color: {colors[1]}; border: 1px solid {colors[1]}; }}"
            f"QTableCornerButton::section {{ background-color: {colors[2]}; }}"
        )

        header_stylesheet = f"QHeaderView::section {{ background-color: {colors[2]}; }}"
        self.table.horizontalHeader().setStyleSheet(header_stylesheet)
        self.table.verticalHeader().setStyleSheet(header_stylesheet)

        self.search_bar.setStyleSheet(f"border-radius: 15px; padding: 5px;background-color: {colors[2]}")
        self.check_valid_search_term()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
