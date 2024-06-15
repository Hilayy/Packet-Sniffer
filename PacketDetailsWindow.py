from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QApplication, QMainWindow, QDialog, QVBoxLayout, QMessageBox, QFileDialog, QLineEdit
from PyQt5 import QtCore, QtGui

class PacketDetailsWindow(QtWidgets.QWidget):
    def __init__(self, layers_dict, number, theme):
        super().__init__()
        self.layers_dict = layers_dict
        self.number = number
        self.theme = theme
        self.initUI()
    def initUI1(self):
        self.setGeometry(400, 100, 500, 400)
        self.login = QtWidgets.QPushButton(self)

    def initUI(self):
        self.setStyleSheet(f"background-color: {self.theme[0]};")
        self.setWindowTitle(f'Packet {self.number}')
        self.setGeometry(400, 100, 500, 400)
        self.buttons = []
        num1 = int((500 / len(self.layers_dict.keys())))
        num2 = num1 * -1
        for key in self.layers_dict.keys():
            button = QtWidgets.QPushButton(self)
            num2 += num1
            button.setGeometry(QtCore.QRect(num2, 5, num1, 30))
            button.setStyleSheet(f"background-color: {self.theme[2]};")
            button.setText(key)
            # Use a default argument in lambda to capture the current value of key
            button.clicked.connect(lambda checked, key=key: self.layer_clicked(self.layers_dict[key]))
            self.buttons.append(button)

    def layer_clicked(self, info):
        label = QtWidgets.QLabel(info, self)
        label.setStyleSheet("""
                    QLabel {
                        font-family: 'Arial';
                        font-size: 16px;
                        color: #2E2E2E;  # Dark Gray color
                        background-color: #F5F5F5;  # Light Gray background
                        padding: 10px;
                        border-radius: 5px;
                    }
                """)
        font = font = QtGui.QFont("Circular")
        font.setPointSize(11)
        label.setFont(font)
        label.setGeometry(QtCore.QRect(0, 50, 400, 300))

        label.setVisible(True)