import sys
from View import *
from Sniffer import Sniffer



def window():
    # set window and window properties
    application = QApplication(sys.argv)
    win = Sniffer(MainWindow())
    win.gui.show()
    sys.exit(application.exec_())


if __name__ == "__main__":
    try:
        window()
    except Exception as e:
        print(e.args)
        sys.exit(0)
