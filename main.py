from PyQt5 import QtWidgets
import sniffer_gui
import sniffer_handler

if __name__ == '__main__':
    app = QtWidgets.QApplication([])
    ui = sniffer_gui.Ui_MainWindow()
    mainWindow = QtWidgets.QMainWindow()
    ui.setupUi(mainWindow)
    mainWindow.show()
    handler = sniffer_handler.SnifferHandler(ui)
    handler.connect_ui()
    app.exec_()