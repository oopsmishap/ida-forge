
################################################################################
## Form generated from reading UI file 'about.ui'
##
## Created by: Qt User Interface Compiler version 6.11.0
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from forge.util.qt import QtCore, QtGui, QtWidgets

QCoreApplication = QtCore.QCoreApplication
QMetaObject = QtCore.QMetaObject
QPoint = QtCore.QPoint
QRect = QtCore.QRect
QSize = QtCore.QSize
Qt = QtCore.Qt
QAction = QtGui.QAction
QBrush = QtGui.QBrush
QColor = QtGui.QColor
QConicalGradient = QtGui.QConicalGradient
QCursor = QtGui.QCursor
QFont = QtGui.QFont
QFontDatabase = QtGui.QFontDatabase
QGradient = QtGui.QGradient
QIcon = QtGui.QIcon
QImage = QtGui.QImage
QKeySequence = QtGui.QKeySequence
QLinearGradient = QtGui.QLinearGradient
QPainter = QtGui.QPainter
QPalette = QtGui.QPalette
QPixmap = QtGui.QPixmap
QRadialGradient = QtGui.QRadialGradient
QTransform = QtGui.QTransform
QApplication = QtWidgets.QApplication
QDialog = QtWidgets.QDialog
QFrame = QtWidgets.QFrame
QGridLayout = QtWidgets.QGridLayout
QHBoxLayout = QtWidgets.QHBoxLayout
QHeaderView = QtWidgets.QHeaderView
QLabel = QtWidgets.QLabel
QLayout = QtWidgets.QLayout
QLineEdit = QtWidgets.QLineEdit
QListWidget = QtWidgets.QListWidget
QListWidgetItem = QtWidgets.QListWidgetItem
QPushButton = QtWidgets.QPushButton
QSizePolicy = QtWidgets.QSizePolicy
QSpacerItem = QtWidgets.QSpacerItem
QTableWidget = QtWidgets.QTableWidget
QTableWidgetItem = QtWidgets.QTableWidgetItem
QTextEdit = QtWidgets.QTextEdit
QVBoxLayout = QtWidgets.QVBoxLayout
QWidget = QtWidgets.QWidget

class Ui_about_window:
    def setupUi(self, about_window):
        if not about_window.objectName():
            about_window.setObjectName("about_window")
        about_window.resize(300, 375)
        self.verticalLayout = QVBoxLayout(about_window)
        self.verticalLayout.setObjectName("verticalLayout")
        self.image_label = QLabel(about_window)
        self.image_label.setObjectName("image_label")
        self.image_label.setAlignment(Qt.AlignCenter)

        self.verticalLayout.addWidget(self.image_label)

        self.grid_widget = QWidget(about_window)
        self.grid_widget.setObjectName("grid_widget")
        self.gridLayout = QGridLayout(self.grid_widget)
        self.gridLayout.setObjectName("gridLayout")
        self.gridLayout.setSizeConstraint(QLayout.SetDefaultConstraint)
        self.plugin_label = QLabel(self.grid_widget)
        self.plugin_label.setObjectName("plugin_label")

        self.gridLayout.addWidget(self.plugin_label, 0, 0, 1, 1)

        self.plugin_name = QLabel(self.grid_widget)
        self.plugin_name.setObjectName("plugin_name")

        self.gridLayout.addWidget(self.plugin_name, 0, 1, 1, 1)

        self.author_label = QLabel(self.grid_widget)
        self.author_label.setObjectName("author_label")

        self.gridLayout.addWidget(self.author_label, 1, 0, 1, 1)

        self.author_name = QLabel(self.grid_widget)
        self.author_name.setObjectName("author_name")

        self.gridLayout.addWidget(self.author_name, 1, 1, 1, 1)

        self.version_label = QLabel(self.grid_widget)
        self.version_label.setObjectName("version_label")

        self.gridLayout.addWidget(self.version_label, 2, 0, 1, 1)

        self.version_num = QLabel(self.grid_widget)
        self.version_num.setObjectName("version_num")

        self.gridLayout.addWidget(self.version_num, 2, 1, 1, 1)


        self.verticalLayout.addWidget(self.grid_widget)


        self.retranslateUi(about_window)

        QMetaObject.connectSlotsByName(about_window)
    # setupUi

    def retranslateUi(self, about_window):
        about_window.setWindowTitle(QCoreApplication.translate("about_window", "About Forge", None))
        self.image_label.setText("")
        self.plugin_label.setText(QCoreApplication.translate("about_window", "Plugin Name:", None))
        self.plugin_name.setText("")
        self.author_label.setText(QCoreApplication.translate("about_window", "Author:", None))
        self.author_name.setText("")
        self.version_label.setText(QCoreApplication.translate("about_window", "Version:", None))
        self.version_num.setText("")
    # retranslateUi

