# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'form.ui'
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

class Ui_templated_types_form(object):
    def setupUi(self, templated_types_form):
        if not templated_types_form.objectName():
            templated_types_form.setObjectName(u"templated_types_form")
        templated_types_form.resize(1100, 600)
        self.gridLayout = QGridLayout(templated_types_form)
        self.gridLayout.setObjectName(u"gridLayout")
        self.type_list_label = QLabel(templated_types_form)
        self.type_list_label.setObjectName(u"type_list_label")

        self.gridLayout.addWidget(self.type_list_label, 0, 0, 1, 1)

        self.stl_title_fields = QLabel(templated_types_form)
        self.stl_title_fields.setObjectName(u"stl_title_fields")

        self.gridLayout.addWidget(self.stl_title_fields, 0, 1, 1, 1)

        self.stl_title_struct = QLabel(templated_types_form)
        self.stl_title_struct.setObjectName(u"stl_title_struct")

        self.gridLayout.addWidget(self.stl_title_struct, 0, 2, 1, 1)

        self.stl_list = QListWidget(templated_types_form)
        self.stl_list.setObjectName(u"stl_list")
        self.stl_list.setMinimumSize(QSize(300, 0))
        self.stl_list.setMaximumSize(QSize(300, 16777215))

        self.gridLayout.addWidget(self.stl_list, 1, 0, 1, 1)

        self.stl_widget = QWidget(templated_types_form)
        self.stl_widget.setObjectName(u"stl_widget")

        self.gridLayout.addWidget(self.stl_widget, 1, 1, 1, 1)

        self.stl_struct_view = QTextEdit(templated_types_form)
        self.stl_struct_view.setObjectName(u"stl_struct_view")
        self.stl_struct_view.setReadOnly(True)

        self.gridLayout.addWidget(self.stl_struct_view, 1, 2, 1, 1)

        self.btn_reload_stl_list = QPushButton(templated_types_form)
        self.btn_reload_stl_list.setObjectName(u"btn_reload_stl_list")
        self.btn_reload_stl_list.setMinimumSize(QSize(300, 0))
        self.btn_reload_stl_list.setMaximumSize(QSize(300, 16777215))

        self.gridLayout.addWidget(self.btn_reload_stl_list, 2, 0, 1, 1)

        self.btn_open_stl_toml = QPushButton(templated_types_form)
        self.btn_open_stl_toml.setObjectName(u"btn_open_stl_toml")
        self.btn_open_stl_toml.setMinimumSize(QSize(300, 0))
        self.btn_open_stl_toml.setMaximumSize(QSize(300, 16777215))

        self.gridLayout.addWidget(self.btn_open_stl_toml, 3, 0, 1, 1)


        self.retranslateUi(templated_types_form)

        QMetaObject.connectSlotsByName(templated_types_form)
    # setupUi

    def retranslateUi(self, templated_types_form):
        templated_types_form.setWindowTitle(QCoreApplication.translate("templated_types_form", u"Templated Types", None))
        self.type_list_label.setText(QCoreApplication.translate("templated_types_form", u"Type List:", None))
        self.stl_title_fields.setText(QCoreApplication.translate("templated_types_form", u"Selected Type:", None))
        self.stl_title_struct.setText(QCoreApplication.translate("templated_types_form", u"Creating Type:", None))
        self.btn_reload_stl_list.setText(QCoreApplication.translate("templated_types_form", u"Reload Templated Types TOML", None))
        self.btn_open_stl_toml.setText(QCoreApplication.translate("templated_types_form", u"Open Templated Types TOML", None))
    # retranslateUi

