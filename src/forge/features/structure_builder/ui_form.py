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
QFrame = QtWidgets.QFrame
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

class Ui_view_form(object):
    def setupUi(self, view_form):
        if not view_form.objectName():
            view_form.setObjectName(u"view_form")
        view_form.resize(843, 602)
        view_form.setAutoFillBackground(False)
        self.action_enable = QAction(view_form)
        self.action_enable.setObjectName(u"action_enable")
        self.action_disable = QAction(view_form)
        self.action_disable.setObjectName(u"action_disable")
        self.action_resolve = QAction(view_form)
        self.action_resolve.setObjectName(u"action_resolve")
        self.action_finalize = QAction(view_form)
        self.action_finalize.setObjectName(u"action_finalize")
        self.action_edit = QAction(view_form)
        self.action_edit.setObjectName(u"action_edit")
        self.action_add_row = QAction(view_form)
        self.action_add_row.setObjectName(u"action_add_row")
        self.horizontalLayout = QHBoxLayout(view_form)
        self.horizontalLayout.setObjectName(u"horizontalLayout")
        self.horizontalLayout.setContentsMargins(1, 1, 1, 1)
        self.frm_left = QFrame(view_form)
        self.frm_left.setObjectName(u"frm_left")
        sizePolicy = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.frm_left.sizePolicy().hasHeightForWidth())
        self.frm_left.setSizePolicy(sizePolicy)
        self.frm_left.setMinimumSize(QSize(100, 0))
        self.frm_left.setMaximumSize(QSize(180, 16777215))
        self.frm_left.setFrameShape(QFrame.NoFrame)
        self.verticalLayout_2 = QVBoxLayout(self.frm_left)
        self.verticalLayout_2.setSpacing(1)
        self.verticalLayout_2.setObjectName(u"verticalLayout_2")
        self.verticalLayout_2.setContentsMargins(1, 1, 1, 1)
        self.lbl_title = QLabel(self.frm_left)
        self.lbl_title.setObjectName(u"lbl_title")
        self.lbl_title.setMinimumSize(QSize(0, 34))

        self.verticalLayout_2.addWidget(self.lbl_title)

        self.lst_structures = QListWidget(self.frm_left)
        self.lst_structures.setObjectName(u"lst_structures")

        self.verticalLayout_2.addWidget(self.lst_structures)

        self.btn_add = QPushButton(self.frm_left)
        self.btn_add.setObjectName(u"btn_add")

        self.verticalLayout_2.addWidget(self.btn_add)

        self.btn_remove = QPushButton(self.frm_left)
        self.btn_remove.setObjectName(u"btn_remove")

        self.verticalLayout_2.addWidget(self.btn_remove)


        self.horizontalLayout.addWidget(self.frm_left)

        self.frm_right = QFrame(view_form)
        self.frm_right.setObjectName(u"frm_right")
        self.verticalLayout = QVBoxLayout(self.frm_right)
        self.verticalLayout.setSpacing(1)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.verticalLayout.setContentsMargins(1, 1, 1, 1)
        self.frm_right_header = QFrame(self.frm_right)
        self.frm_right_header.setObjectName(u"frm_right_header")
        sizePolicy1 = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        sizePolicy1.setHorizontalStretch(0)
        sizePolicy1.setVerticalStretch(0)
        sizePolicy1.setHeightForWidth(self.frm_right_header.sizePolicy().hasHeightForWidth())
        self.frm_right_header.setSizePolicy(sizePolicy1)
        self.frm_right_header.setFrameShape(QFrame.NoFrame)
        self.horizontalLayout_2 = QHBoxLayout(self.frm_right_header)
        self.horizontalLayout_2.setObjectName(u"horizontalLayout_2")
        self.horizontalLayout_2.setContentsMargins(5, 5, 5, 5)
        self.lbl_name = QLabel(self.frm_right_header)
        self.lbl_name.setObjectName(u"lbl_name")

        self.horizontalLayout_2.addWidget(self.lbl_name)

        self.input_name = QLineEdit(self.frm_right_header)
        self.input_name.setObjectName(u"input_name")
        sizePolicy2 = QSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        sizePolicy2.setHorizontalStretch(0)
        sizePolicy2.setVerticalStretch(0)
        sizePolicy2.setHeightForWidth(self.input_name.sizePolicy().hasHeightForWidth())
        self.input_name.setSizePolicy(sizePolicy2)
        self.input_name.setMinimumSize(QSize(0, 23))

        self.horizontalLayout_2.addWidget(self.input_name)

        self.btn_apply_name = QPushButton(self.frm_right_header)
        self.btn_apply_name.setObjectName(u"btn_apply_name")

        self.horizontalLayout_2.addWidget(self.btn_apply_name)


        self.verticalLayout.addWidget(self.frm_right_header)

        self.tbl_structure = QTableWidget(self.frm_right)
        if (self.tbl_structure.columnCount() < 5):
            self.tbl_structure.setColumnCount(5)
        font = QFont()
        font.setBold(True)
        font.setItalic(False)
        font.setKerning(False)
        __qtablewidgetitem = QTableWidgetItem()
        __qtablewidgetitem.setFont(font)
        self.tbl_structure.setHorizontalHeaderItem(0, __qtablewidgetitem)
        font1 = QFont()
        font1.setBold(True)
        font1.setKerning(False)
        __qtablewidgetitem1 = QTableWidgetItem()
        __qtablewidgetitem1.setFont(font1)
        self.tbl_structure.setHorizontalHeaderItem(1, __qtablewidgetitem1)
        __qtablewidgetitem2 = QTableWidgetItem()
        __qtablewidgetitem2.setFont(font1)
        self.tbl_structure.setHorizontalHeaderItem(2, __qtablewidgetitem2)
        font2 = QFont()
        font2.setBold(True)
        __qtablewidgetitem3 = QTableWidgetItem()
        __qtablewidgetitem3.setFont(font2)
        self.tbl_structure.setHorizontalHeaderItem(3, __qtablewidgetitem3)
        __qtablewidgetitem4 = QTableWidgetItem()
        __qtablewidgetitem4.setFont(font1)
        self.tbl_structure.setHorizontalHeaderItem(4, __qtablewidgetitem4)
        self.tbl_structure.setObjectName(u"tbl_structure")
        self.tbl_structure.horizontalHeader().setStretchLastSection(True)
        self.tbl_structure.verticalHeader().setStretchLastSection(False)

        self.verticalLayout.addWidget(self.tbl_structure)

        self.frm_buttons = QGridLayout()
        self.frm_buttons.setSpacing(1)
        self.frm_buttons.setObjectName(u"frm_buttons")
        self.btn_view_scanned_uses = QPushButton(self.frm_right)
        self.btn_view_scanned_uses.setObjectName(u"btn_view_scanned_uses")
        sizePolicy3 = QSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        sizePolicy3.setHorizontalStretch(0)
        sizePolicy3.setVerticalStretch(0)
        sizePolicy3.setHeightForWidth(self.btn_view_scanned_uses.sizePolicy().hasHeightForWidth())
        self.btn_view_scanned_uses.setSizePolicy(sizePolicy3)
        self.btn_view_scanned_uses.setMinimumSize(QSize(200, 0))

        self.frm_buttons.addWidget(self.btn_view_scanned_uses, 0, 5, 1, 1)

        self.btn_enable_rows = QPushButton(self.frm_right)
        self.btn_enable_rows.setObjectName(u"btn_enable_rows")

        self.frm_buttons.addWidget(self.btn_enable_rows, 0, 2, 1, 1)

        self.btn_disable_rows = QPushButton(self.frm_right)
        self.btn_disable_rows.setObjectName(u"btn_disable_rows")

        self.frm_buttons.addWidget(self.btn_disable_rows, 2, 2, 1, 1)

        self.btn_auto_resolve = QPushButton(self.frm_right)
        self.btn_auto_resolve.setObjectName(u"btn_auto_resolve")
        sizePolicy3.setHeightForWidth(self.btn_auto_resolve.sizePolicy().hasHeightForWidth())
        self.btn_auto_resolve.setSizePolicy(sizePolicy3)

        self.frm_buttons.addWidget(self.btn_auto_resolve, 0, 0, 1, 1)

        self.btn_toggle_array = QPushButton(self.frm_right)
        self.btn_toggle_array.setObjectName(u"btn_toggle_array")

        self.frm_buttons.addWidget(self.btn_toggle_array, 2, 1, 1, 1)

        self.horizontalSpacer = QSpacerItem(20, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.frm_buttons.addItem(self.horizontalSpacer, 0, 4, 1, 1)

        self.btn_recognize_vtable = QPushButton(self.frm_right)
        self.btn_recognize_vtable.setObjectName(u"btn_recognize_vtable")

        self.frm_buttons.addWidget(self.btn_recognize_vtable, 2, 5, 1, 1)

        self.btn_set_origin = QPushButton(self.frm_right)
        self.btn_set_origin.setObjectName(u"btn_set_origin")

        self.frm_buttons.addWidget(self.btn_set_origin, 2, 0, 1, 1)

        self.btn_create_type = QPushButton(self.frm_right)
        self.btn_create_type.setObjectName(u"btn_create_type")

        self.frm_buttons.addWidget(self.btn_create_type, 0, 1, 1, 1)

        self.btn_remove_rows = QPushButton(self.frm_right)
        self.btn_remove_rows.setObjectName(u"btn_remove_rows")

        self.frm_buttons.addWidget(self.btn_remove_rows, 0, 3, 1, 1)

        self.btn_add_row = QPushButton(self.frm_right)
        self.btn_add_row.setObjectName(u"btn_add_row")

        self.frm_buttons.addWidget(self.btn_add_row, 2, 4, 1, 1)

        self.btn_clear_rows = QPushButton(self.frm_right)
        self.btn_clear_rows.setObjectName(u"btn_clear_rows")

        self.frm_buttons.addWidget(self.btn_clear_rows, 2, 3, 1, 1)

        self.btn_edit_row = QPushButton(self.frm_right)
        self.btn_edit_row.setObjectName(u"btn_edit_row")

        self.frm_buttons.addWidget(self.btn_edit_row, 0, 6, 1, 1)


        self.verticalLayout.addLayout(self.frm_buttons)

        self.lbl_summary = QLabel(self.frm_right)
        self.lbl_summary.setObjectName(u"lbl_summary")

        self.verticalLayout.addWidget(self.lbl_summary)


        self.horizontalLayout.addWidget(self.frm_right)


        self.retranslateUi(view_form)

        QMetaObject.connectSlotsByName(view_form)
    # setupUi

    def retranslateUi(self, view_form):
        view_form.setWindowTitle(QCoreApplication.translate("view_form", u"Form", None))
        self.action_enable.setText(QCoreApplication.translate("view_form", u"Enable Row", None))
#if QT_CONFIG(tooltip)
        self.action_enable.setToolTip(QCoreApplication.translate("view_form", u"Enable a row", None))
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(shortcut)
        self.action_enable.setShortcut(QCoreApplication.translate("view_form", u"E", None))
#endif // QT_CONFIG(shortcut)
        self.action_disable.setText(QCoreApplication.translate("view_form", u"Disable Row", None))
#if QT_CONFIG(tooltip)
        self.action_disable.setToolTip(QCoreApplication.translate("view_form", u"Disale a row", None))
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(shortcut)
        self.action_disable.setShortcut(QCoreApplication.translate("view_form", u"D", None))
#endif // QT_CONFIG(shortcut)
        self.action_resolve.setText(QCoreApplication.translate("view_form", u"Auto Resolve", None))
#if QT_CONFIG(tooltip)
        self.action_resolve.setToolTip(QCoreApplication.translate("view_form", u"Auto resolve structure table using scoring", None))
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(shortcut)
        self.action_resolve.setShortcut(QCoreApplication.translate("view_form", u"R", None))
#endif // QT_CONFIG(shortcut)
        self.action_finalize.setText(QCoreApplication.translate("view_form", u"Finialize", None))
#if QT_CONFIG(tooltip)
        self.action_finalize.setToolTip(QCoreApplication.translate("view_form", u"Finialize the structure table into a struct", None))
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(shortcut)
        self.action_finalize.setShortcut(QCoreApplication.translate("view_form", u"F", None))
#endif // QT_CONFIG(shortcut)
        self.action_edit.setText(QCoreApplication.translate("view_form", u"Edit Row", None))
#if QT_CONFIG(tooltip)
        self.action_edit.setToolTip(QCoreApplication.translate("view_form", u"Edit the selected row", None))
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(shortcut)
        self.action_edit.setShortcut(QCoreApplication.translate("view_form", u"Ctrl+E", None))
#endif // QT_CONFIG(shortcut)
        self.action_add_row.setText(QCoreApplication.translate("view_form", u"Add Row", None))
#if QT_CONFIG(tooltip)
        self.action_add_row.setToolTip(QCoreApplication.translate("view_form", u"Add a manual row", None))
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(shortcut)
        self.action_add_row.setShortcut(QCoreApplication.translate("view_form", u"Insert", None))
#endif // QT_CONFIG(shortcut)
        self.lbl_title.setText(QCoreApplication.translate("view_form", u"Structures", None))
#if QT_CONFIG(tooltip)
        self.btn_add.setToolTip(QCoreApplication.translate("view_form", u"<html><head/><body><p>Add a structure to the structure list</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.btn_add.setText(QCoreApplication.translate("view_form", u"Add Structure", None))
#if QT_CONFIG(tooltip)
        self.btn_remove.setToolTip(QCoreApplication.translate("view_form", u"<html><head/><body><p>Remove selected structure from the list</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.btn_remove.setText(QCoreApplication.translate("view_form", u"Remove Structure", None))
        self.lbl_name.setText(QCoreApplication.translate("view_form", u"Name:", None))
#if QT_CONFIG(tooltip)
        self.input_name.setToolTip(QCoreApplication.translate("view_form", u"<html><head/><body><p>Apply a new name to the structure</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(tooltip)
        self.btn_apply_name.setToolTip(QCoreApplication.translate("view_form", u"<html><head/><body><p>Apply a new name to the structure</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.btn_apply_name.setText(QCoreApplication.translate("view_form", u"Apply Name", None))
        ___qtablewidgetitem = self.tbl_structure.horizontalHeaderItem(0)
        ___qtablewidgetitem.setText(QCoreApplication.translate("view_form", u"Offset", None))
        ___qtablewidgetitem1 = self.tbl_structure.horizontalHeaderItem(1)
        ___qtablewidgetitem1.setText(QCoreApplication.translate("view_form", u"Type", None))
        ___qtablewidgetitem2 = self.tbl_structure.horizontalHeaderItem(2)
        ___qtablewidgetitem2.setText(QCoreApplication.translate("view_form", u"Name", None))
        ___qtablewidgetitem3 = self.tbl_structure.horizontalHeaderItem(3)
        ___qtablewidgetitem3.setText(QCoreApplication.translate("view_form", u"Score", None))
        ___qtablewidgetitem4 = self.tbl_structure.horizontalHeaderItem(4)
        ___qtablewidgetitem4.setText(QCoreApplication.translate("view_form", u"Comment", None))
        self.btn_view_scanned_uses.setText(QCoreApplication.translate("view_form", u"View Scanned Uses", None))
        self.btn_enable_rows.setText(QCoreApplication.translate("view_form", u"Enable", None))
        self.btn_disable_rows.setText(QCoreApplication.translate("view_form", u"Disable", None))
        self.btn_auto_resolve.setText(QCoreApplication.translate("view_form", u"Auto Resolve", None))
        self.btn_toggle_array.setText(QCoreApplication.translate("view_form", u"Array", None))
        self.btn_recognize_vtable.setText(QCoreApplication.translate("view_form", u"Recognize VTable", None))
        self.btn_set_origin.setText(QCoreApplication.translate("view_form", u"Set Origin", None))
        self.btn_create_type.setText(QCoreApplication.translate("view_form", u"Create Type", None))
        self.btn_remove_rows.setText(QCoreApplication.translate("view_form", u"Remove", None))
        self.btn_add_row.setText(QCoreApplication.translate("view_form", u"Add Row", None))
        self.btn_clear_rows.setText(QCoreApplication.translate("view_form", u"Clear", None))
        self.btn_edit_row.setText(QCoreApplication.translate("view_form", u"Edit Row", None))
        self.lbl_summary.setText(QCoreApplication.translate("view_form", u"No structure selected.", None))
    # retranslateUi

