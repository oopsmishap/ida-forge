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
QTreeWidget = QtWidgets.QTreeWidget
QTreeWidgetItem = QtWidgets.QTreeWidgetItem
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
        view_form.resize(1180, 720)
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
        self.action_duplicate_row = QAction(view_form)
        self.action_duplicate_row.setObjectName(u"action_duplicate_row")
        self.action_duplicate_structure = QAction(view_form)
        self.action_duplicate_structure.setObjectName(u"action_duplicate_structure")
        self.action_scan_child = QAction(view_form)
        self.action_scan_child.setObjectName(u"action_scan_child")
        self.action_create_child_types = QAction(view_form)
        self.action_create_child_types.setObjectName(u"action_create_child_types")
        self.action_create_subtree_types = QAction(view_form)
        self.action_create_subtree_types.setObjectName(u"action_create_subtree_types")
        self.horizontalLayout = QHBoxLayout(view_form)
        self.horizontalLayout.setObjectName(u"horizontalLayout")
        self.horizontalLayout.setContentsMargins(1, 1, 1, 1)
        self.frm_left = QFrame(view_form)
        self.frm_left.setObjectName(u"frm_left")
        self.frm_left.setMinimumSize(QSize(220, 0))
        self.frm_left.setMaximumSize(QSize(300, 16777215))
        self.frm_left.setFrameShape(QFrame.NoFrame)
        self.verticalLayout_2 = QVBoxLayout(self.frm_left)
        self.verticalLayout_2.setSpacing(4)
        self.verticalLayout_2.setObjectName(u"verticalLayout_2")
        self.verticalLayout_2.setContentsMargins(4, 4, 4, 4)
        self.lbl_title = QLabel(self.frm_left)
        self.lbl_title.setObjectName(u"lbl_title")
        self.lbl_title.setMinimumSize(QSize(0, 28))

        self.verticalLayout_2.addWidget(self.lbl_title)

        self.input_filter = QLineEdit(self.frm_left)
        self.input_filter.setObjectName(u"input_filter")
        self.input_filter.setClearButtonEnabled(True)

        self.verticalLayout_2.addWidget(self.input_filter)

        self.tree_structures = QTreeWidget(self.frm_left)
        self.tree_structures.setObjectName(u"tree_structures")
        self.tree_structures.setHeaderHidden(True)

        self.verticalLayout_2.addWidget(self.tree_structures)

        self.btn_add = QPushButton(self.frm_left)
        self.btn_add.setObjectName(u"btn_add")

        self.verticalLayout_2.addWidget(self.btn_add)

        self.btn_duplicate_structure = QPushButton(self.frm_left)
        self.btn_duplicate_structure.setObjectName(u"btn_duplicate_structure")

        self.verticalLayout_2.addWidget(self.btn_duplicate_structure)

        self.btn_remove = QPushButton(self.frm_left)
        self.btn_remove.setObjectName(u"btn_remove")

        self.verticalLayout_2.addWidget(self.btn_remove)


        self.horizontalLayout.addWidget(self.frm_left)

        self.frm_right = QFrame(view_form)
        self.frm_right.setObjectName(u"frm_right")
        self.frm_right.setFrameShape(QFrame.NoFrame)
        self.horizontalLayout_right = QHBoxLayout(self.frm_right)
        self.horizontalLayout_right.setSpacing(4)
        self.horizontalLayout_right.setObjectName(u"horizontalLayout_right")
        self.horizontalLayout_right.setContentsMargins(1, 1, 1, 1)
        self.frm_right_main = QFrame(self.frm_right)
        self.frm_right_main.setObjectName(u"frm_right_main")
        self.frm_right_main.setFrameShape(QFrame.NoFrame)
        self.verticalLayout_main = QVBoxLayout(self.frm_right_main)
        self.verticalLayout_main.setSpacing(4)
        self.verticalLayout_main.setObjectName(u"verticalLayout_main")
        self.verticalLayout_main.setContentsMargins(1, 1, 1, 1)
        self.frm_right_header = QFrame(self.frm_right_main)
        self.frm_right_header.setObjectName(u"frm_right_header")
        self.frm_right_header.setFrameShape(QFrame.NoFrame)
        self.horizontalLayout_2 = QHBoxLayout(self.frm_right_header)
        self.horizontalLayout_2.setObjectName(u"horizontalLayout_2")
        self.horizontalLayout_2.setContentsMargins(5, 5, 5, 5)
        self.lbl_name = QLabel(self.frm_right_header)
        self.lbl_name.setObjectName(u"lbl_name")

        self.horizontalLayout_2.addWidget(self.lbl_name)

        self.input_name = QLineEdit(self.frm_right_header)
        self.input_name.setObjectName(u"input_name")
        self.input_name.setMinimumSize(QSize(0, 23))

        self.horizontalLayout_2.addWidget(self.input_name)

        self.btn_apply_name = QPushButton(self.frm_right_header)
        self.btn_apply_name.setObjectName(u"btn_apply_name")

        self.horizontalLayout_2.addWidget(self.btn_apply_name)


        self.verticalLayout_main.addWidget(self.frm_right_header)

        self.tbl_structure = QTableWidget(self.frm_right_main)
        if (self.tbl_structure.columnCount() < 5):
            self.tbl_structure.setColumnCount(5)
        __qtablewidgetitem = QTableWidgetItem()
        self.tbl_structure.setHorizontalHeaderItem(0, __qtablewidgetitem)
        __qtablewidgetitem1 = QTableWidgetItem()
        self.tbl_structure.setHorizontalHeaderItem(1, __qtablewidgetitem1)
        __qtablewidgetitem2 = QTableWidgetItem()
        self.tbl_structure.setHorizontalHeaderItem(2, __qtablewidgetitem2)
        __qtablewidgetitem3 = QTableWidgetItem()
        self.tbl_structure.setHorizontalHeaderItem(3, __qtablewidgetitem3)
        __qtablewidgetitem4 = QTableWidgetItem()
        self.tbl_structure.setHorizontalHeaderItem(4, __qtablewidgetitem4)
        self.tbl_structure.setObjectName(u"tbl_structure")
        self.tbl_structure.horizontalHeader().setStretchLastSection(True)
        self.tbl_structure.verticalHeader().setStretchLastSection(False)

        self.verticalLayout_main.addWidget(self.tbl_structure)

        self.frm_buttons = QGridLayout()
        self.frm_buttons.setSpacing(2)
        self.frm_buttons.setObjectName(u"frm_buttons")
        self.btn_auto_resolve = QPushButton(self.frm_right_main)
        self.btn_auto_resolve.setObjectName(u"btn_auto_resolve")

        self.frm_buttons.addWidget(self.btn_auto_resolve, 0, 0, 1, 1)

        self.btn_create_type = QPushButton(self.frm_right_main)
        self.btn_create_type.setObjectName(u"btn_create_type")

        self.frm_buttons.addWidget(self.btn_create_type, 0, 1, 1, 1)

        self.btn_enable_rows = QPushButton(self.frm_right_main)
        self.btn_enable_rows.setObjectName(u"btn_enable_rows")

        self.frm_buttons.addWidget(self.btn_enable_rows, 0, 2, 1, 1)

        self.btn_remove_rows = QPushButton(self.frm_right_main)
        self.btn_remove_rows.setObjectName(u"btn_remove_rows")

        self.frm_buttons.addWidget(self.btn_remove_rows, 0, 3, 1, 1)

        self.horizontalSpacer = QSpacerItem(20, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.frm_buttons.addItem(self.horizontalSpacer, 0, 4, 1, 1)

        self.btn_view_scanned_uses = QPushButton(self.frm_right_main)
        self.btn_view_scanned_uses.setObjectName(u"btn_view_scanned_uses")
        self.btn_view_scanned_uses.setMinimumSize(QSize(180, 0))

        self.frm_buttons.addWidget(self.btn_view_scanned_uses, 0, 5, 1, 1)

        self.btn_edit_row = QPushButton(self.frm_right_main)
        self.btn_edit_row.setObjectName(u"btn_edit_row")

        self.frm_buttons.addWidget(self.btn_edit_row, 0, 6, 1, 1)

        self.btn_set_origin = QPushButton(self.frm_right_main)
        self.btn_set_origin.setObjectName(u"btn_set_origin")

        self.frm_buttons.addWidget(self.btn_set_origin, 1, 0, 1, 1)

        self.btn_toggle_array = QPushButton(self.frm_right_main)
        self.btn_toggle_array.setObjectName(u"btn_toggle_array")

        self.frm_buttons.addWidget(self.btn_toggle_array, 1, 1, 1, 1)

        self.btn_disable_rows = QPushButton(self.frm_right_main)
        self.btn_disable_rows.setObjectName(u"btn_disable_rows")

        self.frm_buttons.addWidget(self.btn_disable_rows, 1, 2, 1, 1)

        self.btn_clear_rows = QPushButton(self.frm_right_main)
        self.btn_clear_rows.setObjectName(u"btn_clear_rows")

        self.frm_buttons.addWidget(self.btn_clear_rows, 1, 3, 1, 1)

        self.btn_add_row = QPushButton(self.frm_right_main)
        self.btn_add_row.setObjectName(u"btn_add_row")

        self.frm_buttons.addWidget(self.btn_add_row, 1, 4, 1, 1)

        self.btn_recognize_vtable = QPushButton(self.frm_right_main)
        self.btn_recognize_vtable.setObjectName(u"btn_recognize_vtable")

        self.frm_buttons.addWidget(self.btn_recognize_vtable, 1, 5, 1, 1)

        self.btn_duplicate_row = QPushButton(self.frm_right_main)
        self.btn_duplicate_row.setObjectName(u"btn_duplicate_row")

        self.frm_buttons.addWidget(self.btn_duplicate_row, 1, 6, 1, 1)


        self.verticalLayout_main.addLayout(self.frm_buttons)

        self.lbl_summary = QLabel(self.frm_right_main)
        self.lbl_summary.setObjectName(u"lbl_summary")

        self.verticalLayout_main.addWidget(self.lbl_summary)


        self.horizontalLayout_right.addWidget(self.frm_right_main)

        self.frm_inspector = QFrame(self.frm_right)
        self.frm_inspector.setObjectName(u"frm_inspector")
        self.frm_inspector.setMinimumSize(QSize(280, 0))
        self.frm_inspector.setMaximumSize(QSize(360, 16777215))
        self.frm_inspector.setFrameShape(QFrame.StyledPanel)
        self.verticalLayout_inspector = QVBoxLayout(self.frm_inspector)
        self.verticalLayout_inspector.setSpacing(4)
        self.verticalLayout_inspector.setObjectName(u"verticalLayout_inspector")
        self.lbl_inspector_title = QLabel(self.frm_inspector)
        self.lbl_inspector_title.setObjectName(u"lbl_inspector_title")

        self.verticalLayout_inspector.addWidget(self.lbl_inspector_title)

        self.lbl_provenance = QLabel(self.frm_inspector)
        self.lbl_provenance.setObjectName(u"lbl_provenance")
        self.lbl_provenance.setWordWrap(True)

        self.verticalLayout_inspector.addWidget(self.lbl_provenance)

        self.lbl_root_info = QLabel(self.frm_inspector)
        self.lbl_root_info.setObjectName(u"lbl_root_info")
        self.lbl_root_info.setWordWrap(True)

        self.verticalLayout_inspector.addWidget(self.lbl_root_info)

        self.lbl_parent_links = QLabel(self.frm_inspector)
        self.lbl_parent_links.setObjectName(u"lbl_parent_links")
        self.lbl_parent_links.setWordWrap(True)

        self.verticalLayout_inspector.addWidget(self.lbl_parent_links)

        self.lbl_child_links = QLabel(self.frm_inspector)
        self.lbl_child_links.setObjectName(u"lbl_child_links")
        self.lbl_child_links.setWordWrap(True)

        self.verticalLayout_inspector.addWidget(self.lbl_child_links)

        self.lbl_selected_member_info = QLabel(self.frm_inspector)
        self.lbl_selected_member_info.setObjectName(u"lbl_selected_member_info")
        self.lbl_selected_member_info.setWordWrap(True)

        self.verticalLayout_inspector.addWidget(self.lbl_selected_member_info)

        self.lbl_type_status = QLabel(self.frm_inspector)
        self.lbl_type_status.setObjectName(u"lbl_type_status")
        self.lbl_type_status.setWordWrap(True)

        self.verticalLayout_inspector.addWidget(self.lbl_type_status)

        self.btn_scan_child = QPushButton(self.frm_inspector)
        self.btn_scan_child.setObjectName(u"btn_scan_child")

        self.verticalLayout_inspector.addWidget(self.btn_scan_child)

        self.btn_open_child = QPushButton(self.frm_inspector)
        self.btn_open_child.setObjectName(u"btn_open_child")

        self.verticalLayout_inspector.addWidget(self.btn_open_child)

        self.btn_create_child_types = QPushButton(self.frm_inspector)
        self.btn_create_child_types.setObjectName(u"btn_create_child_types")

        self.verticalLayout_inspector.addWidget(self.btn_create_child_types)

        self.btn_create_subtree_types = QPushButton(self.frm_inspector)
        self.btn_create_subtree_types.setObjectName(u"btn_create_subtree_types")

        self.verticalLayout_inspector.addWidget(self.btn_create_subtree_types)

        self.verticalSpacer = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_inspector.addItem(self.verticalSpacer)


        self.horizontalLayout_right.addWidget(self.frm_inspector)


        self.horizontalLayout.addWidget(self.frm_right)


        self.retranslateUi(view_form)

        QMetaObject.connectSlotsByName(view_form)
    # setupUi

    def retranslateUi(self, view_form):
        view_form.setWindowTitle(QCoreApplication.translate("view_form", u"Structure Builder", None))
        self.action_enable.setText(QCoreApplication.translate("view_form", u"Enable Row", None))
#if QT_CONFIG(shortcut)
        self.action_enable.setShortcut(QCoreApplication.translate("view_form", u"E", None))
#endif // QT_CONFIG(shortcut)
        self.action_disable.setText(QCoreApplication.translate("view_form", u"Disable Row", None))
#if QT_CONFIG(shortcut)
        self.action_disable.setShortcut(QCoreApplication.translate("view_form", u"D", None))
#endif // QT_CONFIG(shortcut)
        self.action_resolve.setText(QCoreApplication.translate("view_form", u"Auto Resolve", None))
#if QT_CONFIG(shortcut)
        self.action_resolve.setShortcut(QCoreApplication.translate("view_form", u"R", None))
#endif // QT_CONFIG(shortcut)
        self.action_finalize.setText(QCoreApplication.translate("view_form", u"Finalize", None))
#if QT_CONFIG(shortcut)
        self.action_finalize.setShortcut(QCoreApplication.translate("view_form", u"F", None))
#endif // QT_CONFIG(shortcut)
        self.action_edit.setText(QCoreApplication.translate("view_form", u"Edit Row", None))
#if QT_CONFIG(shortcut)
        self.action_edit.setShortcut(QCoreApplication.translate("view_form", u"Ctrl+E", None))
#endif // QT_CONFIG(shortcut)
        self.action_add_row.setText(QCoreApplication.translate("view_form", u"Add Row", None))
#if QT_CONFIG(shortcut)
        self.action_add_row.setShortcut(QCoreApplication.translate("view_form", u"Insert", None))
#endif // QT_CONFIG(shortcut)
        self.action_duplicate_row.setText(QCoreApplication.translate("view_form", u"Duplicate Row", None))
#if QT_CONFIG(shortcut)
        self.action_duplicate_row.setShortcut(QCoreApplication.translate("view_form", u"Ctrl+D", None))
#endif // QT_CONFIG(shortcut)
        self.action_duplicate_structure.setText(QCoreApplication.translate("view_form", u"Duplicate Structure", None))
#if QT_CONFIG(shortcut)
        self.action_duplicate_structure.setShortcut(QCoreApplication.translate("view_form", u"Ctrl+Shift+D", None))
#endif // QT_CONFIG(shortcut)
        self.action_scan_child.setText(QCoreApplication.translate("view_form", u"Scan Child Structure", None))
#if QT_CONFIG(shortcut)
        self.action_scan_child.setShortcut(QCoreApplication.translate("view_form", u"Ctrl+Shift+C", None))
#endif // QT_CONFIG(shortcut)
        self.action_create_child_types.setText(QCoreApplication.translate("view_form", u"Create Child Types", None))
        self.action_create_subtree_types.setText(QCoreApplication.translate("view_form", u"Create Type Subtree", None))
        self.lbl_title.setText(QCoreApplication.translate("view_form", u"Structures & Scan Graph", None))
        self.input_filter.setPlaceholderText(QCoreApplication.translate("view_form", u"Filter structures...", None))
        self.btn_add.setText(QCoreApplication.translate("view_form", u"Add Structure", None))
        self.btn_duplicate_structure.setText(QCoreApplication.translate("view_form", u"Duplicate Structure", None))
        self.btn_remove.setText(QCoreApplication.translate("view_form", u"Remove Structure", None))
        self.lbl_name.setText(QCoreApplication.translate("view_form", u"Name:", None))
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
        self.btn_auto_resolve.setText(QCoreApplication.translate("view_form", u"Auto Resolve", None))
        self.btn_create_type.setText(QCoreApplication.translate("view_form", u"Create Type", None))
        self.btn_enable_rows.setText(QCoreApplication.translate("view_form", u"Enable", None))
        self.btn_remove_rows.setText(QCoreApplication.translate("view_form", u"Remove", None))
        self.btn_view_scanned_uses.setText(QCoreApplication.translate("view_form", u"View Scanned Uses", None))
        self.btn_edit_row.setText(QCoreApplication.translate("view_form", u"Edit Row", None))
        self.btn_set_origin.setText(QCoreApplication.translate("view_form", u"Set Origin", None))
        self.btn_toggle_array.setText(QCoreApplication.translate("view_form", u"Array", None))
        self.btn_disable_rows.setText(QCoreApplication.translate("view_form", u"Disable", None))
        self.btn_clear_rows.setText(QCoreApplication.translate("view_form", u"Clear", None))
        self.btn_add_row.setText(QCoreApplication.translate("view_form", u"Add Row", None))
        self.btn_recognize_vtable.setText(QCoreApplication.translate("view_form", u"Recognize VTable", None))
        self.btn_duplicate_row.setText(QCoreApplication.translate("view_form", u"Duplicate Row", None))
        self.lbl_summary.setText(QCoreApplication.translate("view_form", u"No structure selected.", None))
        self.lbl_inspector_title.setText(QCoreApplication.translate("view_form", u"Inspector", None))
        self.lbl_provenance.setText(QCoreApplication.translate("view_form", u"Provenance: -", None))
        self.lbl_root_info.setText(QCoreApplication.translate("view_form", u"Root: -", None))
        self.lbl_parent_links.setText(QCoreApplication.translate("view_form", u"Parents: -", None))
        self.lbl_child_links.setText(QCoreApplication.translate("view_form", u"Children: -", None))
        self.lbl_selected_member_info.setText(QCoreApplication.translate("view_form", u"Selected Row: -", None))
        self.lbl_type_status.setText(QCoreApplication.translate("view_form", u"Type Status: not created", None))
        self.btn_scan_child.setText(QCoreApplication.translate("view_form", u"Scan Child Structure", None))
        self.btn_open_child.setText(QCoreApplication.translate("view_form", u"Open Linked Child", None))
        self.btn_create_child_types.setText(QCoreApplication.translate("view_form", u"Create Child Types", None))
        self.btn_create_subtree_types.setText(QCoreApplication.translate("view_form", u"Create Type Subtree", None))
    # retranslateUi

