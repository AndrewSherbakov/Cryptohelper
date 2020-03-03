# -*- coding: utf-8 -*-

import datetime
import random
import OpenSSL

from PyQt5.QtWidgets import QMessageBox, QFileDialog, QInputDialog
from PyQt5.QtGui import QIntValidator
from PyQt5 import QtCore, QtGui, QtWidgets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

ALLOWED_RSA_KEY_SIZES = ['1024', '2048', '4096']

regex = QtCore.QRegExp("^[^А-Яа-я]+$") # Регулярное выражение для валидатора

# Глобальные переменные, вместо буфера обмена
PASSWORD = None
CREATED_PRIVATE_KEY = None
CREATED_PUBLIC_KEY = None
LOADED_PRIVATE_KEY_FROM_PC = None
LOADED_PRIVATE_KEY_FOR_CSR = None
LOADED_PRIVATE_KEY_FOR_SELFSIGNED_CSR = None
GENERATED_CSR = None
GENERATED_SELF_SIGNED_CERTIFICATE = None
LOADED_CSR = None
LOADED_PRIVATE_KEY_FOR_P12 = None
LOADED_CRT_FOR_P12 = None
PFXDATA = None
# ******************************************************************
# Source code
# ******************************************************************
class HashAlgorithms:
    """
        Поддерживаемые алгоритмы для подписи CSR и сертификатов
    """
    sha1 = hashes.SHA1()
    sha256 = hashes.SHA256()
    sha512 = hashes.SHA512()


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        self.window = MainWindow
        self.onlyInt = QIntValidator()
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(771, 431)
        MainWindow.setMinimumSize(QtCore.QSize(771, 431))
        MainWindow.setMaximumSize(QtCore.QSize(771, 431))
        MainWindow.setContextMenuPolicy(QtCore.Qt.NoContextMenu)
        MainWindow.setStyleSheet("font: 25 10pt \"Calibri Light\";")
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setGeometry(QtCore.QRect(0, 10, 771, 431))
        self.tabWidget.setObjectName("tabWidget")
        self.PrivateKeyCreateTab = QtWidgets.QWidget()
        self.PrivateKeyCreateTab.setObjectName("PrivateKeyCreateTab")
        self.line = QtWidgets.QFrame(self.PrivateKeyCreateTab)
        self.line.setGeometry(QtCore.QRect(20, 240, 341, 16))
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.layoutWidget = QtWidgets.QWidget(self.PrivateKeyCreateTab)
        self.layoutWidget.setGeometry(QtCore.QRect(20, 170, 341, 25))
        self.layoutWidget.setObjectName("layoutWidget")
        self.horizontalLayout_20 = QtWidgets.QHBoxLayout(self.layoutWidget)
        self.horizontalLayout_20.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_20.setObjectName("horizontalLayout_20")
        self.label_12 = QtWidgets.QLabel(self.layoutWidget)
        self.label_12.setObjectName("label_12")
        self.horizontalLayout_20.addWidget(self.label_12)
        self.horizontalLayout_14 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_14.setObjectName("horizontalLayout_14")
        self.Tab1KeyFormatPemRadioBtn = QtWidgets.QRadioButton(self.layoutWidget)
        self.Tab1KeyFormatPemRadioBtn.setAutoExclusive(False)
        self.Tab1KeyFormatPemRadioBtn.setObjectName("Tab1KeyFormatPemRadioBtn")
        self.horizontalLayout_14.addWidget(self.Tab1KeyFormatPemRadioBtn)
        self.Tab1KeyFormatPemRadioBtn.clicked.connect(self.der_radio_btn_disable)
        self.Tab1KeyFormatDerRadioBtn = QtWidgets.QRadioButton(self.layoutWidget)
        self.Tab1KeyFormatDerRadioBtn.setAutoExclusive(False)
        self.Tab1KeyFormatDerRadioBtn.setObjectName("Tab1KeyFormatDerRadioBtn")
        self.horizontalLayout_14.addWidget(self.Tab1KeyFormatDerRadioBtn)
        self.Tab1KeyFormatDerRadioBtn.clicked.connect(self.pem_radio_btn_disable)
        self.horizontalLayout_20.addLayout(self.horizontalLayout_14)
        self.layoutWidget1 = QtWidgets.QWidget(self.PrivateKeyCreateTab)
        self.layoutWidget1.setGeometry(QtCore.QRect(20, 200, 341, 25))
        self.layoutWidget1.setObjectName("layoutWidget1")
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout(self.layoutWidget1)
        self.horizontalLayout_3.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.Tab1CreatePrivateKeyBtn = QtWidgets.QPushButton(self.layoutWidget1)
        self.Tab1CreatePrivateKeyBtn.setObjectName("Tab1CreatePrivateKeyBtn")
        self.Tab1CreatePrivateKeyBtn.clicked.connect(self.generate_rsa_private_key)
        self.horizontalLayout_3.addWidget(self.Tab1CreatePrivateKeyBtn)
        self.Tab1SavePrivateKeyBtn = QtWidgets.QPushButton(self.layoutWidget1)
        self.Tab1SavePrivateKeyBtn.setObjectName("Tab1SavePrivateKeyBtn")
        self.horizontalLayout_3.addWidget(self.Tab1SavePrivateKeyBtn)
        self.Tab1SavePrivateKeyBtn.clicked.connect(self.dump_private_key)
        self.layoutWidget2 = QtWidgets.QWidget(self.PrivateKeyCreateTab)
        self.layoutWidget2.setGeometry(QtCore.QRect(20, 10, 341, 118))
        self.layoutWidget2.setObjectName("layoutWidget2")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.layoutWidget2)
        self.verticalLayout_4.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.Tab1KeySizeLabel = QtWidgets.QLabel(self.layoutWidget2)
        self.Tab1KeySizeLabel.setObjectName("Tab1KeySizeLabel")
        self.horizontalLayout.addWidget(self.Tab1KeySizeLabel)
        self.Tab1KeySizeLineEdit = QtWidgets.QLineEdit(self.layoutWidget2)
        self.Tab1KeySizeLineEdit.setMaximumSize(QtCore.QSize(40, 16777215))
        self.Tab1KeySizeLineEdit.setInputMethodHints(QtCore.Qt.ImhNone)
        self.Tab1KeySizeLineEdit.setAlignment(QtCore.Qt.AlignCenter)
        self.Tab1KeySizeLineEdit.setObjectName("Tab1KeySizeLineEdit")
        self.horizontalLayout.addWidget(self.Tab1KeySizeLineEdit)
        self.verticalLayout_4.addLayout(self.horizontalLayout)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.Tab1PasswordLabel = QtWidgets.QLabel(self.layoutWidget2)
        self.Tab1PasswordLabel.setObjectName("Tab1PasswordLabel")
        self.horizontalLayout_4.addWidget(self.Tab1PasswordLabel)
        self.Tab1PasswordLineEdit = QtWidgets.QLineEdit(self.layoutWidget2)
        self.Tab1PasswordLineEdit.setMaxLength(20)
        self.Tab1PasswordLineEdit.setClearButtonEnabled(True)
        self.Tab1PasswordLineEdit.setObjectName("Tab1PasswordLineEdit")
        self.horizontalLayout_4.addWidget(self.Tab1PasswordLineEdit)
        self.verticalLayout_4.addLayout(self.horizontalLayout_4)
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.Tab1KeyLengthLabel = QtWidgets.QLabel(self.layoutWidget2)
        self.Tab1KeyLengthLabel.setObjectName("Tab1KeyLengthLabel")
        self.horizontalLayout_5.addWidget(self.Tab1KeyLengthLabel)
        self.Tab1KeyLengthLineEdit = QtWidgets.QLineEdit(self.layoutWidget2)
        self.Tab1KeyLengthLineEdit.setEnabled(True)
        self.Tab1KeyLengthLineEdit.setMaximumSize(QtCore.QSize(40, 16777215))
        self.Tab1KeyLengthLineEdit.setInputMethodHints(QtCore.Qt.ImhDate | QtCore.Qt.ImhDigitsOnly)
        self.Tab1KeyLengthLineEdit.setAlignment(QtCore.Qt.AlignCenter)
        self.Tab1KeyLengthLineEdit.setObjectName("Tab1KeyLengthLineEdit")
        self.horizontalLayout_5.addWidget(self.Tab1KeyLengthLineEdit)
        self.verticalLayout_4.addLayout(self.horizontalLayout_5)
        self.Tab1PasswordGeneratorBtn = QtWidgets.QPushButton(self.layoutWidget2)
        self.Tab1PasswordGeneratorBtn.setObjectName("Tab1PasswordGeneratorBtn")
        self.Tab1PasswordGeneratorBtn.clicked.connect(self.password_generator)
        self.verticalLayout_4.addWidget(self.Tab1PasswordGeneratorBtn)
        self.Tab1PublicKeyCreateLabel = QtWidgets.QLabel(self.PrivateKeyCreateTab)
        self.Tab1PublicKeyCreateLabel.setEnabled(True)
        self.Tab1PublicKeyCreateLabel.setGeometry(QtCore.QRect(70, 260, 249, 16))
        self.Tab1PublicKeyCreateLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.Tab1PublicKeyCreateLabel.setObjectName("Tab1PublicKeyCreateLabel")
        self.layoutWidget3 = QtWidgets.QWidget(self.PrivateKeyCreateTab)
        self.layoutWidget3.setGeometry(QtCore.QRect(381, 11, 371, 381))
        self.layoutWidget3.setObjectName("layoutWidget3")
        self.verticalLayout_15 = QtWidgets.QVBoxLayout(self.layoutWidget3)
        self.verticalLayout_15.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_15.setObjectName("verticalLayout_15")
        self.Tab1TextBrowser = QtWidgets.QTextBrowser(self.layoutWidget3)
        self.Tab1TextBrowser.setObjectName("Tab1TextBrowser")
        self.Tab1TextBrowser.setStyleSheet("font-size: 11px; font-family: \"Courier New\"")
        self.Tab1TextBrowser.setLineWrapMode(QtWidgets.QTextEdit.NoWrap)
        self.verticalLayout_15.addWidget(self.Tab1TextBrowser)
        self.Tab1ClearBtn = QtWidgets.QPushButton(self.layoutWidget3)
        self.Tab1ClearBtn.setObjectName("Tab1ClearBtn")
        self.Tab1ClearBtn.clicked.connect(self.clear_tab1_text_browser_window)
        self.verticalLayout_15.addWidget(self.Tab1ClearBtn)
        self.widget = QtWidgets.QWidget(self.PrivateKeyCreateTab)
        self.widget.setGeometry(QtCore.QRect(20, 290, 341, 101))
        self.widget.setObjectName("widget")
        self.verticalLayout_16 = QtWidgets.QVBoxLayout(self.widget)
        self.verticalLayout_16.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_16.setObjectName("verticalLayout_16")
        self.horizontalLayout_28 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_28.setObjectName("horizontalLayout_28")
        self.Tab1LoadKeyLabel = QtWidgets.QLabel(self.widget)
        self.Tab1LoadKeyLabel.setObjectName("Tab1LoadKeyLabel")
        self.horizontalLayout_28.addWidget(self.Tab1LoadKeyLabel)
        self.Tab1LoadKeyToolBtn = QtWidgets.QToolButton(self.widget)
        self.Tab1LoadKeyToolBtn.setObjectName("Tab1LoadKeyToolBtn")
        self.horizontalLayout_28.addWidget(self.Tab1LoadKeyToolBtn)
        self.Tab1LoadKeyToolBtn.clicked.connect(self.load_pem_private_key_from_pc)
        self.verticalLayout_16.addLayout(self.horizontalLayout_28)
        self.horizontalLayout_10 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_10.setObjectName("horizontalLayout_10")
        self.Tab1UseCreatedKeyLabel = QtWidgets.QLabel(self.widget)
        self.Tab1UseCreatedKeyLabel.setObjectName("Tab1UseCreatedKeyLabel")
        self.horizontalLayout_10.addWidget(self.Tab1UseCreatedKeyLabel)
        self.Tab1UseCreatedKeyRadioBtn = QtWidgets.QRadioButton(self.widget)
        self.Tab1UseCreatedKeyRadioBtn.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.Tab1UseCreatedKeyRadioBtn.setText("")
        self.Tab1UseCreatedKeyRadioBtn.setAutoExclusive(False)
        self.Tab1UseCreatedKeyRadioBtn.setObjectName("Tab1UseCreatedKeyRadioBtn")
        self.horizontalLayout_10.addWidget(self.Tab1UseCreatedKeyRadioBtn)
        self.Tab1UseCreatedKeyRadioBtn.clicked.connect(
            self.clear_loaded_private_key_while_use_created_key_radio_btn_clicked)
        self.verticalLayout_16.addLayout(self.horizontalLayout_10)
        self.horizontalLayout_27 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_27.setObjectName("horizontalLayout_27")
        self.Tab1CreatePublicKeyBtn = QtWidgets.QPushButton(self.widget)
        self.Tab1CreatePublicKeyBtn.setObjectName("Tab1CreatePublicKeyBtn")
        self.horizontalLayout_27.addWidget(self.Tab1CreatePublicKeyBtn)
        self.Tab1CreatePublicKeyBtn.clicked.connect(self.generate_rsa_public_key)
        self.Tab1SavePublicKeyBtn = QtWidgets.QPushButton(self.widget)
        self.Tab1SavePublicKeyBtn.setObjectName("Tab1SavePublicKeyBtn")
        self.horizontalLayout_27.addWidget(self.Tab1SavePublicKeyBtn)
        self.Tab1SavePublicKeyBtn.clicked.connect(self.dump_public_key)
        self.verticalLayout_16.addLayout(self.horizontalLayout_27)
        self.widget1 = QtWidgets.QWidget(self.PrivateKeyCreateTab)
        self.widget1.setGeometry(QtCore.QRect(21, 141, 341, 23))
        self.widget1.setObjectName("widget1")
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout(self.widget1)
        self.horizontalLayout_6.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        self.Tab1AlgoritmLabel = QtWidgets.QLabel(self.widget1)
        self.Tab1AlgoritmLabel.setObjectName("Tab1AlgoritmLabel")
        self.horizontalLayout_6.addWidget(self.Tab1AlgoritmLabel)
        self.Tab1RsaRadioBtn = QtWidgets.QRadioButton(self.layoutWidget)
        self.Tab1RsaRadioBtn.setMouseTracking(True)
        self.Tab1RsaRadioBtn.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Tab1RsaRadioBtn.setAcceptDrops(False)
        self.Tab1RsaRadioBtn.setCheckable(True)
        self.Tab1RsaRadioBtn.setAutoRepeat(False)
        self.Tab1RsaRadioBtn.setAutoExclusive(False)
        self.Tab1RsaRadioBtn.setObjectName("Tab1RsaRadioBtn")
        self.horizontalLayout_6.addWidget(self.Tab1RsaRadioBtn)
        self.tabWidget.addTab(self.PrivateKeyCreateTab, "")
        self.CertificateRequestTab = QtWidgets.QWidget()
        self.CertificateRequestTab.setObjectName("CertificateRequestTab")
        self.layoutWidget4 = QtWidgets.QWidget(self.CertificateRequestTab)
        self.layoutWidget4.setGeometry(QtCore.QRect(20, 10, 341, 27))
        self.layoutWidget4.setObjectName("layoutWidget4")
        self.horizontalLayout_7 = QtWidgets.QHBoxLayout(self.layoutWidget4)
        self.horizontalLayout_7.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_7.setObjectName("horizontalLayout_7")
        self.Tab2LoadPrivateKeyLabel = QtWidgets.QLabel(self.layoutWidget4)
        self.Tab2LoadPrivateKeyLabel.setObjectName("Tab2LoadPrivateKeyLabel")
        self.horizontalLayout_7.addWidget(self.Tab2LoadPrivateKeyLabel)
        self.Tab2LoadPrivateKeyToolBtn = QtWidgets.QToolButton(self.layoutWidget4)
        self.Tab2LoadPrivateKeyToolBtn.setObjectName("Tab2LoadPrivateKeyToolBtn")
        self.horizontalLayout_7.addWidget(self.Tab2LoadPrivateKeyToolBtn)
        self.Tab2LoadPrivateKeyToolBtn.clicked.connect(self.load_private_key_from_pc_for_csr)
        self.layoutWidget_7 = QtWidgets.QWidget(self.CertificateRequestTab)
        self.layoutWidget_7.setGeometry(QtCore.QRect(20, 210, 341, 141))
        self.layoutWidget_7.setObjectName("layoutWidget_7")
        self.verticalLayout_11 = QtWidgets.QVBoxLayout(self.layoutWidget_7)
        self.verticalLayout_11.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_11.setObjectName("verticalLayout_11")
        self.verticalLayout_12 = QtWidgets.QVBoxLayout()
        self.verticalLayout_12.setObjectName("verticalLayout_12")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.Tab2OptionalTextLabel = QtWidgets.QLabel(self.layoutWidget_7)
        self.Tab2OptionalTextLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.Tab2OptionalTextLabel.setObjectName("Tab2OptionalTextLabel")
        self.verticalLayout_2.addWidget(self.Tab2OptionalTextLabel)
        self.horizontalLayout_21 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_21.setObjectName("horizontalLayout_21")
        self.Tab2AdditionalDnsNameLineEditReadOnly = QtWidgets.QLineEdit(self.layoutWidget_7)
        self.Tab2AdditionalDnsNameLineEditReadOnly.setReadOnly(True)
        self.Tab2AdditionalDnsNameLineEditReadOnly.setObjectName("Tab2AdditionalDnsNameLineEditReadOnly")
        self.horizontalLayout_21.addWidget(self.Tab2AdditionalDnsNameLineEditReadOnly)
        self.Tab2AdditionalDnsNameLineEdit = QtWidgets.QLineEdit(self.layoutWidget_7)
        self.Tab2AdditionalDnsNameLineEdit.setObjectName("Tab2AdditionalDnsNameLineEdit")
        self.horizontalLayout_21.addWidget(self.Tab2AdditionalDnsNameLineEdit)
        self.verticalLayout_2.addLayout(self.horizontalLayout_21)
        self.verticalLayout_12.addLayout(self.verticalLayout_2)
        self.horizontalLayout_26 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_26.setObjectName("horizontalLayout_26")
        self.Tab2SignLabel = QtWidgets.QLabel(self.layoutWidget_7)
        self.Tab2SignLabel.setObjectName("Tab2SignLabel")
        self.horizontalLayout_26.addWidget(self.Tab2SignLabel)
        self.horizontalLayout_16 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_16.setObjectName("horizontalLayout_16")
        self.Tab2Sha1RadioBtn = QtWidgets.QRadioButton(self.layoutWidget_7)
        self.Tab2Sha1RadioBtn.setAutoExclusive(False)
        self.Tab2Sha1RadioBtn.setObjectName("Tab2Sha1RadioBtn")
        self.horizontalLayout_16.addWidget(self.Tab2Sha1RadioBtn)
        self.Tab2Sha1RadioBtn.clicked.connect(self.sha1_radio_btn_behavior)
        self.Tab2Sha256RadioBtn = QtWidgets.QRadioButton(self.layoutWidget_7)
        self.Tab2Sha256RadioBtn.setAutoExclusive(False)
        self.Tab2Sha256RadioBtn.setObjectName("Tab2Sha256RadioBtn")
        self.horizontalLayout_16.addWidget(self.Tab2Sha256RadioBtn)
        self.Tab2Sha256RadioBtn.clicked.connect(self.sha256_radio_btn_behavior)
        self.Tab2Sha512RadioBtn = QtWidgets.QRadioButton(self.layoutWidget_7)
        self.Tab2Sha512RadioBtn.setAutoExclusive(False)
        self.Tab2Sha512RadioBtn.setObjectName("Tab2Sha512RadioBtn")
        self.horizontalLayout_16.addWidget(self.Tab2Sha512RadioBtn)
        self.Tab2Sha512RadioBtn.clicked.connect(self.sha512_radio_btn_behavior)
        self.horizontalLayout_26.addLayout(self.horizontalLayout_16)
        self.verticalLayout_12.addLayout(self.horizontalLayout_26)
        self.verticalLayout_11.addLayout(self.verticalLayout_12)
        self.horizontalLayout_31 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_31.setObjectName("horizontalLayout_31")
        self.Tab2GenerateRequestBtn = QtWidgets.QPushButton(self.layoutWidget_7)
        self.Tab2GenerateRequestBtn.setObjectName("Tab2GenerateRequestBtn")
        self.horizontalLayout_31.addWidget(self.Tab2GenerateRequestBtn)
        self.Tab2GenerateRequestBtn.clicked.connect(self.generate_csr)
        self.Tab2SaveCsrBtn = QtWidgets.QPushButton(self.layoutWidget_7)
        self.Tab2SaveCsrBtn.setObjectName("Tab2SaveCsrBtn")
        self.horizontalLayout_31.addWidget(self.Tab2SaveCsrBtn)
        self.Tab2SaveCsrBtn.clicked.connect(self.dump_csr)
        self.verticalLayout_11.addLayout(self.horizontalLayout_31)
        self.layoutWidget_2 = QtWidgets.QWidget(self.CertificateRequestTab)
        self.layoutWidget_2.setGeometry(QtCore.QRect(380, 10, 371, 381))
        self.layoutWidget_2.setObjectName("layoutWidget_2")
        self.verticalLayout_5 = QtWidgets.QVBoxLayout(self.layoutWidget_2)
        self.verticalLayout_5.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        self.Tab2TextBrowser = QtWidgets.QTextBrowser(self.layoutWidget_2)
        self.Tab2TextBrowser.setObjectName("Tab2TextBrowser")
        self.Tab2TextBrowser.setStyleSheet("font-size: 11px; font-family: \"Courier New\"")
        self.Tab2TextBrowser.setLineWrapMode(QtWidgets.QTextEdit.NoWrap)
        self.verticalLayout_5.addWidget(self.Tab2TextBrowser)
        self.Tab2ClearBtn = QtWidgets.QPushButton(self.layoutWidget_2)
        self.Tab2ClearBtn.clicked.connect(self.clear_tab2_text_browser_window)
        self.Tab2ClearBtn.setObjectName("Tab2ClearBtn")
        self.verticalLayout_5.addWidget(self.Tab2ClearBtn)
        self.layoutWidget5 = QtWidgets.QWidget(self.CertificateRequestTab)
        self.layoutWidget5.setGeometry(QtCore.QRect(21, 43, 341, 172))
        self.layoutWidget5.setObjectName("layoutWidget5")
        self.horizontalLayout_22 = QtWidgets.QHBoxLayout(self.layoutWidget5)
        self.horizontalLayout_22.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_22.setObjectName("horizontalLayout_22")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout()
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.Tab2CountryReadOnlyLineEdit = QtWidgets.QLineEdit(self.layoutWidget5)
        self.Tab2CountryReadOnlyLineEdit.setReadOnly(True)
        self.Tab2CountryReadOnlyLineEdit.setObjectName("Tab2CountryReadOnlyLineEdit")
        self.verticalLayout_3.addWidget(self.Tab2CountryReadOnlyLineEdit)
        self.Tab2StateReadOnlyLineEdit = QtWidgets.QLineEdit(self.layoutWidget5)
        self.Tab2StateReadOnlyLineEdit.setReadOnly(True)
        self.Tab2StateReadOnlyLineEdit.setObjectName("Tab2StateReadOnlyLineEdit")
        self.verticalLayout_3.addWidget(self.Tab2StateReadOnlyLineEdit)
        self.Tab2LocationReadonlyLineEdit = QtWidgets.QLineEdit(self.layoutWidget5)
        self.Tab2LocationReadonlyLineEdit.setReadOnly(True)
        self.Tab2LocationReadonlyLineEdit.setObjectName("Tab2LocationReadonlyLineEdit")
        self.verticalLayout_3.addWidget(self.Tab2LocationReadonlyLineEdit)
        self.Tab2OrganizationReadOnlyLineEdit = QtWidgets.QLineEdit(self.layoutWidget5)
        self.Tab2OrganizationReadOnlyLineEdit.setReadOnly(True)
        self.Tab2OrganizationReadOnlyLineEdit.setObjectName("Tab2OrganizationReadOnlyLineEdit")
        self.verticalLayout_3.addWidget(self.Tab2OrganizationReadOnlyLineEdit)
        self.Tab2OrgUnitReadOnlyLineEdit = QtWidgets.QLineEdit(self.layoutWidget5)
        self.Tab2OrgUnitReadOnlyLineEdit.setReadOnly(True)
        self.Tab2OrgUnitReadOnlyLineEdit.setObjectName("Tab2OrgUnitReadOnlyLineEdit")
        self.verticalLayout_3.addWidget(self.Tab2OrgUnitReadOnlyLineEdit)
        self.Tab2EmailReadOnlyLineEdit = QtWidgets.QLineEdit(self.layoutWidget5)
        self.Tab2EmailReadOnlyLineEdit.setReadOnly(True)
        self.Tab2EmailReadOnlyLineEdit.setObjectName("Tab2EmailReadOnlyLineEdit")
        self.verticalLayout_3.addWidget(self.Tab2EmailReadOnlyLineEdit)
        self.horizontalLayout_22.addLayout(self.verticalLayout_3)
        self.verticalLayout_10 = QtWidgets.QVBoxLayout()
        self.verticalLayout_10.setObjectName("verticalLayout_10")
        self.Tab2CountryLineEdit = QtWidgets.QLineEdit(self.layoutWidget5)
        self.Tab2CountryLineEdit.setWhatsThis("")
        self.Tab2CountryLineEdit.setAutoFillBackground(False)
        self.Tab2CountryLineEdit.setInputMethodHints(QtCore.Qt.ImhLatinOnly)
        self.Tab2CountryLineEdit.setText("")
        self.Tab2CountryLineEdit.setCursorPosition(0)
        self.Tab2CountryLineEdit.setObjectName("Tab2CountryLineEdit")
        self.verticalLayout_10.addWidget(self.Tab2CountryLineEdit)
        self.Tab2StateLineEdit = QtWidgets.QLineEdit(self.layoutWidget5)
        self.Tab2StateLineEdit.setWhatsThis("")
        self.Tab2StateLineEdit.setAutoFillBackground(False)
        self.Tab2StateLineEdit.setText("")
        self.Tab2StateLineEdit.setCursorPosition(0)
        self.Tab2StateLineEdit.setObjectName("Tab2StateLineEdit")
        self.verticalLayout_10.addWidget(self.Tab2StateLineEdit)
        self.Tab2LocationLineEdit = QtWidgets.QLineEdit(self.layoutWidget5)
        self.Tab2LocationLineEdit.setText("")
        self.Tab2LocationLineEdit.setObjectName("Tab2LocationLineEdit")
        self.verticalLayout_10.addWidget(self.Tab2LocationLineEdit)
        self.Tab2OrganizationLineEdit = QtWidgets.QLineEdit(self.layoutWidget5)
        self.Tab2OrganizationLineEdit.setText("")
        self.Tab2OrganizationLineEdit.setObjectName("Tab2OrganizationLineEdit")
        self.verticalLayout_10.addWidget(self.Tab2OrganizationLineEdit)
        self.Tab2OrgUnitLineEdit = QtWidgets.QLineEdit(self.layoutWidget5)
        self.Tab2OrgUnitLineEdit.setText("")
        self.Tab2OrgUnitLineEdit.setObjectName("Tab2OrgUnitLineEdit")
        self.verticalLayout_10.addWidget(self.Tab2OrgUnitLineEdit)
        self.Tab2EmailLineEdit = QtWidgets.QLineEdit(self.layoutWidget5)
        self.Tab2EmailLineEdit.setText("")
        self.Tab2EmailLineEdit.setObjectName("Tab2EmailLineEdit")
        self.verticalLayout_10.addWidget(self.Tab2EmailLineEdit)
        self.horizontalLayout_22.addLayout(self.verticalLayout_10)
        self.tabWidget.addTab(self.CertificateRequestTab, "")
        self.SelfSignedCertificateTab = QtWidgets.QWidget()
        self.SelfSignedCertificateTab.setObjectName("SelfSignedCertificateTab")
        self.layoutWidget6 = QtWidgets.QWidget(self.SelfSignedCertificateTab)
        self.layoutWidget6.setGeometry(QtCore.QRect(20, 211, 341, 161))
        self.layoutWidget6.setObjectName("layoutWidget6")
        self.verticalLayout_7 = QtWidgets.QVBoxLayout(self.layoutWidget6)
        self.verticalLayout_7.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_7.setObjectName("verticalLayout_7")
        self.verticalLayout_6 = QtWidgets.QVBoxLayout()
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.Tab3OptionalLabel = QtWidgets.QLabel(self.layoutWidget6)
        self.Tab3OptionalLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.Tab3OptionalLabel.setObjectName("Tab3OptionalLabel")
        self.verticalLayout.addWidget(self.Tab3OptionalLabel)
        self.horizontalLayout_18 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_18.setObjectName("horizontalLayout_18")
        self.Tab3AdditionalReadOnlyDnsNameLineEdit = QtWidgets.QLineEdit(self.layoutWidget6)
        self.Tab3AdditionalReadOnlyDnsNameLineEdit.setReadOnly(True)
        self.Tab3AdditionalReadOnlyDnsNameLineEdit.setObjectName("Tab3AdditionalReadOnlyDnsNameLineEdit")
        self.horizontalLayout_18.addWidget(self.Tab3AdditionalReadOnlyDnsNameLineEdit)
        self.Tab3AdditionalDnsNameLineEdit = QtWidgets.QLineEdit(self.layoutWidget6)
        self.Tab3AdditionalDnsNameLineEdit.setObjectName("Tab3AdditionalDnsNameLineEdit")
        self.horizontalLayout_18.addWidget(self.Tab3AdditionalDnsNameLineEdit)
        self.verticalLayout.addLayout(self.horizontalLayout_18)
        self.verticalLayout_6.addLayout(self.verticalLayout)
        self.horizontalLayout_9 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_9.setObjectName("horizontalLayout_9")
        self.Tab3CertificateValidityInDaysLabel = QtWidgets.QLabel(self.layoutWidget6)
        self.Tab3CertificateValidityInDaysLabel.setObjectName("Tab3CertificateValidityInDaysLabel")
        self.horizontalLayout_9.addWidget(self.Tab3CertificateValidityInDaysLabel)
        self.Tab3CertificateValidityInDaysLineEdit = QtWidgets.QLineEdit(self.layoutWidget6)
        self.Tab3CertificateValidityInDaysLineEdit.setMaximumSize(QtCore.QSize(40, 16777215))
        self.Tab3CertificateValidityInDaysLineEdit.setObjectName("Tab3CertificateValidityInDaysLineEdit")
        self.horizontalLayout_9.addWidget(self.Tab3CertificateValidityInDaysLineEdit)
        self.verticalLayout_6.addLayout(self.horizontalLayout_9)
        self.horizontalLayout_23 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_23.setObjectName("horizontalLayout_23")
        self.Tab3SignLabel = QtWidgets.QLabel(self.layoutWidget6)
        self.Tab3SignLabel.setObjectName("Tab3SignLabel")
        self.horizontalLayout_23.addWidget(self.Tab3SignLabel)
        self.horizontalLayout_15 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_15.setObjectName("horizontalLayout_15")
        self.Tab3Sha1RadioBtn = QtWidgets.QRadioButton(self.layoutWidget6)
        self.Tab3Sha1RadioBtn.setAutoExclusive(False)
        self.Tab3Sha1RadioBtn.setObjectName("Tab3Sha1RadioBtn")
        self.horizontalLayout_15.addWidget(self.Tab3Sha1RadioBtn)
        self.Tab3Sha1RadioBtn.clicked.connect(self.tab3_sha1_radio_btn_behavior)
        self.Tab3SignSha256RadioBtn = QtWidgets.QRadioButton(self.layoutWidget6)
        self.Tab3SignSha256RadioBtn.setAutoExclusive(False)
        self.Tab3SignSha256RadioBtn.setObjectName("Tab3SignSha256RadioBtn")
        self.horizontalLayout_15.addWidget(self.Tab3SignSha256RadioBtn)
        self.Tab3SignSha256RadioBtn.clicked.connect(self.tab3_sha256_radio_btn_behavior)
        self.Tab3Sha512RadioBtn = QtWidgets.QRadioButton(self.layoutWidget6)
        self.Tab3Sha512RadioBtn.setAutoExclusive(False)
        self.Tab3Sha512RadioBtn.setObjectName("Tab3Sha512RadioBtn")
        self.horizontalLayout_15.addWidget(self.Tab3Sha512RadioBtn)
        self.Tab3Sha512RadioBtn.clicked.connect(self.tab3_sha512_radio_btn_behavior)
        self.horizontalLayout_23.addLayout(self.horizontalLayout_15)
        self.verticalLayout_6.addLayout(self.horizontalLayout_23)
        self.verticalLayout_7.addLayout(self.verticalLayout_6)
        self.horizontalLayout_29 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_29.setObjectName("horizontalLayout_29")
        self.Tab3GenerateRequestBtn = QtWidgets.QPushButton(self.layoutWidget6)
        self.Tab3GenerateRequestBtn.setObjectName("Tab3GenerateRequestBtn")
        self.horizontalLayout_29.addWidget(self.Tab3GenerateRequestBtn)
        self.Tab3GenerateRequestBtn.clicked.connect(self.generate_selfsigned_csr)
        self.Tab3SaveSelfSignedCertBtn = QtWidgets.QPushButton(self.layoutWidget6)
        self.Tab3SaveSelfSignedCertBtn.setObjectName("Tab3SaveSelfSignedCertBtn")
        self.Tab3SaveSelfSignedCertBtn.clicked.connect(self.dump_selfsigned_crt)
        self.horizontalLayout_29.addWidget(self.Tab3SaveSelfSignedCertBtn)
        self.verticalLayout_7.addLayout(self.horizontalLayout_29)
        self.layoutWidget_3 = QtWidgets.QWidget(self.SelfSignedCertificateTab)
        self.layoutWidget_3.setGeometry(QtCore.QRect(380, 10, 371, 381))
        self.layoutWidget_3.setObjectName("layoutWidget_3")
        self.verticalLayout_8 = QtWidgets.QVBoxLayout(self.layoutWidget_3)
        self.verticalLayout_8.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_8.setObjectName("verticalLayout_8")
        self.Tab3TextBrowser = QtWidgets.QTextBrowser(self.layoutWidget_3)
        self.Tab3TextBrowser.setObjectName("Tab3TextBrowser")
        self.Tab3TextBrowser.setStyleSheet("font-size: 11px; font-family: \"Courier New\"")
        self.Tab3TextBrowser.setLineWrapMode(QtWidgets.QTextEdit.NoWrap)
        self.verticalLayout_8.addWidget(self.Tab3TextBrowser)
        self.Tab3ClearBtn = QtWidgets.QPushButton(self.layoutWidget_3)
        self.Tab3ClearBtn.clicked.connect(self.clear_tab3_text_browser_window)
        self.Tab3ClearBtn.setObjectName("Tab3ClearBtn")
        self.verticalLayout_8.addWidget(self.Tab3ClearBtn)
        self.layoutWidget7 = QtWidgets.QWidget(self.SelfSignedCertificateTab)
        self.layoutWidget7.setGeometry(QtCore.QRect(20, 42, 341, 172))
        self.layoutWidget7.setObjectName("layoutWidget7")
        self.horizontalLayout_13 = QtWidgets.QHBoxLayout(self.layoutWidget7)
        self.horizontalLayout_13.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_13.setObjectName("horizontalLayout_13")
        self.verticalLayout_13 = QtWidgets.QVBoxLayout()
        self.verticalLayout_13.setObjectName("verticalLayout_13")
        self.Tab3CountryReadOnlyLineEdit = QtWidgets.QLineEdit(self.layoutWidget7)
        self.Tab3CountryReadOnlyLineEdit.setReadOnly(True)
        self.Tab3CountryReadOnlyLineEdit.setObjectName("Tab3CountryReadOnlyLineEdit")
        self.verticalLayout_13.addWidget(self.Tab3CountryReadOnlyLineEdit)
        self.Tab3StateReadOnlyLineEdit = QtWidgets.QLineEdit(self.layoutWidget7)
        self.Tab3StateReadOnlyLineEdit.setReadOnly(True)
        self.Tab3StateReadOnlyLineEdit.setObjectName("Tab3StateReadOnlyLineEdit")
        self.verticalLayout_13.addWidget(self.Tab3StateReadOnlyLineEdit)
        self.Tab3LocationReadOnlyLineEdit = QtWidgets.QLineEdit(self.layoutWidget7)
        self.Tab3LocationReadOnlyLineEdit.setReadOnly(True)
        self.Tab3LocationReadOnlyLineEdit.setObjectName("Tab3LocationReadOnlyLineEdit")
        self.verticalLayout_13.addWidget(self.Tab3LocationReadOnlyLineEdit)
        self.Tab3OrganizationReadOnlyLineEdit = QtWidgets.QLineEdit(self.layoutWidget7)
        self.Tab3OrganizationReadOnlyLineEdit.setReadOnly(True)
        self.Tab3OrganizationReadOnlyLineEdit.setObjectName("Tab3OrganizationReadOnlyLineEdit")
        self.verticalLayout_13.addWidget(self.Tab3OrganizationReadOnlyLineEdit)
        self.Tab3OrgUnitReadOnlyLineEdit = QtWidgets.QLineEdit(self.layoutWidget7)
        self.Tab3OrgUnitReadOnlyLineEdit.setReadOnly(True)
        self.Tab3OrgUnitReadOnlyLineEdit.setObjectName("Tab3OrgUnitReadOnlyLineEdit")
        self.verticalLayout_13.addWidget(self.Tab3OrgUnitReadOnlyLineEdit)
        self.Tab3EmailReadOnlyLineEdit = QtWidgets.QLineEdit(self.layoutWidget7)
        self.Tab3EmailReadOnlyLineEdit.setReadOnly(True)
        self.Tab3EmailReadOnlyLineEdit.setObjectName("Tab3EmailReadOnlyLineEdit")
        self.verticalLayout_13.addWidget(self.Tab3EmailReadOnlyLineEdit)
        self.horizontalLayout_13.addLayout(self.verticalLayout_13)
        self.verticalLayout_14 = QtWidgets.QVBoxLayout()
        self.verticalLayout_14.setObjectName("verticalLayout_14")
        self.Tab3CountryLineEdit = QtWidgets.QLineEdit(self.layoutWidget7)
        self.Tab3CountryLineEdit.setWhatsThis("")
        self.Tab3CountryLineEdit.setAutoFillBackground(False)
        self.Tab3CountryLineEdit.setText("")
        self.Tab3CountryLineEdit.setCursorPosition(0)
        self.Tab3CountryLineEdit.setObjectName("Tab3CountryLineEdit")
        self.verticalLayout_14.addWidget(self.Tab3CountryLineEdit)
        self.Tab3StateLineEdit = QtWidgets.QLineEdit(self.layoutWidget7)
        self.Tab3StateLineEdit.setWhatsThis("")
        self.Tab3StateLineEdit.setAutoFillBackground(False)
        self.Tab3StateLineEdit.setText("")
        self.Tab3StateLineEdit.setCursorPosition(0)
        self.Tab3StateLineEdit.setObjectName("Tab3StateLineEdit")
        self.verticalLayout_14.addWidget(self.Tab3StateLineEdit)
        self.Tab3LocationLineEdit = QtWidgets.QLineEdit(self.layoutWidget7)
        self.Tab3LocationLineEdit.setText("")
        self.Tab3LocationLineEdit.setObjectName("Tab3LocationLineEdit")
        self.verticalLayout_14.addWidget(self.Tab3LocationLineEdit)
        self.Tab3OrganizationLineEdit = QtWidgets.QLineEdit(self.layoutWidget7)
        self.Tab3OrganizationLineEdit.setText("")
        self.Tab3OrganizationLineEdit.setObjectName("Tab3OrganizationLineEdit")
        self.verticalLayout_14.addWidget(self.Tab3OrganizationLineEdit)
        self.Tab3OrgUnitLineEdit = QtWidgets.QLineEdit(self.layoutWidget7)
        self.Tab3OrgUnitLineEdit.setText("")
        self.Tab3OrgUnitLineEdit.setObjectName("Tab3OrgUnitLineEdit")
        self.verticalLayout_14.addWidget(self.Tab3OrgUnitLineEdit)
        self.Tab3EmailLineEdit = QtWidgets.QLineEdit(self.layoutWidget7)
        self.Tab3EmailLineEdit.setText("")
        self.Tab3EmailLineEdit.setObjectName("Tab3EmailLineEdit")
        self.verticalLayout_14.addWidget(self.Tab3EmailLineEdit)
        self.horizontalLayout_13.addLayout(self.verticalLayout_14)
        self.widget2 = QtWidgets.QWidget(self.SelfSignedCertificateTab)
        self.widget2.setGeometry(QtCore.QRect(20, 10, 341, 24))
        self.widget2.setObjectName("widget2")
        self.horizontalLayout_8 = QtWidgets.QHBoxLayout(self.widget2)
        self.horizontalLayout_8.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_8.setObjectName("horizontalLayout_8")
        self.Tab3LoadPrivateKeyLabel = QtWidgets.QLabel(self.widget2)
        self.Tab3LoadPrivateKeyLabel.setObjectName("Tab3LoadPrivateKeyLabel")
        self.horizontalLayout_8.addWidget(self.Tab3LoadPrivateKeyLabel)
        self.Tab3LoadPrivateKeyToolBtn = QtWidgets.QToolButton(self.widget2)
        self.Tab3LoadPrivateKeyToolBtn.setObjectName("Tab3LoadPrivateKeyToolBtn")
        self.horizontalLayout_8.addWidget(self.Tab3LoadPrivateKeyToolBtn)
        self.Tab3LoadPrivateKeyToolBtn.clicked.connect(self.load_private_key_from_pc_for_selfsigned_csr)
        self.tabWidget.addTab(self.SelfSignedCertificateTab, "")
        self.P12ContainerTab = QtWidgets.QWidget()
        self.P12ContainerTab.setObjectName("P12ContainerTab")
        self.Tab4CertViewBtn = QtWidgets.QPushButton(self.P12ContainerTab)
        self.Tab4CertViewBtn.setGeometry(QtCore.QRect(120, 50, 136, 23))
        self.Tab4CertViewBtn.setObjectName("Tab4CertViewBtn")
        self.Tab4CertViewBtn.clicked.connect(self.view_cert_for_p12_info)
        self.layoutWidget_5 = QtWidgets.QWidget(self.P12ContainerTab)
        self.layoutWidget_5.setGeometry(QtCore.QRect(380, 10, 371, 381))
        self.layoutWidget_5.setObjectName("layoutWidget_5")
        self.verticalLayout_18 = QtWidgets.QVBoxLayout(self.layoutWidget_5)
        self.verticalLayout_18.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_18.setObjectName("verticalLayout_18")
        self.Tab4TextBrowser = QtWidgets.QTextBrowser(self.layoutWidget_5)
        self.Tab4TextBrowser.setObjectName("Tab4TextBrowser")
        self.Tab4TextBrowser.setStyleSheet("font-size: 11px; font-family: \"Courier New\"")
        self.Tab4TextBrowser.setLineWrapMode(QtWidgets.QTextEdit.NoWrap)
        self.verticalLayout_18.addWidget(self.Tab4TextBrowser)
        self.Tab4ClearBtn = QtWidgets.QPushButton(self.layoutWidget_5)
        self.Tab4ClearBtn.setObjectName("Tab4ClearBtn")
        self.verticalLayout_18.addWidget(self.Tab4ClearBtn)
        self.Tab4ClearBtn.clicked.connect(self.clear_tab4_text_browser_window)
        self.widget3 = QtWidgets.QWidget(self.P12ContainerTab)
        self.widget3.setGeometry(QtCore.QRect(20, 180, 341, 25))
        self.widget3.setObjectName("widget3")
        self.horizontalLayout_19 = QtWidgets.QHBoxLayout(self.widget3)
        self.horizontalLayout_19.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_19.setObjectName("horizontalLayout_19")
        self.Tab4CreatePfxBtn = QtWidgets.QPushButton(self.widget3)
        self.Tab4CreatePfxBtn.setObjectName("Tab4CreatePfxBtn")
        self.Tab4CreatePfxBtn.clicked.connect(self.generate_p12)
        self.horizontalLayout_19.addWidget(self.Tab4CreatePfxBtn)
        self.Tab4SavePfxBtn = QtWidgets.QPushButton(self.widget3)
        self.Tab4SavePfxBtn.setObjectName("Tab4SavePfxBtn")
        self.Tab4SavePfxBtn.clicked.connect(self.dump_p12)
        self.horizontalLayout_19.addWidget(self.Tab4SavePfxBtn)
        self.widget4 = QtWidgets.QWidget(self.P12ContainerTab)
        self.widget4.setGeometry(QtCore.QRect(20, 130, 341, 25))
        self.widget4.setObjectName("widget4")
        self.horizontalLayout_17 = QtWidgets.QHBoxLayout(self.widget4)
        self.horizontalLayout_17.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_17.setObjectName("horizontalLayout_17")
        self.Tab4PasswordLabel = QtWidgets.QLabel(self.widget4)
        self.Tab4PasswordLabel.setObjectName("Tab4PasswordLabel")
        self.horizontalLayout_17.addWidget(self.Tab4PasswordLabel)
        self.Tab4PasswordLineEdit = QtWidgets.QLineEdit(self.widget4)
        LatinTextValidator = QtGui.QRegExpValidator(regex, self.Tab4PasswordLineEdit)
        self.Tab4PasswordLineEdit.setObjectName("Tab4PasswordLineEdit")
        self.Tab4PasswordLineEdit.setValidator(LatinTextValidator)
        self.Tab4PasswordLineEdit.setClearButtonEnabled(True)
        self.horizontalLayout_17.addWidget(self.Tab4PasswordLineEdit)
        self.widget5 = QtWidgets.QWidget(self.P12ContainerTab)
        self.widget5.setGeometry(QtCore.QRect(21, 11, 341, 24))
        self.widget5.setObjectName("widget5")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.widget5)
        self.horizontalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.Tab4LoadCertLabel = QtWidgets.QLabel(self.widget5)
        self.Tab4LoadCertLabel.setObjectName("Tab4LoadCertLabel")
        self.horizontalLayout_2.addWidget(self.Tab4LoadCertLabel)
        self.Tab4LoadCertBtn_2 = QtWidgets.QToolButton(self.widget5)
        self.Tab4LoadCertBtn_2.setObjectName("Tab4LoadCertBtn_2")
        self.Tab4LoadCertBtn_2.clicked.connect(self.load_cert_for_p12)
        self.horizontalLayout_2.addWidget(self.Tab4LoadCertBtn_2)
        self.widget6 = QtWidgets.QWidget(self.P12ContainerTab)
        self.widget6.setGeometry(QtCore.QRect(20, 90, 341, 24))
        self.widget6.setObjectName("widget6")
        self.horizontalLayout_11 = QtWidgets.QHBoxLayout(self.widget6)
        self.horizontalLayout_11.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_11.setObjectName("horizontalLayout_11")
        self.Tab4LoadPrivateKeyLabel = QtWidgets.QLabel(self.widget6)
        self.Tab4LoadPrivateKeyLabel.setObjectName("Tab4LoadPrivateKeyLabel")
        self.horizontalLayout_11.addWidget(self.Tab4LoadPrivateKeyLabel)
        self.Tab4LoadPrivateKeyBtn = QtWidgets.QToolButton(self.widget6)
        self.Tab4LoadPrivateKeyBtn.setObjectName("Tab4LoadPrivateKeyBtn")
        self.Tab4LoadPrivateKeyBtn.clicked.connect(self.load_private_key_for_p12)
        self.horizontalLayout_11.addWidget(self.Tab4LoadPrivateKeyBtn)
        self.tabWidget.addTab(self.P12ContainerTab, "")
        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "CryptoHelper"))
        self.label_12.setText(_translate("MainWindow", "Формат ключа(кодировка):"))
        self.Tab1KeyFormatPemRadioBtn.setText(_translate("MainWindow", "PEM"))
        self.Tab1KeyFormatDerRadioBtn.setText(_translate("MainWindow", "DER"))
        self.Tab1CreatePrivateKeyBtn.setText(_translate("MainWindow", "Создать закрытый ключ"))
        self.Tab1SavePrivateKeyBtn.setText(_translate("MainWindow", "Сохранить в файл"))
        self.Tab1KeySizeLabel.setText(_translate("MainWindow", "Размер ключа, в битах:"))
        self.Tab1KeySizeLineEdit.setPlaceholderText(_translate("MainWindow", "2048"))
        self.Tab1PasswordLabel.setText(_translate("MainWindow", "Пароль:"))
        self.Tab1KeyLengthLabel.setText(_translate("MainWindow", "Длина пароля:"))
        self.Tab1KeyLengthLineEdit.setPlaceholderText(_translate("MainWindow", "20"))
        self.Tab1PasswordGeneratorBtn.setText(_translate("MainWindow", "Генерировать пароль"))
        self.Tab1PublicKeyCreateLabel.setText(_translate("MainWindow", "Создать открытый ключ на основе закрытого:"))
        self.Tab1TextBrowser.setHtml(_translate("MainWindow",
                                                "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
                                                "<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
                                                "p, li { white-space: pre-wrap; }\n"
                                                "</style></head><body style=\" font-family:\'Calibri Light\'; font-size:10pt; font-weight:24; font-style:normal;\">\n"
                                                "<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p></body></html>"))
        self.Tab1ClearBtn.setText(_translate("MainWindow", "Очистить"))
        self.Tab1LoadKeyLabel.setText(_translate("MainWindow", "Загрузить закрытый ключ:"))
        self.Tab1LoadKeyToolBtn.setText(_translate("MainWindow", "..."))
        self.Tab1UseCreatedKeyLabel.setText(_translate("MainWindow", "Использовать созданный"))
        self.Tab1CreatePublicKeyBtn.setText(_translate("MainWindow", "Создать открытый ключ"))
        self.Tab1SavePublicKeyBtn.setText(_translate("MainWindow", "Сохранить в файл"))
        self.Tab1AlgoritmLabel.setText(_translate("MainWindow", "Алгоритм(Тип ключа):"))
        self.Tab1RsaRadioBtn.setText(_translate("MainWindow", "RSA"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.PrivateKeyCreateTab),
                                  _translate("MainWindow", "Создать закрытый ключ"))
        self.Tab2LoadPrivateKeyLabel.setText(_translate("MainWindow", "Загрузить закрытый ключ:"))
        self.Tab2LoadPrivateKeyToolBtn.setText(_translate("MainWindow", "..."))
        self.Tab2OptionalTextLabel.setText(_translate("MainWindow", "Опционально:"))
        self.Tab2AdditionalDnsNameLineEditReadOnly.setText(_translate("MainWindow", "Дополнительное DNS имя:"))
        self.Tab2AdditionalDnsNameLineEdit.setPlaceholderText(_translate("MainWindow", "some-syte.com"))
        self.Tab2SignLabel.setText(_translate("MainWindow", "Подпись(sign):"))
        self.Tab2Sha1RadioBtn.setText(_translate("MainWindow", "SHA1"))
        self.Tab2Sha256RadioBtn.setText(_translate("MainWindow", "SHA256"))
        self.Tab2Sha512RadioBtn.setText(_translate("MainWindow", "SHA512"))
        self.Tab2GenerateRequestBtn.setText(_translate("MainWindow", "Сгенерировать запрос"))
        self.Tab2SaveCsrBtn.setText(_translate("MainWindow", "Сохранить в файл"))
        self.Tab2ClearBtn.setText(_translate("MainWindow", "Очистить"))
        self.Tab2CountryReadOnlyLineEdit.setText(_translate("MainWindow", "Страна(C):"))
        self.Tab2StateReadOnlyLineEdit.setText(_translate("MainWindow", "Область(S):"))
        self.Tab2LocationReadonlyLineEdit.setText(_translate("MainWindow", "Расположение(L):"))
        self.Tab2OrganizationReadOnlyLineEdit.setText(_translate("MainWindow", "Организация(O):"))
        self.Tab2OrgUnitReadOnlyLineEdit.setText(_translate("MainWindow", "Подразделение(OU):"))
        self.Tab2EmailReadOnlyLineEdit.setText(_translate("MainWindow", "Email"))
        self.Tab2CountryLineEdit.setPlaceholderText(_translate("MainWindow", "RU"))
        self.Tab2StateLineEdit.setPlaceholderText(_translate("MainWindow", "Crimea"))
        self.Tab2LocationLineEdit.setPlaceholderText(_translate("MainWindow", "Sevastopol"))
        self.Tab2OrganizationLineEdit.setPlaceholderText(_translate("MainWindow", "Payberry"))
        self.Tab2OrgUnitLineEdit.setPlaceholderText(_translate("MainWindow", "STP"))
        self.Tab2EmailLineEdit.setPlaceholderText(_translate("MainWindow", "helpdesk@payberry.ru"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.CertificateRequestTab),
                                  _translate("MainWindow", "Запрос на сертификат(CSR)"))
        self.Tab3OptionalLabel.setText(_translate("MainWindow", "Опционально:"))
        self.Tab3AdditionalReadOnlyDnsNameLineEdit.setText(_translate("MainWindow", "Дополнительное DNS имя:"))
        self.Tab3AdditionalDnsNameLineEdit.setPlaceholderText(_translate("MainWindow", "some-syte.com"))
        self.Tab3CertificateValidityInDaysLabel.setText(_translate("MainWindow", "Время действия, в днях:"))
        self.Tab3SignLabel.setText(_translate("MainWindow", "Подпись(sign):"))
        self.Tab3Sha1RadioBtn.setText(_translate("MainWindow", "SHA1"))
        self.Tab3SignSha256RadioBtn.setText(_translate("MainWindow", "SHA256"))
        self.Tab3Sha512RadioBtn.setText(_translate("MainWindow", "SHA512"))
        self.Tab3GenerateRequestBtn.setText(_translate("MainWindow", "Сгенерировать запрос"))
        self.Tab3SaveSelfSignedCertBtn.setText(_translate("MainWindow", "Сохранить в файл"))
        self.Tab3ClearBtn.setText(_translate("MainWindow", "Очистить"))
        self.Tab3CountryReadOnlyLineEdit.setText(_translate("MainWindow", "Страна(C):"))
        self.Tab3StateReadOnlyLineEdit.setText(_translate("MainWindow", "Область(S):"))
        self.Tab3LocationReadOnlyLineEdit.setText(_translate("MainWindow", "Расположение(L):"))
        self.Tab3OrganizationReadOnlyLineEdit.setText(_translate("MainWindow", "Организация(O):"))
        self.Tab3OrgUnitReadOnlyLineEdit.setText(_translate("MainWindow", "Подразделение(OU):"))
        self.Tab3EmailReadOnlyLineEdit.setText(_translate("MainWindow", "Email"))
        self.Tab3CountryLineEdit.setPlaceholderText(_translate("MainWindow", "RU"))
        self.Tab3StateLineEdit.setPlaceholderText(_translate("MainWindow", "Crimea"))
        self.Tab3LocationLineEdit.setPlaceholderText(_translate("MainWindow", "Sevastopol"))
        self.Tab3OrganizationLineEdit.setPlaceholderText(_translate("MainWindow", "Payberry"))
        self.Tab3OrgUnitLineEdit.setPlaceholderText(_translate("MainWindow", "STP"))
        self.Tab3EmailLineEdit.setPlaceholderText(_translate("MainWindow", "helpdesk@payberry.ru"))
        self.Tab3LoadPrivateKeyLabel.setText(_translate("MainWindow", "Загрузить закрытый ключ:"))
        self.Tab3LoadPrivateKeyToolBtn.setText(_translate("MainWindow", "..."))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.SelfSignedCertificateTab),
                                  _translate("MainWindow", "Самоподписанный сертификат"))
        self.Tab4CertViewBtn.setText(_translate("MainWindow", "Просмотр сертификата"))
        self.Tab4ClearBtn.setText(_translate("MainWindow", "Очистить"))
        self.Tab4CreatePfxBtn.setText(_translate("MainWindow", "Создать контейнер"))
        self.Tab4SavePfxBtn.setText(_translate("MainWindow", "Сохранить в файл"))
        self.Tab4PasswordLabel.setText(_translate("MainWindow", "Задать пароль для контейнера:"))
        self.Tab4LoadCertLabel.setText(_translate("MainWindow", "Загрузить сертификат:"))
        self.Tab4LoadCertBtn_2.setText(_translate("MainWindow", "..."))
        self.Tab4LoadPrivateKeyLabel.setText(_translate("MainWindow", "Загрузить закрытый ключ:"))
        self.Tab4LoadPrivateKeyBtn.setText(_translate("MainWindow", "..."))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.P12ContainerTab),
                                  _translate("MainWindow", "Контейнеры(.p12)"))

    def password_generator(self):
        """
        Генерирует пароль для закрытого ключа. Минимальная длина пароля 12 символов, максимальная 20. Поле ввода длины
        пароля не может быть строкой.
        :return:
        """
        chars = '+-/*!&$#?=@<>abcdefghijklnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
        password = ''
        try:
            password_length = int(self.Tab1KeyLengthLineEdit.text())
            if 12 <= password_length <= 20:
                for i in range(password_length):
                    password += random.choice(chars)
                self.Tab1PasswordLineEdit.setText(password)
                global PASSWORD
                PASSWORD = password
            elif password_length > 20:
                QtWidgets.QMessageBox.critical(self.window, 'Ошибка', 'Максимальная длина пароля 20 символов',
                                               QMessageBox.Ok)
            else:
                QtWidgets.QMessageBox.critical(self.window, 'Ошибка', 'Минимальная длина пароля 12 символов',
                                               QMessageBox.Ok)

        except ValueError:
            QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                           'Поле ввода длины пароля не может быть пустым',
                                           QMessageBox.Ok)

    def clear_tab1_text_browser_window(self):
        """
        Очищает окно текстового браузера №1
        :return:
        """
        self.Tab1TextBrowser.clear()

    def clear_tab2_text_browser_window(self):
        """
        Очищает окно текстового браузера №2
        :return:
        """
        self.Tab2TextBrowser.clear()

    def clear_tab3_text_browser_window(self):
        """
        Очищает окно текстового браузера №3
        :return:
        """
        self.Tab3TextBrowser.clear()

    def clear_tab4_text_browser_window(self):
        """
        Очищает окно текстового браузера №4
        :return:
        """
        self.Tab4TextBrowser.clear()

    def pem_radio_btn_disable(self):
        """
        Делает неактивной PEM radio button при нажатии DER radio button
        :param self:
        :return:
        """
        self.Tab1KeyFormatPemRadioBtn.setEnabled(
            False) if self.Tab1KeyFormatDerRadioBtn.isChecked() else self.Tab1KeyFormatPemRadioBtn.setEnabled(True)

    def der_radio_btn_disable(self):
        """
        Делает неактивной Der radio button при нажатии PEM radio button
        :param self:
        :return:
        """
        self.Tab1KeyFormatDerRadioBtn.setEnabled(
            False) if self.Tab1KeyFormatPemRadioBtn.isChecked() else self.Tab1KeyFormatDerRadioBtn.setEnabled(True)

    def clear_loaded_private_key_while_use_created_key_radio_btn_clicked(self):
        """
        Очищает загруженный приватный ключ при нажатии кнопки 'Использовать созданный'
        :param self:
        :return:
        """
        global LOADED_PRIVATE_KEY_FROM_PC
        LOADED_PRIVATE_KEY_FROM_PC = None

    def generate_rsa_private_key(self):
        """
        Генерирует приватный ключ RSA в формате PEM с заданной длиной и паролем
        :return:
        """
        if not self.Tab1RsaRadioBtn.isChecked():
            QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                           'Не выбран Алгоритм шифрования',
                                           QMessageBox.Ok)
        elif not self.Tab1KeySizeLineEdit.text() or not self.Tab1PasswordLineEdit.text():
            QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                           'Заполните все необходимые поля для создания ключа:\n'
                                           '1) Размер ключа\n2) Пароль',
                                           QMessageBox.Ok)
        elif self.Tab1KeySizeLineEdit.text() not in ALLOWED_RSA_KEY_SIZES:
            QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                           'Недопустимый размер ключа! Введите один из трех вариантов:\n'
                                           'RSA:\n'
                                           '1) 1024\n2) 2048\n3) 4096\n',
                                           QMessageBox.Ok)
        elif not (12 <= int(self.Tab1KeyLengthLineEdit.text()) <= 20):
            QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                           'Минимальная длина пароля 12 символов, максимальная 20',
                                           QMessageBox.Ok)
        elif not self.Tab1KeyFormatPemRadioBtn.isChecked() and not self.Tab1KeyFormatDerRadioBtn.isChecked():
            QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                           'Не выбран Формат ключа')
        else:
            if self.Tab1RsaRadioBtn.isChecked() and self.Tab1KeyFormatPemRadioBtn.isChecked():
                global PASSWORD
                private_key = rsa.generate_private_key(public_exponent=65537,
                                                       key_size=int(self.Tab1KeySizeLineEdit.text()),
                                                       backend=default_backend())
                key_for_dumping = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                            encryption_algorithm=serialization.BestAvailableEncryption(
                                                                bytes(PASSWORD, 'utf-8')))
                global CREATED_PRIVATE_KEY
                CREATED_PRIVATE_KEY = private_key

                for _ in range(len(key_for_dumping.splitlines())):
                    self.Tab1TextBrowser.setText(
                        "\n".join((part.decode('utf-8')) for part in key_for_dumping.splitlines()))

                QtWidgets.QMessageBox.information(self.window, 'Готово',
                                                  'Ключ создан!',
                                                  QMessageBox.Ok)
            else:
                QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                               'Неизвестная ошибка!',
                                               QMessageBox.Ok)

    def dump_private_key(self):
        """
        Сохраняет созданный приватный ключ в файл
        :return:
        """
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_name, _ = QFileDialog.getSaveFileName(self.window, "Сохранить в файл",
                                                   "", "All Files (*);;Key Files (*.pem)",
                                                   options=options)

        pr_key = CREATED_PRIVATE_KEY
        global PASSWORD
        password = PASSWORD
        try:
            key_for_dumping = pr_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                   format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                   encryption_algorithm=serialization.BestAvailableEncryption(
                                                       bytes(password, 'utf-8')))

            with open(file_name, 'w') as key:
                key.write(
                    "\n".join((part.decode('utf-8')) for part in key_for_dumping.splitlines()))
            QtWidgets.QMessageBox.information(self.window, 'Готово',
                                              'Ключ сохранен!',
                                              QMessageBox.Ok)
        except AttributeError:
            pass
        except FileNotFoundError:
            pass

    def load_pem_private_key_from_pc(self):
        """
        Загружает приватный ключ с компьютера
        :return:
        """
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_name, _ = QFileDialog.getOpenFileName(self.window, "Загрузить файл",
                                                   "", "All Files (*);;Key Files (*.pem)",
                                                   options=options)
        global LOADED_PRIVATE_KEY_FROM_PC
        try:
            with open(file_name, 'rb') as private_key_data:
                key = load_pem_private_key(private_key_data.read(),
                                           password=None,
                                           backend=default_backend())

            if not isinstance(key, rsa.RSAPrivateKey):
                QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                               'Ошибка загрузки ключа. Ключ должен быть создан при помощи алгоритма RSA',
                                               QMessageBox.Ok)
            else:
                QtWidgets.QMessageBox.information(self.window, 'Готово',
                                                  'Ключ загружен!',
                                                  QMessageBox.Ok)
                self.Tab1UseCreatedKeyRadioBtn.setChecked(False)
            LOADED_PRIVATE_KEY_FROM_PC = key

        except TypeError:
            try:
                password, ok_pressed = QInputDialog.getText(self.window, 'Информация', 'Введите пароль от ключа:')
                if password and ok_pressed:
                    with open(file_name, 'rb') as private_key_data:
                        key = load_pem_private_key(private_key_data.read(),
                                                   password=bytes(password,
                                                                  encoding='utf-8'),
                                                   backend=default_backend())
                    if not isinstance(key, rsa.RSAPrivateKey):
                        QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                                       'Ошибка загрузки ключа. Ключ должен быть создан при помощи алгоритма RSA',
                                                       QMessageBox.Ok)
                    else:
                        QtWidgets.QMessageBox.information(self.window, 'Готово',
                                                          'Ключ загружен!',
                                                          QMessageBox.Ok)
                        self.Tab1UseCreatedKeyRadioBtn.setChecked(False)
                    LOADED_PRIVATE_KEY_FROM_PC = key
                elif ok_pressed:
                    QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                                   'Ошибка загрузки ключа. Ключ защищен паролем, но пароль не передан',
                                                   QMessageBox.Ok)
            except ValueError:
                QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                               'Неверный пароль',
                                               QMessageBox.Ok)

        except ValueError:
            QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                           'Ошибка декодирования структуры данных PEM-ключа',
                                           QMessageBox.Ok)

        except FileNotFoundError:
            pass

    def generate_rsa_public_key(self):
        """
        Генерирует публичный ключ на основе загруженного закрытого ключа с компьютера или созданного в программе
        :return:
        """
        created_pr_key = CREATED_PRIVATE_KEY
        loaded_pr_key = LOADED_PRIVATE_KEY_FROM_PC
        global CREATED_PUBLIC_KEY
        if self.Tab1UseCreatedKeyRadioBtn.isChecked() and created_pr_key:
            try:
                public_key = created_pr_key.public_key()
                QtWidgets.QMessageBox.information(self.window, 'Готово',
                                                  'Ключ создан!',
                                                  QMessageBox.Ok)
                public_key_for_dumping = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo)
                CREATED_PUBLIC_KEY = public_key

                for _ in range(len(public_key_for_dumping.splitlines())):
                    self.Tab1TextBrowser.setText(
                        "\n".join((part.decode('utf-8')) for part in public_key_for_dumping.splitlines()))
            except ValueError:
                QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                               'Не удалось создать открытый ключ',
                                               QMessageBox.Ok)
        elif not self.Tab1UseCreatedKeyRadioBtn.isChecked() and loaded_pr_key:
            try:
                public_key = loaded_pr_key.public_key()
                QtWidgets.QMessageBox.information(self.window, 'Готово',
                                                  'Ключ создан!',
                                                  QMessageBox.Ok)
                public_key_for_dumping = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo)
                CREATED_PUBLIC_KEY = public_key

                for _ in range(len(public_key_for_dumping.splitlines())):
                    self.Tab1TextBrowser.setText(
                        "\n".join((part.decode('utf-8')) for part in public_key_for_dumping.splitlines()))
            except ValueError:
                QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                               'Не удалось создать открытый ключ',
                                               QMessageBox.Ok)

        else:
            QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                           'Приватный ключ не найден! Выберите один из предложенных вариантов:\n'
                                           '1) Загрузить закрытый ключ\n'
                                           '2) Использовать созданный',
                                           QMessageBox.Ok)

    def dump_public_key(self):
        """
        Сохраняет созданный публичный ключ в файл
        :return:
        """
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_name, _ = QFileDialog.getSaveFileName(self.window, "Сохранить в файл",
                                                   "", "All Files (*);;Key Files (*.pem)",
                                                   options=options)
        global CREATED_PUBLIC_KEY
        public_key = CREATED_PUBLIC_KEY
        try:
            public_key_for_dumping = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                             format=serialization.PublicFormat.SubjectPublicKeyInfo)

            with open(file_name, 'w') as key:
                key.write(
                    "\n".join((part.decode('utf-8')) for part in public_key_for_dumping.splitlines()))
            QtWidgets.QMessageBox.information(self.window, 'Готово',
                                              'Ключ сохранен!',
                                              QMessageBox.Ok)
        except AttributeError:
            pass
        except FileNotFoundError:
            pass

    def load_private_key_from_pc_for_csr(self):
        """
        Загружает приватный ключ с компьютера для создания CSR-запроса
        :return:
        """
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_name, _ = QFileDialog.getOpenFileName(self.window, "Загрузить файл",
                                                   "", "All Files (*);;Key Files (*.pem)",
                                                   options=options)
        global LOADED_PRIVATE_KEY_FOR_CSR
        try:
            with open(file_name, 'rb') as private_key_data:
                key = load_pem_private_key(private_key_data.read(),
                                           password=None,
                                           backend=default_backend())

            if not isinstance(key, rsa.RSAPrivateKey):
                QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                               'Ошибка загрузки ключа. Ключ должен быть создан при помощи алгоритма RSA',
                                               QMessageBox.Ok)
            else:
                QtWidgets.QMessageBox.information(self.window, 'Готово',
                                                  'Ключ загружен!',
                                                  QMessageBox.Ok)
                LOADED_PRIVATE_KEY_FOR_CSR = key

        except TypeError:
            try:
                password, ok_pressed = QInputDialog.getText(self.window, 'Информация', 'Введите пароль от ключа:')
                if password and ok_pressed:
                    with open(file_name, 'rb') as private_key_data:
                        key = load_pem_private_key(private_key_data.read(),
                                                   password=bytes(password,
                                                                  encoding='utf-8'),
                                                   backend=default_backend())
                        if not isinstance(key, rsa.RSAPrivateKey):
                            QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                                           'Ошибка загрузки ключа. Ключ должен быть создан при помощи алгоритма RSA',
                                                           QMessageBox.Ok)
                        else:
                            QtWidgets.QMessageBox.information(self.window, 'Готово',
                                                              'Ключ загружен!',
                                                              QMessageBox.Ok)
                            LOADED_PRIVATE_KEY_FOR_CSR = key
                elif ok_pressed:
                    QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                                   'Ошибка загрузки ключа. Ключ защищен паролем, но пароль не передан',
                                                   QMessageBox.Ok)
            except ValueError:
                QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                               'Неверный пароль',
                                               QMessageBox.Ok)

        except ValueError:
            QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                           'Ошибка декодирования структуры данных PEM-ключа',
                                           QMessageBox.Ok)

        except FileNotFoundError:
            pass

    def sha1_radio_btn_behavior(self):
        """
        Устанавливает поведение SHA1 radio button: если она нажата, делает неактивными SHA256 и SHA512
        :param self:
        :return:
        """
        if self.Tab2Sha1RadioBtn.isChecked():
            self.Tab2Sha256RadioBtn.setEnabled(False)
            self.Tab2Sha512RadioBtn.setEnabled(False)
        else:
            self.Tab2Sha256RadioBtn.setEnabled(True)
            self.Tab2Sha512RadioBtn.setEnabled(True)

    def sha256_radio_btn_behavior(self):
        """
        Устанавливает поведение SHA256 radio button: если она нажата, делает неактивными SHA1 и SHA512
        :param self:
        :return:
        """
        if self.Tab2Sha256RadioBtn.isChecked():
            self.Tab2Sha1RadioBtn.setEnabled(False)
            self.Tab2Sha512RadioBtn.setEnabled(False)
        else:
            self.Tab2Sha1RadioBtn.setEnabled(True)
            self.Tab2Sha512RadioBtn.setEnabled(True)

    def sha512_radio_btn_behavior(self):
        """
        Устанавливает поведение SHA512 radio button: если она нажата, делает неактивными SHA1 и SHA256
        :param self:
        :return:
        """
        if self.Tab2Sha512RadioBtn.isChecked():
            self.Tab2Sha1RadioBtn.setEnabled(False)
            self.Tab2Sha256RadioBtn.setEnabled(False)
        else:
            self.Tab2Sha1RadioBtn.setEnabled(True)
            self.Tab2Sha256RadioBtn.setEnabled(True)

    def tab3_sha1_radio_btn_behavior(self):
        """
        Устанавливает поведение SHA1 radio button: если она нажата, делает неактивными SHA256 и SHA512
        :param self:
        :return:
        """
        if self.Tab3Sha1RadioBtn.isChecked():
            self.Tab3SignSha256RadioBtn.setEnabled(False)
            self.Tab3Sha512RadioBtn.setEnabled(False)
        else:
            self.Tab3SignSha256RadioBtn.setEnabled(True)
            self.Tab3Sha512RadioBtn.setEnabled(True)

    def tab3_sha256_radio_btn_behavior(self):
        """
        Устанавливает поведение SHA256 radio button: если она нажата, делает неактивными SHA1 и SHA512
        :param self:
        :return:
        """
        if self.Tab3SignSha256RadioBtn.isChecked():
            self.Tab3Sha1RadioBtn.setEnabled(False)
            self.Tab3Sha512RadioBtn.setEnabled(False)
        else:
            self.Tab3Sha1RadioBtn.setEnabled(True)
            self.Tab3Sha512RadioBtn.setEnabled(True)

    def tab3_sha512_radio_btn_behavior(self):
        """
        Устанавливает поведение SHA512 radio button: если она нажата, делает неактивными SHA1 и SHA256
        :param self:
        :return:
        """
        if self.Tab3Sha512RadioBtn.isChecked():
            self.Tab3Sha1RadioBtn.setEnabled(False)
            self.Tab3SignSha256RadioBtn.setEnabled(False)
        else:
            self.Tab3Sha1RadioBtn.setEnabled(True)
            self.Tab3SignSha256RadioBtn.setEnabled(True)

    def generate_csr(self):
        """
        Генерирует CSR-запрос на сертификат на основе введенных пользователем данных
        :return:
        """
        global LOADED_PRIVATE_KEY_FOR_CSR
        pr_key = LOADED_PRIVATE_KEY_FOR_CSR
        hash_algorithm = None
        country_name = self.Tab2CountryLineEdit.text().upper()
        state = self.Tab2StateLineEdit.text().capitalize()
        location_name = self.Tab2LocationLineEdit.text().capitalize()
        organization_name = self.Tab2OrganizationLineEdit.text().capitalize()
        organizational_unit_name = self.Tab2OrgUnitLineEdit.text().upper()
        email = self.Tab2EmailLineEdit.text()
        csr_attributes_list = frozenset(
            (country_name, state, location_name, organization_name, organizational_unit_name, email))
        alternative_dns_name = self.Tab2AdditionalDnsNameLineEdit.text() if self.Tab2AdditionalDnsNameLineEdit.text() else ""
        if not all(csr_attributes_list):
            QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                           'Заполните все параметры для создания запроса',
                                           QMessageBox.Ok)

        elif not pr_key:
            QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                           'Отсутствует закрытый ключ!',
                                           QMessageBox.Ok)
        else:
            if self.Tab2Sha1RadioBtn.isChecked():
                hash_algorithm = HashAlgorithms.sha1
            elif self.Tab2Sha256RadioBtn.isChecked():
                hash_algorithm = HashAlgorithms.sha256
            elif self.Tab2Sha512RadioBtn.isChecked():
                hash_algorithm = HashAlgorithms.sha512
            try:
                csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, u'{}'.format(country_name)),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'{}'.format(state)),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, u'{}'.format(location_name)),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'{}'.format(organization_name)),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'{}'.format(organizational_unit_name)),
                    x509.NameAttribute(NameOID.EMAIL_ADDRESS, u'{}'.format(email))
                ])).add_extension(
                    x509.SubjectAlternativeName([
                        x509.DNSName(u'{}'.format(alternative_dns_name))
                    ]),
                    critical=False
                ).sign(pr_key, hash_algorithm, default_backend())
                global GENERATED_CSR
                GENERATED_CSR = csr
                csr_for_dumping = csr.public_bytes(serialization.Encoding.PEM)

                for _ in range(len(csr_for_dumping.splitlines())):
                    self.Tab2TextBrowser.setText(
                        "\n".join((part.decode('utf-8')) for part in csr_for_dumping.splitlines()))
                QtWidgets.QMessageBox.information(self.window, 'Готово',
                                                  'Запрос создан!',
                                                  QMessageBox.Ok)
            except TypeError:
                QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                               'Не выбран алгоритм хеширования!',
                                               QMessageBox.Ok)
            except ValueError:
                QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                               'Страна(C) должна быть в виде двухсимвольного кода, пример: RU',
                                               QMessageBox.Ok)

    def dump_csr(self):
        """
        Сохраняет созданный CSR-запрос в файл
        :return:
        """
        global GENERATED_CSR
        csr = GENERATED_CSR
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_name, _ = QFileDialog.getSaveFileName(self.window, "Сохранить в файл",
                                                   "", "All Files (*);;Key Files (*.pem, *.csr)",
                                                   options=options)
        try:
            with open(file_name, 'wb') as csr_for_dump:
                csr_for_dump.write(csr.public_bytes(serialization.Encoding.PEM))
            QtWidgets.QMessageBox.information(self.window, 'Готово',
                                              'Запрос сохранен',
                                              QMessageBox.Ok)
        except FileNotFoundError:
            pass

    def load_private_key_from_pc_for_selfsigned_csr(self):
        """
        Загружет приватный ключ для создания самодописанного сертификата
        :return:
        """
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_name, _ = QFileDialog.getOpenFileName(self.window, "Загрузить файл",
                                                   "", "All Files (*);;Key Files (*.pem)",
                                                   options=options)
        global LOADED_PRIVATE_KEY_FOR_SELFSIGNED_CSR
        try:
            with open(file_name, 'rb') as private_key_data:
                key = load_pem_private_key(private_key_data.read(),
                                           password=None,
                                           backend=default_backend())

            if not isinstance(key, rsa.RSAPrivateKey):
                QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                               'Ошибка загрузки ключа. Ключ должен быть создан при помощи алгоритма RSA',
                                               QMessageBox.Ok)
            else:
                QtWidgets.QMessageBox.information(self.window, 'Готово',
                                                  'Ключ загружен!',
                                                  QMessageBox.Ok)
                LOADED_PRIVATE_KEY_FOR_SELFSIGNED_CSR = key

        except TypeError:
            try:
                password, ok_pressed = QInputDialog.getText(self.window, 'Информация', 'Введите пароль от ключа:')
                if password and ok_pressed:
                    with open(file_name, 'rb') as private_key_data:
                        key = load_pem_private_key(private_key_data.read(),
                                                   password=bytes(password,
                                                                  encoding='utf-8'),
                                                   backend=default_backend())
                        if not isinstance(key, rsa.RSAPrivateKey):
                            QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                                           'Ошибка загрузки ключа. Ключ должен быть создан при помощи алгоритма RSA',
                                                           QMessageBox.Ok)
                        else:
                            QtWidgets.QMessageBox.information(self.window, 'Готово',
                                                              'Ключ загружен!',
                                                              QMessageBox.Ok)
                            LOADED_PRIVATE_KEY_FOR_SELFSIGNED_CSR = key
                elif ok_pressed:
                    QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                                   'Ошибка загрузки ключа. Ключ защищен паролем, но пароль не передан',
                                                   QMessageBox.Ok)
            except ValueError:
                QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                               'Неверный пароль',
                                               QMessageBox.Ok)

        except ValueError:
            QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                           'Ошибка декодирования структуры данных PEM-ключа',
                                           QMessageBox.Ok)

        except FileNotFoundError:
            pass

    def generate_selfsigned_csr(self):
        """
        Гененирует самоподписанный сертификат
        :return:
        """
        global LOADED_PRIVATE_KEY_FOR_SELFSIGNED_CSR
        pr_key = LOADED_PRIVATE_KEY_FOR_SELFSIGNED_CSR
        global GENERATED_SELF_SIGNED_CERTIFICATE
        days = self.Tab3CertificateValidityInDaysLineEdit.text()
        hash_algorithm = None
        country_name = self.Tab3CountryLineEdit.text().upper()
        state = self.Tab3StateLineEdit.text().capitalize()
        locality_name = self.Tab3LocationLineEdit.text().capitalize()
        organization_name = self.Tab3OrganizationLineEdit.text().capitalize()
        organizational_unit_name = self.Tab3OrgUnitLineEdit.text().upper()
        email = self.Tab3EmailLineEdit.text()
        csr_attributes_list = frozenset(
            (country_name, state, locality_name, organization_name, organizational_unit_name, email))
        alternative_dns_name = self.Tab3AdditionalDnsNameLineEdit.text() if self.Tab3AdditionalDnsNameLineEdit.text() else ""
        if not all(csr_attributes_list):
            QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                           'Заполните все параметры для создания запроса',
                                           QMessageBox.Ok)

        elif not pr_key:
            QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                           'Отсутствует закрытый ключ!',
                                           QMessageBox.Ok)
        elif not days:
            QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                           'Укажите время действия сертификата!',
                                           QMessageBox.Ok)
        elif int(days) <= 0:
            QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                           'Время действия сертификата должно быть положительным целым числом отличным от 0',
                                           QMessageBox.Ok)
        else:
            if self.Tab3Sha1RadioBtn.isChecked():
                hash_algorithm, sha = HashAlgorithms.sha1, "SHA1"
            elif self.Tab3SignSha256RadioBtn.isChecked():
                hash_algorithm, sha = HashAlgorithms.sha256, "SHA256"
            elif self.Tab3Sha512RadioBtn.isChecked():
                hash_algorithm, sha = HashAlgorithms.sha512, "SHA512"
            try:
                subject = issuer = x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, u'{}'.format(country_name)),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'{}'.format(state)),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, u'{}'.format(locality_name)),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'{}'.format(organization_name)),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'{}'.format(organizational_unit_name)),
                    x509.NameAttribute(NameOID.EMAIL_ADDRESS, u'{}'.format(email))])
                cert = x509.CertificateBuilder().subject_name(
                    subject
                ).issuer_name(
                    issuer
                ).public_key(
                    pr_key.public_key()
                ).serial_number(
                    x509.random_serial_number()
                ).not_valid_before(
                    datetime.datetime.utcnow()
                ).not_valid_after(
                    datetime.datetime.utcnow() + datetime.timedelta(days=int(days))
                ).add_extension(
                    x509.SubjectAlternativeName([
                        x509.DNSName(u'{}'.format(alternative_dns_name))]),
                    critical=False
                ).sign(pr_key, hash_algorithm, default_backend())
                QtWidgets.QMessageBox.information(self.window, 'Готово',
                                                  'Запрос создан!',
                                                  QMessageBox.Ok)
                GENERATED_SELF_SIGNED_CERTIFICATE = cert
                public_key = cert.public_key()
                public_key_for_print = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                               format=serialization.PublicFormat.SubjectPublicKeyInfo)

                self.Tab3TextBrowser.setText("\n".join(tuple(("Версия сертификата: {}".format(cert.version),
                                                              "Fingerprint: {}".format(
                                                                  cert.fingerprint(hash_algorithm)),
                                                              "Серийный номер: {}".format(cert.serial_number),
                                                              "Публичный ключ:",
                                                              "{}".format("\n".join((part.decode('utf-8')) for part in
                                                                                    public_key_for_print.splitlines())),
                                                              "Действует с: {}".format(cert.not_valid_before),
                                                              "Не действуйет после: {}".format(cert.not_valid_after),
                                                              "Издатель: {}".format(cert.issuer),
                                                              "Объект: {}".format(cert.subject),
                                                              "Алгоритм подписи: {}".format(sha)
                                                              ))))
            except TypeError:
                QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                               'Не выбран алгоритм хеширования!',
                                               QMessageBox.Ok)
            except ValueError:
                QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                               'Страна(C) должна быть в виде двухсимвольного кода, пример: RU',
                                               QMessageBox.Ok)

    def dump_selfsigned_crt(self):
        """
        Сохраняет созданный самоподписанный сертификат в файл
        :return:
        """
        global GENERATED_SELF_SIGNED_CERTIFICATE
        selfsigned_crt = GENERATED_SELF_SIGNED_CERTIFICATE
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_name, _ = QFileDialog.getSaveFileName(self.window, "Сохранить в файл",
                                                   "", "All Files (*);;Key Files (*.pem, *.crt)",
                                                   options=options)
        try:
            with open(file_name, 'wb') as selfsigned_crt_for_dump:
                selfsigned_crt_for_dump.write(selfsigned_crt.public_bytes(serialization.Encoding.PEM))
            QtWidgets.QMessageBox.information(self.window, 'Готово',
                                              'Запрос сохранен',
                                              QMessageBox.Ok)
        except FileNotFoundError:
            pass

    def load_cert_for_p12(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_name, _ = QFileDialog.getOpenFileName(self.window, "Загрузить файл",
                                                   "", "All Files (*);;Key Files (*.pem, *.crt)",
                                                   options=options)
        global LOADED_CRT_FOR_P12
        try:
            with open(file_name, 'rb') as cert_data:
                cert = x509.load_pem_x509_certificate(cert_data.read(),
                                                      backend=default_backend())
            QtWidgets.QMessageBox.information(self.window, 'Готово',
                                              'Сертификат загружен!',
                                              QMessageBox.Ok)
            LOADED_CRT_FOR_P12 = cert
        except FileNotFoundError:
            pass
        except ValueError:
            QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                           'Не удалось загрузить сертификат!',
                                           QMessageBox.Ok)

    def load_private_key_for_p12(self):
        """
        Загружает приватный ключ для создания контейнера P12
        :return:
        """
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_name, _ = QFileDialog.getOpenFileName(self.window, "Загрузить файл",
                                                   "", "All Files (*);;Key Files (*.pem)",
                                                   options=options)
        global LOADED_PRIVATE_KEY_FOR_P12
        try:
            with open(file_name, 'rb') as private_key_data:
                key = load_pem_private_key(private_key_data.read(),
                                           password=None,
                                           backend=default_backend())

            if not isinstance(key, rsa.RSAPrivateKey):
                QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                               'Ошибка загрузки ключа. Ключ должен быть создан при помощи алгоритма RSA',
                                               QMessageBox.Ok)
            else:
                QtWidgets.QMessageBox.information(self.window, 'Готово',
                                                  'Ключ загружен!',
                                                  QMessageBox.Ok)
                LOADED_PRIVATE_KEY_FOR_P12 = key

        except TypeError:
            try:
                password, ok_pressed = QInputDialog.getText(self.window, 'Информация', 'Введите пароль от ключа:')
                if password and ok_pressed:
                    with open(file_name, 'rb') as private_key_data:
                        key = load_pem_private_key(private_key_data.read(),
                                                   password=bytes(password,
                                                                  encoding='utf-8'),
                                                   backend=default_backend())
                        if not isinstance(key, rsa.RSAPrivateKey):
                            QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                                           'Ошибка загрузки ключа. Ключ должен быть создан при помощи алгоритма RSA',
                                                           QMessageBox.Ok)
                        else:
                            QtWidgets.QMessageBox.information(self.window, 'Готово',
                                                              'Ключ загружен!',
                                                              QMessageBox.Ok)
                            LOADED_PRIVATE_KEY_FOR_P12 = key
                elif ok_pressed:
                    QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                                   'Ошибка загрузки ключа. Ключ защищен паролем, но пароль не передан',
                                                   QMessageBox.Ok)
            except ValueError:
                QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                               'Неверный пароль',
                                               QMessageBox.Ok)

        except ValueError:
            QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                           'Ошибка декодирования структуры данных PEM-ключа',
                                           QMessageBox.Ok)

        except FileNotFoundError:
            pass

    def view_cert_for_p12_info(self):
        """
        Выводит информацию о сертификате в окно текстового браузера
        :return:
        """
        global LOADED_CRT_FOR_P12
        cert = LOADED_CRT_FOR_P12
        try:
            public_key = cert.public_key()
            public_key_for_print = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                           format=serialization.PublicFormat.SubjectPublicKeyInfo)
            self.Tab4TextBrowser.setText("\n".join(tuple(("Версия сертификата: {}".format(cert.version),
                                                          "Серийный номер: {}".format(cert.serial_number),
                                                          "Публичный ключ:",
                                                          "{}".format("\n".join((part.decode('utf-8')) for part in
                                                                                public_key_for_print.splitlines())),
                                                          "Действует с: {}".format(cert.not_valid_before),
                                                          "Не действуйет после: {}".format(cert.not_valid_after),
                                                          "Издатель: {}".format(cert.issuer),
                                                          "Объект: {}".format(cert.subject)
                                                          ))))
        except AttributeError:
            QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                           "Сертификат не найден!",
                                           QMessageBox.Ok)

    def generate_p12(self):
        """
        Генерирует контейнер P12
        :return:
        """
        global LOADED_CRT_FOR_P12
        global LOADED_PRIVATE_KEY_FOR_P12
        global PFXDATA
        password = self.Tab4PasswordLineEdit.text()
        if not password:
            QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                           "Пароль не задан!",
                                           QMessageBox.Ok)
        else:
            try:
                cert = LOADED_CRT_FOR_P12.public_bytes(encoding=serialization.Encoding.PEM)
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                pr_key = LOADED_PRIVATE_KEY_FOR_P12.private_bytes(encoding=serialization.Encoding.PEM,
                                                                  format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                                  encryption_algorithm=serialization.NoEncryption())
                pr_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, pr_key)
                pfx = OpenSSL.crypto.PKCS12()
                pfx.set_privatekey(pr_key)
                pfx.set_certificate(cert)
                pfxdata = pfx.export(bytes(password,
                                           encoding='utf-8'))
                PFXDATA = pfxdata
            except AttributeError:
                QtWidgets.QMessageBox.critical(self.window, 'Ошибка',
                                               "Не передан сертификат или закрытый ключ!",
                                               QMessageBox.Ok)
            else:
                QtWidgets.QMessageBox.information(self.window, 'Готово',
                                                  'Контейнер создан!',
                                                  QMessageBox.Ok)

    def dump_p12(self):
        """
        Сохраняет контейнер P12 в файл
        :return:
        """
        global PFXDATA
        pfxdata = PFXDATA
        try:
            options = QFileDialog.Options()
            options |= QFileDialog.DontUseNativeDialog
            file_name, _ = QFileDialog.getSaveFileName(self.window, "Сохранить в файл",
                                                       "", "All Files (*);;Key Files (*.pfx, *.p12)",
                                                       options=options)
            with open(file_name, 'wb') as p12:
                p12.write(pfxdata)
            QtWidgets.QMessageBox.information(self.window, 'Готово',
                                              'Контейнер сохранен!',
                                              QMessageBox.Ok)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    app.setStyle('Fusion')
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
