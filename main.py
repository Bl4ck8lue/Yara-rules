import os
import sys
from threading import Thread

import yara
from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QWidget, QApplication, QMainWindow, QPushButton, QLabel, QMessageBox, QVBoxLayout, \
    QFileDialog, QHBoxLayout, QProgressBar
from docx import Document


def create_rules_list(address):
    yara_list = {}
    files = os.listdir(address)
    for file_name in files:
        if '.yar' in file_name:
            yara_list[file_name.split('.yar')[0]] = address + file_name
    return yara_list


def print_in_document(path_to_check, matches):
    count = 0
    # print(f"The file {path_to_check} follows the following rules:")
    for match in matches:

        print("\t", match)

        if os.path.exists(f'docxDir/{str(match)}.docx'):
            doc_to_write = Document(f'docxDir/{str(match)}.docx')
            doc_to_write.add_paragraph(f"The file {path_to_check}")
            doc_to_write.save(f'docxDir/{str(match)}.docx')
        else:
            document = Document()
            document.add_paragraph(f"{str(match)}:")
            document.add_paragraph(f"The file {path_to_check}")
            document.save(f'docxDir/{str(match)}.docx')


def checking_files_in_directory(rules_for_checking, address):
    directory_path = address
    for filename in os.listdir(directory_path):
        filepath = os.path.join(directory_path, filename)
        if os.path.isfile(filepath):
            matches_files = rules_for_checking.match(filepath)
            if matches_files:
                print_in_document(filename, matches_files)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        _signal = pyqtSignal(int)
        self.dir_list = None
        self.filename = None
        self.plainTextEdit = None
        self.text_to_save = None
        self.setWindowTitle("AntiVirus Demo")
        self.resize(300, 100)

        self.message_of_checking_exist_file = QMessageBox()

        layout_first_card = QHBoxLayout()
        layout_second_card = QVBoxLayout()
        layout_all = QVBoxLayout()

        # description of layout_first_card ----------------------------------------
        result_of_scanning = QLabel("Выберите")

        self.btn_to_choose_file = QPushButton("Файл")
        self.btn_to_choose_file.setCheckable(True)
        self.btn_to_choose_file.clicked.connect(self.the_btn_to_choose_file_was_clicked)
        or_ = QLabel("или")

        self.btn_to_choose_dir = QPushButton("Папка")
        self.btn_to_choose_dir.setCheckable(True)
        self.btn_to_choose_dir.clicked.connect(self.the_btn_to_choose_dir_was_clicked)
        end_of_sent = QLabel("для сканирования")

        layout_first_card.addWidget(result_of_scanning)
        layout_first_card.addWidget(self.btn_to_choose_file)
        layout_first_card.addWidget(or_)
        layout_first_card.addWidget(self.btn_to_choose_dir)
        layout_first_card.addWidget(end_of_sent)
        # -------------------------------------------------------------------------

        # description of layout_second_card ----------------------------------------
        self.pbar = QProgressBar(self)
        self.pbar.setValue(0)

        self.btn_to_scan = QPushButton("Сканировать")
        self.btn_to_scan.setCheckable(True)
        self.btn_to_scan.clicked.connect(self.the_button_was_clicked)

        layout_second_card.addWidget(self.pbar)
        layout_second_card.addWidget(self.btn_to_scan)
        # --------------------------------------------------------------------------

        layout_all.addLayout(layout_first_card)
        layout_all.addLayout(layout_second_card)

        container = QWidget()

        container.setLayout(layout_all)

        self.setCentralWidget(container)

    def the_btn_to_choose_file_was_clicked(self):
        filename, filetype = QFileDialog.getOpenFileName(self,
                                                         "Выбрать файл",
                                                         ".",
                                                         "All Files(*);;Text Files(*.txt);;JPEG Files(*.jpeg);;\
                                                         PNG Files(*.png);;GIF File(*.gif)")
        if filename != '':
            self.btn_to_choose_dir.setEnabled(False)
            self.filename = filename

    def the_btn_to_choose_dir_was_clicked(self):  # <-----
        dir_list = QFileDialog.getExistingDirectory(self, "Выбрать папку", ".")
        if dir_list != '':
            self.btn_to_choose_file.setEnabled(False)
            self.dir_list = dir_list

    def the_button_was_clicked(self):

        self.thread = Thread()
        self.thread._signal.connect(self.signal_accept)
        self.thread.start()
        self.btn_to_scan.setEnabled(False)

        rules = yara.compile(filepaths=create_rules_list('rulesDir/'))

        if self.filename is None and self.dir_list != '':
            checking_files_in_directory(rules, self.dir_list)
        if self.filename != '' and self.dir_list is None:
            matches = rules.match(self.filename)
            filename = os.path.basename(self.filename).split('.')[0]
            print_in_document(filename, matches)

        self.btn_to_choose_file.setEnabled(True)
        self.btn_to_choose_dir.setEnabled(True)


app = QApplication(sys.argv)
window = MainWindow()
window.show()

app.exec()
