import os
import yara
import sys
from PyQt6.QtWidgets import QWidget, QLineEdit, QApplication, QMainWindow, QPushButton, QLabel, QGridLayout, QMessageBox
from docx import Document


def replace_on_slash_in_path(path_to_file): # from pathlib import Path
    count_of_slash = path_to_file.count('**\\ **')
    normal_path = path_to_file.replace('**\\ **', '/', count_of_slash)
    return normal_path


def create_rules_list(address):
    yara_list = {}
    files = os.listdir(address)
    for file_name in files:
        if '.yar' in file_name:
            yara_list[file_name.split('.yar')[0]] = address + file_name
    return yara_list


def print_in_document(path_to_check, matches):
    document = Document()

    # print(f"The file {path_to_check} follows the following rules:")
    for match in matches:

        print("\t", match)

        if os.path.exists(f'docxDir/{str(match)}.docx'):
            doc_to_write = Document(f'docxDir/{str(match)}.docx')
            doc_to_write.add_paragraph(f"The file {path_to_check}")
            doc_to_write.save(f'docxDir/{str(match)}.docx')
        else:
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
        self.text_to_save = None
        self.setWindowTitle("AntiVirus Demo")
        self.resize(300, 100)

        self.message_of_checking_exist_file = QMessageBox()

        layout = QGridLayout()
        self.input_path_to_dir_or_file = QLineEdit(self)

        path_to_dir_or_file = QLabel("Введите путь к папке/файлу, который необходимо просканировать:")

        self.button = QPushButton("Просканировать")
        self.button.setCheckable(True)
        self.button.clicked.connect(self.the_button_was_clicked)

        layout.addWidget(path_to_dir_or_file, 0, 0)
        layout.addWidget(self.input_path_to_dir_or_file, 1, 0)
        layout.addWidget(self.button, 3, 0)

        container = QWidget()

        container.setLayout(layout)

        self.setCentralWidget(container)

    def the_button_was_clicked(self):

        text_input = self.input_path_to_dir_or_file.text()
        path_to_check = replace_on_slash_in_path(text_input)

        rules = yara.compile(filepaths=create_rules_list('rulesDir/'))

        if os.path.isdir(path_to_check):
            checking_files_in_directory(rules, path_to_check)
        else:
            matches = rules.match(path_to_check)
            filename = os.path.basename(path_to_check).split('.')[0]
            print_in_document(filename, matches)


app = QApplication(sys.argv)
window = MainWindow()
window.show()

app.exec()
