import os
import yara
import sys
from PyQt6.QtWidgets import QWidget, QLineEdit, QApplication, QMainWindow, QPushButton, QHBoxLayout, QLabel, QGridLayout


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AntiVirus Demo")
        self.resize(300, 100)

        layout = QGridLayout()
        self.input_path_to_dir_or_file = QLineEdit(self)
        self.input_path_to_doc = QLineEdit(self)

        path_to_dir_or_file = QLabel("Введите путь к папке/файлу, который необходимо просканировать:")
        path_to_doc = QLabel("Введите путь к папке, куда будет сохранён отчёт о сканировании:")

        self.button = QPushButton("Просканировать")
        self.button.setCheckable(True)
        self.button.clicked.connect(self.the_button_was_clicked)

        layout.addWidget(path_to_dir_or_file, 0, 0)
        layout.addWidget(self.input_path_to_dir_or_file, 1, 0)
        layout.addWidget(path_to_doc, 2, 0)
        layout.addWidget(self.input_path_to_doc, 3, 0)
        layout.addWidget(self.button, 4, 0)

        container = QWidget()

        container.setLayout(layout)

        self.setCentralWidget(container)

    def the_button_was_clicked(self):
        text = self.input.text()
        len_tex = len(self.input.text())
        print(len_tex)
        print(text[len_tex-1])
        print(os.path.isdir(self.input.text()))
        rules = yara.compile(filepaths=create_rules_list('rulesDir/'))
        if os.path.isdir(self.input.text()):
            checking_files_in_directory(rules, self.input.text())
        else:
            matches = rules.match(self.input.text())
            print(matches)


def create_rules_list(address):
    yara_list = {}
    files = os.listdir(address)
    for file_name in files:
        if '.yar' in file_name:
            yara_list[file_name.split('.yar')[0]] = address + file_name
    return yara_list


def checking_files_in_directory(rules_for_checking, address):
    directory_path = address
    for filename in os.listdir(directory_path):
        filepath = os.path.join(directory_path, filename)
        if os.path.isfile(filepath):
            matches_files = rules_for_checking.match(filepath)
            if matches_files:
                print(f"The file {filename} follows the following rules:")
                for match in matches_files:
                    print("\t", match)


app = QApplication(sys.argv)
window = MainWindow()
window.show()

app.exec()


# matches = rules.match(filepath='dataDir/text.txt')

# print(matches)
