import os
import yara
import sys
from PyQt6.QtWidgets import QWidget, QLineEdit, QApplication, QMainWindow, QPushButton, QHBoxLayout


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AntiVirus Demo")
        self.resize(400, 200)

        layout = QHBoxLayout()
        self.input = QLineEdit(self)

        self.button = QPushButton("Press Me!")
        self.button.setCheckable(True)
        self.button.clicked.connect(self.the_button_was_clicked)

        layout.addWidget(self.button)
        layout.addWidget(self.input)

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
