import os
import yara


def create_rules_list(address):
    yara_list = {}
    files = os.listdir(address)
    for file_name in files:
        if '.yar' in file_name:
            yara_list[file_name.split('.yar')[0]] = address + file_name
    return yara_list


rules = yara.compile(filepaths=create_rules_list('rulesDir/'))
matches = rules.match(filepath='text.txt')
print(matches)
