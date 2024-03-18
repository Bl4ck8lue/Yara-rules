import os
import yara


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


rules = yara.compile(filepaths=create_rules_list('rulesDir/'))
checking_files_in_directory(rules, 'dataDir/')
# matches = rules.match(filepath='dataDir/text.txt')

# print(matches)
