import urllib.request
import hashlib
import os


def md5(path_to_new_cvd):
    hash = hashlib.md5()

    with open(path_to_new_cvd, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash.update(chunk)
    x = hash.hexdigest()
    return x


def create_yar_rules(path):
    os.system('sigtool -u ' + path)
    os.rename("main.ndb", "main_rule.ndb")
    os.system('rm main.*')

    os.system('python3 clamav_to_yara.py -f main_rule.ndb -o allRules_new.yar')

    os.system('cp allRules_new.yar ~/PycharmProjects/Yara-rules/rulesDir/')

    os.system('rm allRules_new.yar COPYING main_all.cvd main_rule.ndb')

    if os.path.isfile("rulesDir/allRules.yar"):
        old_md5 = md5("rulesDir/allRules.yar")
        new_md5 = md5("rulesDir/allRules_new.yar")

        if old_md5 == new_md5:
            os.remove("rulesDir/allRules_new.yar")
        else:
            os.remove("rulesDir/allRules.yar")
            os.rename("rulesDir/allRules_new.yar", "rulesDir/allRules.yar")


def main():
    url = 'https://unlix.ru/clamav/main.cvd'

    if os.path.isfile("main_all.cvd"):

        urllib.request.urlretrieve(url, 'main_new.cvd')

        create_yar_rules("main_new.cvd")

    elif os.path.isfile("main.cvd"):
        create_yar_rules("main.cvd")
    else:
        urllib.request.urlretrieve(url, 'main_all.cvd')
        create_yar_rules("main_all.cvd")


if __name__ == '__main__':
    main()
