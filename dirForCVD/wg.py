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
    
def create_yar_rules():
    os.system('sigtool -u main_all.cvd')
    os.rename("main.ndb", "main_rule.ndb")
    os.system('rm main.*')

    os.system('python3 clamav_to_yara.py -f main_rule.ndb -o allRules.yar')

    os.system('cp allRules.yar /home/user/Projects/Yara-rules_UI/rulesDir/')
    
url = 'https://clmvupd.deltamoby.ru/main.cvd'
    
if os.path.isfile("main_all.cvd"):

    urllib.request.urlretrieve(url, 'main_new.cvd')

    old_md5 = md5("main_all.cvd")
    new_md5 = md5("main_new.cvd")

    if old_md5 == new_md5:
        os.remove("main_new.cvd")
    else:
        os.remove("main.cvd")
        os.rename("main_new.cvd", "main_all.cvd")
    create_yar_rules()
        
else:
    urllib.request.urlretrieve(url, 'main_all.cvd')
    create_yar_rules()


