import yara

rules = yara.compile(source='rule foo: bar {strings: $a = "lmn" condition: $a}')

matches = rules.match(data='abcdefgjiklmnoprstuvwxyz')

print(matches['main'][0]['rule'])
