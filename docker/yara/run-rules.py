import yara
rules = yara.compile(filepath="./yara-rules-full.yar", includes=True)
matches = rules.match('./test')

print(matches)