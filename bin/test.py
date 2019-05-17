from pyattck import Attck

attack = Attck()

for technique in attack.techniques:
    print(technique.name)