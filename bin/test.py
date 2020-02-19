from pyattck import Attck

attack = Attck()

for actor in attack.enterprise.actors:
    print(actor.name)
    print(actor.ascii_logo)
    print(actor.image_logo)

#for tool in attack.enterprise.tools:
#    print(tool.name)
#    print(tool.c2_data)


print(attack.enterprise.search_commands('powershell'))