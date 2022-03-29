from nerb import NERB

with open('prog_rock_wiki.txt', 'r') as file:
    prog_rock_wiki = file.read()

nerb_regex = NERB('music_entities.yaml')
artists = nerb_regex.extract_named_entity('ARTIST', prog_rock_wiki)

print(artists)

for match in nerb_regex.ARTIST.finditer(prog_rock_wiki):
    print(match.group())
