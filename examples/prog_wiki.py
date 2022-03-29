from nerb import NERB

with open('prog_rock_wiki.txt', 'r') as file:
    prog_rock_wiki = file.read()

nerb_regex = NERB('music_entities.yaml')
artists = nerb_regex.extract_named_entity('ARTIST', prog_rock_wiki)

print(artists)

# NamedEntityList(
#     [0] NamedEntity(name='The Who', entity='ARTIST', string='the Who', span=(8755, 8762))
#     [1] NamedEntity(name='The Grateful Dead', entity='ARTIST', string='the Grateful Dead', span=(9342, 9359))
#     [2] NamedEntity(name='Pink Floyd', entity='ARTIST', string='Pink Floyd', span=(9364, 9374))
#     [3] NamedEntity(name='Pink Floyd', entity='ARTIST', string='Pink Floyd', span=(13766, 13776))
#     [4] NamedEntity(name='Pink Floyd', entity='ARTIST', string='Pink Floyd', span=(16544, 16554))
#     [5] NamedEntity(name='Pink Floyd', entity='ARTIST', string='Pink Floyd', span=(17316, 17326))
#     [6] NamedEntity(name='Pink Floyd', entity='ARTIST', string='Pink Floyd', span=(17624, 17634))
#     [7] NamedEntity(name='The Who', entity='ARTIST', string='the Who', span=(20938, 20945))
#     [8] NamedEntity(name='Pink Floyd', entity='ARTIST', string='Pink Floyd', span=(23737, 23747))
#     [9] NamedEntity(name='Pink Floyd', entity='ARTIST', string='Pink Floyd', span=(25647, 25657))
#     [10] NamedEntity(name='Pink Floyd', entity='ARTIST', string='Pink Floyd', span=(25797, 25807))
#     [11] NamedEntity(name='Pink Floyd', entity='ARTIST', string='Pink Floyd', span=(29819, 29829))
#     [12] NamedEntity(name='Dream Theater', entity='ARTIST', string='Dream Theater', span=(32119, 32132))
#     [13] NamedEntity(name='Coheed', entity='ARTIST', string='Coheed and Cambria', span=(33005, 33023))
#     [14] NamedEntity(name='Mars Volta', entity='ARTIST', string='Mars Volta', span=(33033, 33043))
#     [15] NamedEntity(name='Dream Theater', entity='ARTIST', string='Dream Theater', span=(35321, 35334))
#     [16] NamedEntity(name='Pink Floyd', entity='ARTIST', string='Pink Floyd', span=(37839, 37849))
# )
