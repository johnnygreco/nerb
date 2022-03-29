# 🏗️ Named Entity Regex Builder (NERB)
#### _Streamlining named capture groups_

---

[![tests](https://github.com/johnnygreco/nerb/actions/workflows/tests.yml/badge.svg)](https://github.com/johnnygreco/nerb/actions/workflows/tests.yml)
[![mypy](https://github.com/johnnygreco/nerb/actions/workflows/mypy.yml/badge.svg)](https://github.com/johnnygreco/nerb/actions/workflows/mypy.yml)
[![license](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://github.com/johnnygreco/nerb/blob/main/LICENSE)


## Overview

Have you ever had a project with a large but _human-manageable_ list of entities that you need to extract from a 
text dataset? If so, you have probably had the pleasure (burden?) of working with a codebase that is littered with 
ginormous regex objects with lots of named capture groups, making your code difficult to parse and develop 😫.

The Named Entity Regex Builder (NERB) is a lightweight package that will build your compiled regex objects 
based on patterns set in a dictionary or yaml config file, which significantly cleans up your code and makes 
it _much_ easier to modify your regex patterns during development 😀.

Let's go 🚀🚀🚀    

## Installation 

You can install the latest stable version of `nerb` using pip:

```shell
pip install nerb
```

If you would like to contribute to the code (awesome!), install the development version by
cloning this repository and pip installing the package in editable mode with the extra "tests" option
for running unit tests and type checking:

```shell
git clone https://github.com/johnnygreco/nerb.git
cd nerb
pip install -e ".[tests]"
```

## Example Usage

Suppose we want to extract some musical artists from the [Progressive Rock Wikipedia page](https://en.wikipedia.org/wiki/Progressive_rock). We'll put the groups we are searching for in a config file called `music_entities.yaml`: 

```yaml
ARTIST:
  Coheed: 'Coheed(?:\s(?:and|\&)\sCambria)?'
  The Doors: '[Tt]he\Doors'
  Dream Theater: 'Dream\sTheater'
  Foo Fighters: 'Foo\sFighters'
  The Grateful Dead: '(?:[Tt]he\s)?Grateful\sDead|[Tt]he\sWarlocks'
  Jay Z: 'Jay(?:\s|-)Z|Shawn(?:\sCorey\s)?\sCarter'
  Mars Volta: 'Mars\sVolta'
  Miles Davis: 'Miles\sDavis'
  Pink Floyd: 'Pink\sFloyd'
  Thelonious Monk: 'Thelonious\sMonk'
  The Who: '[Tt]he\sWho'

GENRE:
  _flags: IGNORECASE
  Hip Hop: 'rap|hip\shop'
  Jazz: '(?:smooth\s)?jazz'
  Pop: 'pop(?:ular)?'
  Rock: '(?:(?:prog(:?ressive)?|alternative|punk)\s)?rock|rock\s(?:and|\&|n)\sroll'
```
> NOTE: `GENRE` is also included as an entity in the config file. Notice that we set the `IGNORECASE` flag using the special `_flags` keyword. If we need more than one flag, we can pass them as a list of flags (e.g., `[IGNORECASE, MULTILINE]`).

We can now create a `NERB` regex object:

```python
from nerb import NERB
nerb_regex = NERB('music_entities.yaml', add_word_boundaries=True)
```
> NOTE: `add_word_boundaries` is `True` by default. This tells `NERB` to add word boundaries to every term in the regex patterns within the config file.

The `NERB` object automatically builds compiled regexes called `ARTIST` and `GENRE`, which are composed of named capture groups, where the group names are the keys (i.e., `Coheed`, `The Doors`, etc). You can access the `re.compile` objects as attributes:

```python 
nerb_regex.ARTIST
nerb_regex.GENRE
```

Suppose we have the text of the Wiki page in a file called `prog_rock_wiki.txt`. Then, we can extract the artists like this:
```python
with open('prog_rock_wiki.txt', 'r') as file:
    prog_rock_wiki = file.read()

artists = nerb_regex.extract_named_entity('ARTIST', prog_rock_wiki)
```

This `extract_named_entity` method returns a [`NamedEntityList`](https://github.com/johnnygreco/nerb/blob/main/src/nerb/named_entities.py) object:

```
NamedEntityList(
    [0] NamedEntity(name='The Who', entity='ARTIST', string='the Who', span=(8755, 8762))
    [1] NamedEntity(name='The Grateful Dead', entity='ARTIST', string='the Grateful Dead', span=(9342, 9359))
    [2] NamedEntity(name='Pink Floyd', entity='ARTIST', string='Pink Floyd', span=(9364, 9374))
    [3] NamedEntity(name='Pink Floyd', entity='ARTIST', string='Pink Floyd', span=(13766, 13776))
    [4] NamedEntity(name='Pink Floyd', entity='ARTIST', string='Pink Floyd', span=(16544, 16554))
    [5] NamedEntity(name='Pink Floyd', entity='ARTIST', string='Pink Floyd', span=(17316, 17326))
    [6] NamedEntity(name='Pink Floyd', entity='ARTIST', string='Pink Floyd', span=(17624, 17634))
    [7] NamedEntity(name='The Who', entity='ARTIST', string='the Who', span=(20938, 20945))
    [8] NamedEntity(name='Pink Floyd', entity='ARTIST', string='Pink Floyd', span=(23737, 23747))
    [9] NamedEntity(name='Pink Floyd', entity='ARTIST', string='Pink Floyd', span=(25647, 25657))
    [10] NamedEntity(name='Pink Floyd', entity='ARTIST', string='Pink Floyd', span=(25797, 25807))
    [11] NamedEntity(name='Pink Floyd', entity='ARTIST', string='Pink Floyd', span=(29819, 29829))
    [12] NamedEntity(name='Dream Theater', entity='ARTIST', string='Dream Theater', span=(32119, 32132))
    [13] NamedEntity(name='Coheed', entity='ARTIST', string='Coheed and Cambria', span=(33005, 33023))
    [14] NamedEntity(name='Mars Volta', entity='ARTIST', string='Mars Volta', span=(33033, 33043))
    [15] NamedEntity(name='Dream Theater', entity='ARTIST', string='Dream Theater', span=(35321, 35334))
    [16] NamedEntity(name='Pink Floyd', entity='ARTIST', string='Pink Floyd', span=(37839, 37849))
)
```

Alternatively, you can apply the compiled regex directly using the `ARTIST` attribute:

```python
for match in nerb_regex.ARTIST.finditer(prog_rock_wiki):
    print(match.group()) 
```

```
The_Who
The_Grateful_Dead
Pink_Floyd
Pink_Floyd
Pink_Floyd
Pink_Floyd
Pink_Floyd
The_Who
Pink_Floyd
Pink_Floyd
Pink_Floyd
Pink_Floyd
Dream_Theater
Coheed
Mars_Volta
Dream_Theater
Pink_Floyd
```
> NOTE: `NERB` automatically turns spaces into underscores when building the named capture group regex patterns.

The code and data for this example are in the [examples directory](https://github.com/johnnygreco/nerb/tree/main/examples).
