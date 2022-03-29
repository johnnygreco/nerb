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
