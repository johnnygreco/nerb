import os
import sys
import builtins
from setuptools import setup, find_packages

# HACK: fetch version
sys.path.append('src')
builtins.__NERB_SETUP__ = True
import nerb
version = nerb.__version__


# Publish the library to PyPI.
if "publish" in sys.argv[-1]:
    os.system("python setup.py sdist bdist_wheel")
    os.system(f"python3 -m twine upload dist/*{version}*")
    sys.exit()

# Push a new tag to GitHub.
if "tag" in sys.argv:
    os.system("git tag -a v{0} -m 'version {0}'".format(version))
    os.system("git push --tags")
    sys.exit()


setup(
    name='nerb',
    description='Named Entity Regex Builder (NERB): Streamlining named capture groups',
    author='Johnny Greco',
    version=version,
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    install_requires=[
        'pyyaml==6.0',
    ],
    extras_require={
        'tests': ['pytest', 'mypy'],
    },
    python_requires='>=3.8',
)
