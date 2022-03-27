from setuptools import setup, find_packages


setup(
    name='nerb',
    description='Named Entity Regex Builder (NERB): Streamlined named capture groups',
    author='Johnny Greco',
    version='0.0.1',
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
