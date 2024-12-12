# setup.py
from setuptools import setup, find_packages

setup(
    name='checker',                # Name of the package

    version='0.1.3',

    packages=find_packages(),
    install_requires=[              # Dependencies
        'requests',
        'termcolor',
        'pyfiglet==0.8.post1',
        'dnspython',
        'argparse',
        'beautifulsoup4 '
    ],
    entry_points={                  # Create command-line entry point
        'console_scripts': [
            'checker = checker.checker:main',  # Call `run_checker` from checker.py
        ],
    },
)
