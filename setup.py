#!/usr/bin/env python

from distutils.core import setup

# Install pysparql
from pysparql import __version__


setup(
    name = 'pysparql',
    version = __version__,
    description = "SPARQL lexer and parser library for Python",
    author = "Knorex",
    author_email = "mail_us@knorex.com",
    maintainer = "Huy Phan",
    maintainer_email = "dachuy@gmail.com",
    url = "http://github.com/huyphan/yardflib",
#    license = "",
    platforms = ["any"],
    classifiers = ["Programming Language :: Python",
                   "License :: BSD License",
                   "Topic :: Software Development :: Libraries :: Python Modules",
                   "Operating System :: OS Independent",
                   "Natural Language :: English",
                   ],
    long_description = \
    """
    """,
    download_url = "",

    packages = ['pysparql'],

    )
