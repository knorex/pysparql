#!/usr/bin/env python

from distutils.core import setup

# Install yardflib
from yardflib import __version__


setup(
    name = 'yardflib',
    version = __version__,
    description = "YaRDFLib - Yet another RDFLib is a Python version of RDF.rb library",
    author = "Huy Phan",
    author_email = "dachuy@gmail.com",
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

    packages = ['yardflib'],

    )
