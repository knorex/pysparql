__version__ = "0.1"
__date__ = "2011/03/24"

__all__ = [
	'Lexer',
	'Parser'
    ]

import sys

# generator expressions require 2.4
assert sys.version_info >= (2, 4, 0), "yardflib requires Python 2.4 or higher"
del sys

import logging
_LOGGER = logging.getLogger("pysparql")
_LOGGER.info("version: %s" % __version__)


from pysparql.lexer import Lexer
from pysparql.parser import Parser