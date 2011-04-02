import re

class Scanner (object):
	
	def __init__(self, s):
		self.s = s
		self.offset = 0

	def eos(self):
		return self.offset == len(self.s)

	def rest(self):
		return self.s[self.offset:]

	def scan(self, pattern):
		match = pattern.match(self.s, self.offset)
		if match is not None:
			self.offset = match.end()
			return match
		return None

class Token (object):
	
	def __init__(self, type, value = None, options = {}):
		self.type = type
		self.value = value	
		self.lineno = options['lineno']
	
	def __repr__(self):
		return "%s : %s" % (self.type, self.value)

	@property
	def representation(self):
		return self.type if self.type else self.value

class TokenError(Exception):
	
	def __init__(self, message, options = {}):
		self._message = message
		self.query  = options.get('query')
		self.token  = options.get('token')
		self.lineno = options.get('lineno')

	def __str__(self):
		return repr(self._message)

class Lexer:

	ESCAPE_CHARS         = {
      '\\t'   : "\t",    # \u0009 (tab)
      '\\n'   : "\n",    # \u000A (line feed)
      '\\r'   : "\r",    # \u000D (carriage return)
      '\\b'   : "\b",    # \u0008 (backspace)
      '\\f'   : "\f",    # \u000C (form feed)
      '\\"'  : '"',     # \u0022 (quotation mark, double quote mark)
      '\\\'' : '\'',    # \u0027 (apostrophe-quote, single quote mark)
      '\\\\' : '\\'     # \u005C (backslash)
	}

	KEYWORDS			 = ['SELECT','CONSTRUCT','DESCRIBE','ASK','BASE','PREFIX','LIMIT','OFFSET','DISTINCT','REDUCED','ORDER','BY','ASC','DESC','FROM','NAMED','WHERE','GRAPH','OPTIONAL','UNION','FILTER']
	FUNCTIONS			 = ['STR','LANGMATCHES','LANG','DATATYPE','BOUND','sameTerm','isIRI','isURI','isBLANK','isLITERAL','REGEX']
	VAR1                 = re.compile("\?([0-9]|_|[A-Z]|[a-z])*")
	VAR2                 = re.compile("\$([0-9]|_|[A-Z]|[a-z])*")
	IRI_REF              = re.compile("<([^<>\"{}|^`\\\x00-\x20]*)>")
	
	PN_CHARS_BASE        = "[A-Z]|[a-z]"
	PN_CHARS_U           = "_|[A-Z]|[a-z]"                  
	PN_CHARS             = "-|[0-9]|%s" % PN_CHARS_U
	PN_CHARS_BODY        = "(?:(?:\.|%s)*(?:%s))?"	% (PN_CHARS, PN_CHARS)
	PN_PREFIX            = "%s%s" % (PN_CHARS_BASE, PN_CHARS_BODY)
	PN_LOCAL             = "(?:[0-9]|%s)%s" % (PN_CHARS_U, PN_CHARS_BODY)
	ECHAR                = "\\\[tbnrf\\\"']"
	EXPONENT			 = "[eE][+-]?[0-9]+"
	
	WS					 = re.compile("(\x20|\x09|\x0D|\x0A)+")
	COMMENT              = re.compile("#.*")

	VAR1                 = re.compile("\?([0-9_A-Za-z]*)")
	VAR2                 = re.compile("\$([0-9_A-Za-z]*)")
	IRI_REF              = re.compile("<([^<>\"{}|^`\\\x00-\x20]*)>")	
	PNAME_LN             = re.compile("(%s?):(%s)" % (PN_PREFIX, PN_LOCAL))
	PNAME_NS             = re.compile("(%s?):" % PN_PREFIX)
	STRING_LITERAL_LONG1 = re.compile("'''((?:(?:'|'')?(?:[^'\\]|%s)+)*)'''" % ECHAR, re.M)
	STRING_LITERAL_LONG2 = re.compile("\"\"\"((?:(?:\"|\"\")?(?:[^\"\\]|%s)+)*)\"\"\"" % ECHAR, re.M)
	STRING_LITERAL1      = re.compile("'((?:[^\x27\x5C\x0A\x0D]|%s)*)'" % ECHAR)	
	STRING_LITERAL2      = re.compile("\"((?:[^\x22\x5C\x0A\x0D]|%s)*)\"" % ECHAR)	

	LANGTAG              = re.compile("@([a-zA-Z]+(?:-[a-zA-Z0-9]+)*)")
	DOUBLE               = re.compile("(?:[0-9]+\.[0-9]*|\.[0-9]+|[0-9]+)%s" % EXPONENT)
	INTEGER              = re.compile("[0-9]+")
	DECIMAL              = re.compile("(?:[0-9]+\.[0-9]*|\.[0-9]+)")
	DOUBLE               = re.compile("(?:[0-9]+\.[0-9]*|\.[0-9]+|[0-9]+)%s" % EXPONENT)
	BooleanLiteral       = re.compile("true|false")
	BLANK_NODE_LABEL     = re.compile("_:(%s)" % PN_LOCAL)
	
	NIL                  = re.compile("\(\x20|\x09|\x0D|\x0A*\)")
	ANON                 = re.compile("\[\x20|\x09|\x0D|\x0A*\]")

	KEYWORD              = re.compile("%s|%s" % ("|".join(KEYWORDS), "|".join(FUNCTIONS)), re.I)
	DELIMITER            = re.compile("\^\^|[{}\(\)\[\],;\.]")
	OPERATOR             = re.compile("a|\|\||&&|!=|<=|>=|[!=<>+\-*\/]")
	
	
	patterns			=	[ 	'VAR1', 'VAR2', 'IRI_REF', 'PNAME_LN', 'PNAME_NS', 'STRING_LITERAL_LONG1', 'STRING_LITERAL_LONG2',
								'STRING_LITERAL1', 'STRING_LITERAL2', 'LANGTAG', 'DOUBLE', 'DECIMAL', 'INTEGER', 'BooleanLiteral', 
								'BLANK_NODE_LABEL', 'KEYWORD', 'DELIMITER', 'OPERATOR' ,'NIL', 'ANON'
							] 

	def __init__(self, query, options = {}):
		self.query = query
		self.lineno = 0
		
	def unescape_string(self, s):
		return re.sub(self.ECHAR, lambda escaped: self.ESCAPE_CHARS[escaped.group(0)] , s)

	def token(self, type, value = None):
		return Token(type, value, {'lineno' : self.lineno})

	def tokens(self):
		self.lineno = 0
		scanner = Scanner(self.query)
		t = scanner.scan(self.WS)
		while not scanner.eos():
			if t: self.lineno += t.group(0).count("\n")
			
			scanner.scan(self.COMMENT)
			
			t = None
			for pattern in self.patterns:
				t = scanner.scan(getattr(self,pattern))
				if t is not None:
					break

			if t is not None:
				if pattern == 'PNAME_LN':
					yield self.token(pattern, [t.group(1),t.group(2)])
					
				elif pattern in ['STRING_LITERAL_LONG1', 'STRING_LITERAL_LONG2', 'STRING_LITERAL1', 'STRING_LITERAL2']:
					yield self.token(pattern, self.unescape_string(t.group(0)))
					
				elif pattern in ['DOUBLE', 'DECIMAL', 'INTEGER', 'BooleanLiteral', 'DOUBLE']:
					yield self.token(pattern, t.group(0))
	
				elif pattern in ['DECIMAL', 'INTEGER']:
					yield self.token(pattern, t.group(0))

				elif pattern in ['OPERATOR', 'DELIMITER']:
					yield self.token(None, t.group(0))
									
				elif pattern in ['NIL', 'ANON']:
					yield self.token(pattern)	

					
				elif pattern == 'KEYWORD':
					yield self.token(None, t.group(0).upper())	
					
				else:
					yield self.token(pattern, t.group(1))
					
			else: # t is None
				try:
					lexeme = re.split("\x20|\x09|\x0D|\x0A|#.*",scanner.rest())[0]
				except Exeption, e:
					lexeme = scanner.rest()
				raise TokenError("invalid token %s at line %d" % (repr(lexeme), self.lineno + 1),
                				{'input' : self.query, 'token' : lexeme, 'lineno' : self.lineno} )
                			
				break

			t = scanner.scan(self.WS)