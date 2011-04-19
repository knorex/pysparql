from yardflib import vocab, literal, query
from yardflib.query import *
from yardflib.model import *
from utils import to_sse

class Evaluatable(object):
	
	def evaluate(self, binding = {}):
		args = []
		for operand in operands:
			args.append(operand.evaluate(bindings))
		
		if options.get('memoize'):
			return self.memoize(*args)
		else:
			return self.apply(*args)

	def memoize(*operands):
		if not self._cache:
			self._cache = yardflib.util.Cache(options.get('memoize') if isinstance(options.get('memoize'), int) else -1)
		term = self._cache.get(operands)
		if not term:
			term = self.apply(*operands)
			self._cache.set(operands, term)
		return term

	def apply(self, *operands):
		raise Exeption("Not Implemented method: %s.apply()" % self.__class__.name)

class ExpressionFactory(object):

	@classmethod
	def factory(self, *sse):
		return ExpressionFactory.new(sse)

	@classmethod
	def new(self, sse, options = {}):

		# sse must be a list
		if isinstance(sse, tuple):
			sse = list(sse)
		if not isinstance(sse, list):
			raise Exception("Invalid Expression form: %s" % repr(sse))

		if not options.has_key('depth'):
			options['depth'] = 0

		opts = options.copy()
		opts['depth'] = options['depth'] + 1

		operator = Operator.factory(sse[0], len(sse) - 1)

		if not operator:
			if isinstance(sse[0], list):
				return [ExpressionFactory.new(s, opts) for s in sse]
			else:
				r = []
				for s in sse:
					if isinstance(s, list):
						r.append(ExpressionFactory.new(s, opts))
					else:
						r.append(s)
				return r
		operands = []
		for operand in sse[1:]:
			if isinstance(operand, list):
				operands.append(ExpressionFactory.new(operand, opts))
			elif isinstance(operand, Operator) or isinstance(operand, Variable) or isinstance(operand, Term) or isinstance(operand, Query) or isinstance(operand, str):
				operands.append(operand)
			elif isinstance(operand, bool) or isinstance(operand, int) or isinstance(operand, str) or isinstance(operand, datetime) or isinstance(operand, date) or isinstance(operand, time):			
				operands.append(Literal(operand))
			else:
				raise Exception("Invalid Expression operand: %s", repr(operand))

		for k in ['debug', 'depth', 'prefixes', 'base_uri']: 
			if options.has_key(k):
				options.pop(k)
				
		if len(options) > 0:
			operands.update(options)

		return operator(*operands)

	@classmethod
	def cast(self, datatype, value):
		if isinstance(datatype, vocab.XSD.get_prop('dateTime')):
			if isinstance(value, literal.DateTime) or isinstance(value, literal.Date) or isinstance(value, literal.Time):
				return Literal(value, {'datatype' : datatype})
			elif isinstance(value, literal.Numeric) or isinstance(value, literal.Boolean) or isinstance(value, URI) or isinstance(value, Node):
				raise Exception("Value %s cannot be cast as %s" % (repr(value), datatype))
			else:
				return Literal(value.value, {'datatype': datatype, 'validate': True})
		elif isinstance(datatype, vocab.XSD.get_prop('float')) or isinstance(datatype, vocab.XSD.get_prop('double')):
			if isinstance(value, literal.Numeric) or isinstance(value, literal.Boolean):
				return Literal(value, {'datatype' : datatype})
			elif isinstance(value, literal.DateTime) or isinstance(value, literal.Date) or isinstance(value, literal.Time) or isinstance(value, URI) or isinstance(value, Node):
				raise Exception("Value %s cannot be cast as %s" % (repr(value), datatype))
			else:
				return Literal(value.value, {'datatype': datatype, 'validate': True})
		elif isinstance(datatype, vocab.XSD.get_prop('boolean')):
			if isinstance(value, literal.Boolean):
				return value
			elif isinstance(value, literal.Numeric):
				return literal.Boolean(value.value != 0)
			elif isinstance(value, literal.DateTime) or isinstance(value, literal.Date) or isinstance(value, literal.Time) or isinstance(value, URI) or isinstance(value, Node):
				raise Exception("Value %s cannot be cast as %s" % (repr(value), datatype))
			else:
				return Literal(len(value),  {'datatype': datatype, 'validate': True})
		elif isinstance(datatype, vocab.XSD.get_prop('decimal')) or isinstance(datatype, vocab.XSD.get_prop('integer')):
			if isinstance(value, literal.Integer) or isinstance(value, literal.Decimal) or isinstance(value, literal.Boolean):
				return Literal(value, {'datatype': datatype})
			elif isinstance(value, literal.DateTime) or isinstance(value, literal.Date) or isinstance(value, literal.Time) or isinstance(value, URI) or isinstance(value, Node):
				raise Exception("Value %s cannot be cast as %s" % (repr(value), datatype))
			else:
				return Literal(value.value, {'datatype': datatype, 'validate': True})
		elif isinstance(datatype, vocab.XSD.get_prop('string')):
			return Literal(value, {'datatype': datatype})
		else:
			raise Exception("Expected datatype (%s) to be an XSD type" % datatype)

class Expression(object):
		
	@property
	def is_variable(self):
		return false
	
	@property
	def is_constant(self):
		return not self.is_variable

	@classmethod
	def parse(self, sse, options = {}):
		pass

	def optimize(self):
		return self
	
	def evaluate(bindings = {}):
		return self

class Operator(Expression):
	
	base_uri = ""
	prefixes = ""
	
	def __init__(self, *operands):
		ops = list(operands)
		self.options = ops[-1].copy() if isinstance(ops[-1],dict) else {}
		ops.pop()
		self.operands = []
		for operand in ops:
			if isinstance(operand, Operator) or isinstance(operand, Variable) or isinstance(operand, Term) or isinstance(operand, Query) or isinstance(operand, Pattern) or isinstance(operand, list):
				self.operands.append(operand)
			elif isinstance(operand, bool) or isinstance(operand, int) or isinstance(operand, long) or isinstance(operand, str) or isinstance(operand, datetime) or isinstance(operand, date) or isinstance(operand, time):
				self.operands.append(Literal(operand))
			else:
				raise Exception("Invalid Operator operand: %s" % repr(operand))

	@classmethod
	def factory(self, name, arity = None):
		s = str(name).lower()
		if s == "<=>"         : return Compare
		elif s == "="         : return Equal
		elif s == "!="        : return NotEqual
		elif s == "<"         : return LessThan
		elif s == ">"         : return GreaterThan
		elif s == "<="        : return LessThanOrEqual
		elif s == ">="        : return GreaterThanOrEqual
		elif s == "*"         : return Multiply
		elif s == "/"         : return Divide
		elif s == "+"         : return (Plus if self.arity == 1 else Add)
		elif s == "-"         : return (Minus if self.arity == 1 else Subtract)
		elif s == "not" or s == "!": return Not
		elif s == "plus"      : return Plus
		elif s == "minus"     : return Minus
		elif s == "bound"     : return Bound
		elif s == "isblank"   : return IsBlank
		elif s == "isiri"     : return IsIRI
		elif s == "isuri"     : return IsIRI # alias
		elif s == "isliteral" : return IsLiteral
		elif s == "str"       : return Str
		elif s == "lang"      : return Lang
		elif s == "datatype"  : return Datatype
		elif s == "or" or s == "||": return Or
		elif s == "and" or s == "&&": return And
		elif s == "multiply"  : return Multiply
		elif s == "divide"    : return Divide
		elif s == "add"       : return Add
		elif s == "subtract"  : return Subtract
		elif s == "sameterm"  : return SameTerm
		elif s == "langmatches" : return LangMatches
		elif s == "regex"     : return Regex
		
		# Miscellaneous
		elif s == "asc"       : return Asc
		elif s == "desc"      : return Desc
		elif s == "exprlist"  : return Exprlist
		
		# Datasets
		elif s == "dataset" : return Dataset
		
		# Query forms
		elif s == "ask"       : return Ask
		elif s == "base"      : return Base
		elif s == "bgp"       : return Query
		elif s == "construct" : return Construct
		elif s == "describe"  : return Describe
		elif s == "distinct"  : return Distinct
		elif s == "filter"    : return Filter
		elif s == "graph"     : return Graph
		elif s == "join"      : return Join
		elif s == "leftjoin"  : return LeftJoin
		elif s == "order"     : return Order
		elif s == "prefix"    : return Prefix
		elif s == "project"   : return Project
		elif s == "reduced"   : return Reduced
		elif s == "slice"     : return Slice
		elif s == "triple"    : return query.Pattern
		elif s == "union"     : return Union
		else: return None # not found				
		
	@property
	def arity(self):
		return self.ARITY

	def to_sse(self):
		operator = self.NAME[0]
		return [operator] + to_sse(self.operands)

#      operator = [self.class.const_get(:NAME)].flatten.first
#      [operator, *(operands || []).map(&:to_sse)]
		
	ARITY = -1

class Nullary(Operator):

	ARITY = 0
	
	def __init__(self, options = {}):
		super(Nullary, self).__init__(options)
	
class Unary(Operator):
	
	ARITY = 1	
	
	def __init__(self, arg, options = {}):
		super(Unary, self).__init__(arg, options)	
		
class Binary(Operator):

	ARITY = 2

	def __init__(self, arg1, arg2, options = {}):
		super(Binary, self).__init__(arg1, arg2, options)

class Ternary(Operator):
	ARITY = 3
	
	def __init__(self, arg1, arg2, arg3, options = {}):
		super(Ternary, self).__init__(arg1, arg2, arg3, options)	

class Compare(Binary):
	
	NAME = ["<=>"]

	def apply(self, left, right):
		if isinstance(left, Literal) and isinstance(right, Literal):
			if (left.is_plain and right.is_plain) or (isinstance(left, literal.Numeric) and isinstance(right, literal.Numeric)) or (left.datatype == right.datatype and left.language == right.language):
				return Literal(left[self.NAME](right))
			elif left.is_plain and right.datatype == vocab.XSD.get_prop('string') and left.value == right.value:
				return Literal(-1)
			elif right.is_plain and left.datatype == vocab.XSD.get_prop('string') and left.value == right.value:
				return Literal(1)
			else:
				raise Exception("Unable to compare %s and %s" % (repr(left), repr(right)))
		elif isinstance(left, URI) and isinstance(right, URI):
			return Literal(Literal(str(left))[self.NAME](Literal(str(right))))
		elif isinstance(left, Node) and isinstance(right, Node):
			return Literal(0)
		elif left == None and right == None:
			return Literal(0)

		elif isinstance(left, Node) and isinstance(right, Term):
			return Literal(-1)
		elif isinstance(left, Term) and isinstance(right, Node):
			return Literal(1)

		elif isinstance(left, URI) and isinstance(right, Term):
			return Literal(-1)
		elif isinstance(left, Term) and isinstance(right, URI):
			return Literal(1)

		else:
			raise Exception("expected two RDF::Term operands, but got %s and %s" % (repr(left), repr(right)))
		
class Equal(Compare):
	
	NAME = ["="]
	
	def apply(self, term1, term2):
		return Literal(term1 == term2)
		
class NotEqual(Equal):
	
	NAME = ["!="]
	
	def apply(self, term1, term2):
		return Literal(term1 != term2)
		
class LessThan(Compare):
	NAME = ["<"]
	
class GreaterThan(Compare):
	NAME = [">"]
	
class LessThanOrEqual(Compare):
	NAME = ["<="]
	
class GreaterThanOrEqual(Compare):
	NAME = [">="]
	
class Multiply(Binary):
	NAME = ["*", "multiply"]

	def apply(self, left, right):
		if isinstance(left, literal.Numeric) and isinstance(right, literal.Numeric):
			return left*right
		else:
			raise Exception("expected two literal.Numeric operands, but got %s and %s" % (repr(left), repr(right)) )

class Divide(Binary):
	NAME = ["/", "divide"]

	def apply(self, left, right):
		if isinstance(left, literal.Numeric) and isinstance(right, literal.Numeric):
			if isinstance(left, literal.Decimal) and right == 0:
				raise Exception("Divided by Zero")			
			return left/right
		else:
			raise Exception("expected two Numeric operands, but got %s and %s" % (left, right))

class Add(Binary):
	NAME = ["+", "add"]
	
	def apply(self, left, right):
		if isinstance(left, literal.Numeric) and isinstance(right, Numeric):
			return left + right
		else:
			raise Exception("expected two Numeric operands, but got %s and %s" % (left, right)) 
			
class Plus(Unary):
	NAME = ["+", "plus"]
	
	def apply(self, term):
		if isinstance(term, literal.Numeric):
			return term
		else:
			raise Exception("Expected an literal.Numeric, but got %s" % repr(term))

class Subtract(Binary):
	NAME = ["-", "subtract"]
	
	def apply(self, left, right):
		if isinstance(left, literal.Numeric) and isinstance(right, literal.Numeric):
			return left - right
		else:
			raise Exception("expected two Numeric operands, but got %s and %s" % (left, right)) 

class Minus(Unary):
	NAME = ["-", "minus"]
	
	def apply(self, term):
		if isinstance(term, literal.Numeric):
			return -term
		else:
			raise Exception("Expected an literal.Numeric, but got %s" % repr(term))
			
class Not(Unary):
	NAME = ["not", "!"]
	
	def apply(self, operand):
		if isinstance(operand, literal.Boolean):
			return Literal(operand == False)
		else:
			raise Exception("Expected an literal.Boolean, but got %s" % repr(term))
			
class Bound(Unary, Evaluatable):
	NAME = ["bound"]

	def __init__(self, var, options = {}):
		super(Unary, self).__init__(var, options)
		
	def evaluate(self, bindings = {}):
		if isinstance(self.operands[0], Variable):
			if self.operands[0].evaluate(bindings):
				return Literal(True)
			else: 
				return Literal(False)
		else:
			raise Exception("Expected a Variable, but got %s" % repr(self.operands[0]))
			
class IsBlank(Unary):
	NAME = ["isBlank"]

	def apply(self, term):
		if isinstance(term, Node):
			return Literal(True)
		elif isinstance(term, Term):
			return Literal(False)
		else:
			raise Exception("Expected a Term, but got %s" % repr(term))

class IsIRI(Unary):
	NAME = ["isIRI", "isURI"]
	
	def apply(self, term):
		if isinstance(term, URI):
			return Literal(True)
		elif isinstance(term, Term):
			return Literal(False)
		else:
			raise Exception("Expected a Term, but got %s" % repr(term))
			
class IsLiteral(Unary):
	NAME = ["isLiteral"]
	
	def apply(self, term):
		if isinstance(term, BaseLiteral):
			return Literal(True)
		elif isinstance(term, Term):
			return Literal(False)
		else:
			raise Exception("Expected a Term, but got %s" % repr(term))
			
class Str(Unary):
	NAME = ["str"]
	
	def apply(self, term):
		if isinstance(term, BaseLiteral):
			return Literal(term.value)
		elif isinstance(term, URI):
			return Literal(str(term))
		else:
			raise Exception("Expected a Literal or URI, but got %s" % repr(term))		

class Lang(Unary):
	NAME = ["lang"]
	
	def apply(self, lit):
		if isinstance(lit, BaseLiteral):
			return Literal(str(lit.language))
		else:
			raise Exception("Expected a Literal, but got %s" % repr(lit))

class Datatype(Unary):
	NAME = ["datatype"]
	
	def apply(self, lit):
		if isinstance(lit, BaseLiteral):
			if lit.is_typed:
				return URI(lit.datatype)
			elif lit.is_plain:
				return vocab.XSD.get_prop('string')
			else:
				raise Exception("Expected a typed or plain Literal, but got %s" % repr(lit))				
		else:
			raise Exception("Expected a Literal, but got %s" % repr(lit))				
			
class Or(Binary, Evaluatable):
				
	NAME = ["or", "||"]		
	
	def evaluate(self, bindings = {}):
		try:
			left = self.operands[0].evaluate(bindings) == True
		except:
			left = None
		
		try:
			right = self.operands[1].evaluate(bindings) == True
		except:
			right = None
		
		if (left == None) or (right == None):
			raise Exception("Type Error")
		elif left == None:
			return Literal(True)
		elif right == None:
			return Literal(True)
		else:
			return Literal(left or right)

class And(Binary, Evaluatable):
	
	NAME = ["or", "and"]		
	
	def evaluate(self, bindings = {}):
		try:
			left = self.operands[0].evaluate(bindings) == True
		except:
			left = None
		
		try:
			right = self.operands[1].evaluate(bindings) == True
		except:
			right = None
		
		if (left == None) or (right == None):
			raise Exception("Type Error")
		elif left == None:
			return Literal(False)
		elif right == None:
			return Literal(False)
		else:
			return Literal(left and right)

class Multiply(Binary):
	NAME = ["+", "multiply"]
	
	def apply(self, left, right):
		if isinstance(left, Numeric) and isinstance(right, Numeric):
			return left * right
		else:
			raise Exception("Expected two Numeric operands, but got %s and %s" % (left, right))

class Divide(Binary):
	NAME = ["+", "divide"]
	
	def apply(self, left, right):
		if isinstance(left, Numeric) and isinstance(right, Numeric):
			return left / right
		else:
			raise Exception("Expected two Numeric operands, but got %s and %s" % (left, right))

class Add(Binary):
	NAME = ["+", "add"]
	
	def apply(self, left, right):
		if isinstance(left, Numeric) and isinstance(right, Numeric):
			return left + right
		else:
			raise Exception("Expected two Numeric operands, but got %s and %s" % (left, right))

class Subtract(Binary):
	NAME = ["+", "subtract"]
	
	def apply(self, left, right):
		if isinstance(left, Numeric) and isinstance(right, Numeric):
			return left - right
		else:
			raise Exception("Expected two Numeric operands, but got %s and %s" % (left, right))

class SameTerm(Binary, Evaluatable):
	
	NAME = ["sameTerm"]

	def apply(self, term1, term2):
		return Literal(term1 == term2)

	def optimize(self):
		if isinstance(self.operands[0], Variable) and (self.operands[0] == self.operands[1]):
			return Literal(True)
		else:
			return super(SameTerm, self).optimize()

class LangMatches(Binary, Evaluatable):
	
	NAME = ["langMatches"]
	
	def apply(self, language_tag, language_range):
		if not isinstance(language_tag, BaseLiteral) or not language_tag.is_plain:
			raise Exception("Expected a plain Literal, but got %s" % repr(language_tag))

		if not isinstance(language_range, BaseLiteral) or not language_range.is_plain:
			raise Exception("Expected a plain Literal, but got %s" % repr(language_range))

		language_tag = str(language_tag).lower()
		language_range = str(language_range).lower()	
		
		#TOTO: there's a bug in ruby version, wait for response from Greg
		
class Regex(Ternary, Evaluatable):
	
	NAME = ["regex"]
	
	def __init__(self, text, pattern, flags = Literal(""), options = {}):
		super(Regex, self).__init__(text, pattern, flags, options)
	
	def apply(self, text, pattern, flags = Literal("")):
		if not isinstance(text, BaseLiteral) or not text.is_plain:
			raise Exception("Expected a plain Literal, but got %s" % repr(text))
			
		if not isinstance(pattern, BaseLiteral) or not pattern.is_plain:
			raise Exception("Expected a plain Literal, but got %s" % repr(pattern))
			
		if not isinstance(flags, BaseLiteral) or not flags.is_plain:
			raise Exception("Expected a plain Literal, but got %s" % repr(flags))
			
		text = str(text)
		pattern = str(pattern)
		flags = str(flags)
		
		options = 0
		if "m" in flags: options |= re.M
		if "x" in flags: options |= re.X
		if "i" in flags: options |= re.I
		
		p = re.compile(pattern, options)
		return Literal(p.search(text) != None)
			
class Asc(Unary, Evaluatable):
	
	NAME = ["asc"]
	
	def evaluate(self, bindings = {}):
		self.operands[0].evaluate(bindings)

class Desc(Asc, Evaluatable):
	
	NAME = ["desc"]			
	
class Exprlist(Operator, Evaluatable):
	NAME = ["exprlist"]
	
	def evaluate(self, bindings = {}):
		res = True
		for op in self.operands:
			if op.evaluate(bindings) != True:
				res = False
				break
		
		return Literal(res)

class Dataset(Binary, Query):
	NAME = ["dataset"]
	
	def optimize(self):
		self.operands[-1].optimize()
		
class Ask(Unary, Query):
	NAME = ["ask"]
	
class Base(Binary, Query):
	NAME = ["base"]
	
class Construct(Binary, Query):
	NAME = ["construct"]
	
class Describe(Binary, Query):
	NAME = ["describe"]
	
class Distinct(Unary, Query):
	NAME = ["distinct"]
	
class Filter(Binary, Query):
	NAME = ["filter"]	
	
class Graph(Binary):
	NAME = ["graph"]
	
	@classmethod
	def new(self, context, bgp):
		bgp.context = context
		return bgp
		
class Join(Binary, Query):
	NAME = ["join"]
	
class LeftJoin(Operator, Query):
	NAME = ["leftjoin"]	

class Order(Binary, Query):
	NAME = ["order"]
	
class Prefix(Binary, Query):
	NAME = ["prefix"]
	
class Project(Binary, Query):
	NAME = ["project"]
	
class Reduced(Unary, Query):
	NAME = ["reduced"]

class Slice(Ternary, Query):
	NAME = ["slice"]
	
class Union(Binary, Query):
	NAME = ["union"]