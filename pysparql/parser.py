from lexer import Lexer, TokenError
from meta import BRANCHES
from extensions import GroupQuery
from utils import flatten
from yardflib.query import Variable, Pattern, Query
from yardflib.model import URI, Literal
from yardflib import vocab, literal
import algebra
import sys

class ParserError(Exception):

	def __init__(self, message, options = {}):
		self._message = message
		self.input	= options['input']
		self.production	 = options['production']
		self.lineno = options['lineno']
		self.position = options['position']

	def __str__(self):
		return repr(self._message)

class Parser(object):

	START = "http://www.w3.org/2000/10/swap/grammar/sparql#Query"
	GRAPH_OUTPUTS = ['query', 'distinct', 'filter', 'order', 'project', 'reduced', 'slice']

	def __init__(self, query = None, options = {}):
		options.update({"anon_base" : "b0", "validate" : False})
		if not options.get('prefixes'):
			options['prefixes'] = {}
		self.options = options
		self.productions = []
		self.vars = {}
		self.nd_var_gen = "0"
		if isinstance(query, list):
			self.input = None
			self.tokens = query
		else:
			if isinstance(query, Lexer):
				lexer = query
			else:
				lexer = Lexer(query, options)
			self.input = lexer.query
			self.tokens = [token for token in lexer.tokens()]

	@property
	def validate(self):
		return self.options.get('validate')

	def debug(self, node, message, options = {}):
		depth = options['depth'] if options.get('depth') else len(self.productions)
		if self.options.get('debug'):
			print >> sys.stderr, "[%d]%s%s: %s" %(self.lineno, '  '* depth, node, message)

	def error(self, node, message, options = {}):
		depth = options['depth'] if options.get('depth') else len(self.productions)
		if options.has_key('production'):
			node = options['production']
#		print >> sys.stderr, "[%d]%s%s: %s" %(self.lineno, ' '* depth, node, message)
		if options.get('token'):
			raise TokenError("Error on production %s%s at line %d: %s" % (options['production'], ' with input ' + repr(options['token']), self.lineno, message), options)
		else:
			raise TokenError("Error on production %s at line %d: %s" % (options['production'], self.lineno, message), options)

	def progress(self, node, message, options = {}):
		depth = options['depth'] if options.has_key('depth') else len(self.productions)
		if self.options.get('progress'):
			print >> sys.stderr, "[%d]%s%s: %s" %(self.lineno, ' '* depth, node, message)

	def abbr(self,prod_uri):
		if isinstance(prod_uri, list):
			return ",".join(prod_uri).split("#")[-1]
		else:
			return prod_uri.split("#")[-1]

	def accept(self, type_or_value):
		token = self.tokens[0]
		if token and ((token.type == type_or_value) or (token.value == type_or_value)):
			return self.tokens.pop(0)

	def parse(self, prod = START):
		self.prod_data = [{}]
		prod = prod.split("#")[-1]
		todo_stack = [{"prod" : prod, "terms" : None}]			
		while len(todo_stack) > 0:
			pushed = False
							
			if todo_stack[-1]['terms'] is None:
				todo_stack[-1]['terms'] = []
				if len(self.tokens):
					token = self.tokens[0]
				else:
					token = None

				if token is not None: self.lineno = token.lineno
				self.debug("parse(token)", "%s, prod %s, depth %s" % (repr(token), todo_stack[-1]['prod'], len(todo_stack) ))

				# Got an opened production
				self.on_start(self.abbr(todo_stack[-1]['prod']))
				if token is None: break
				cur_prod = todo_stack[-1]['prod']

				if not BRANCHES.get(cur_prod):
					self.error("parse", "No branches found for '%s'" % self.abbr(cur_prod),	{'production' : cur_prod, 'token' : token})
		
				prod_branch = BRANCHES[cur_prod]

	
				sequence = prod_branch[token.representation]
				self.debug("parse(production)", "cur_prod %s, token %s prod_branch %s, sequence %s" % (cur_prod, token.representation, prod_branch.keys, sequence))
				
				if sequence is None:
					expected = ' | '.join(map(','.join, s.values()))
					error("parse", "Found '%s' when parsing a %s. expected " % (token, self.abbr(cur_prod), expected), {'production' : cur_prod, 'token' : token})

				todo_stack[-1]['terms'] += sequence

			self.debug("parse(terms)", "stack %s, depth %d" % (todo_stack[-1], len(todo_stack)))
			while (len(todo_stack[-1]['terms']) > 0):
				term = todo_stack[-1]['terms'].pop(0)
				self.debug("parse token(%s)" % term, self.tokens)
				if term in [getattr(t,'representation') for t in self.tokens]:
					token = self.accept(term)	
					self.lineno = token.lineno
					self.debug("parse", "term(%s): %s" % (token, term))
					if token:
						self.on_token(self.abbr(term), token.value)
					else:
						error("parse",	"Found '%s...'; %s expected" % (word, term), {'production' : todo_stack[-1]['prod'], 'token' : tokens[0]})
				else:	
					todo_stack.append({'prod' : term, 'terms': None})
					self.debug("parse(push)", "stack %s, depth %d" % (term, len(todo_stack)))
					pushed = True
					break

			while (not pushed) and (len(todo_stack) > 0) and (len(todo_stack[-1]['terms']) == 0):
				self.debug("parse(pop)", "stack %s, depth %d" %(todo_stack[-1], len(todo_stack)))
				todo_stack.pop()
				self.on_finish()
				
		while len(todo_stack) > 0:
			self.debug("parse(pop)", "stack %s, depth %d" %(todo_stack[-1], len(todo_stack)))
			todo_stack.pop()
			self.on_finish()

	  # The last thing on the @prod_data stack is the result
		if (type(self.prod_data[-1]) != dict):
			self.result = self.prod_data[-1]
		elif len(self.prod_data[-1]) == 0:
			self.result = None
		elif self.prod_data[-1].get('query'):
			self.result = self.prod_data[-1]['query'][0] if len(self.prod_data[-1]['query']) == 1 else self.prod_data[-1]['query']
		else:
			key = self.prod_data[-1].keys()[0]
			self.result = [key] + self.prod_data[-1][key]
				
	def add_prod_datum(self, sym, values):
		if values == None: return
		
		if not self.prod_data[-1].get(sym):
			self.prod_data[-1][sym] = []

		self.debug("add_prod_datum(%s)" % sym, "%s += %s" % (self.prod_data[-1][sym], values))
		
		if type(values) == list:
			self.prod_data[-1][sym] += values
		elif values != None:
			self.prod_data[-1][sym].append(values)	

	def add_prod_data(self, sym, *values):

		if len(filter(lambda x: x != None, values)) == 0:
			return

		if not self.prod_data[-1].get(sym):
			self.prod_data[-1][sym] = []
		self.prod_data[-1][sym] += values
		self.debug("add_prod_datum(%s)" % sym, "%s += %s" % (self.prod_data[-1][sym], values))

	def flatten_filter(self, data):
		query = None
		expr = None
		if hasattr(data[-1], 'execute'):
			query = data.pop(0)
		if len(data) > 1:
			expr = Exprlist(*data)
		else:
			expr = data[0]
		return [expr, query]

	# [1]	  Query						::=		  Prologue ( SelectQuery | ConstructQuery | DescribeQuery | AskQuery )
	#
	# Generate an S-Exp for the final query
	# Inputs are :BaseDecl, :PrefixDecl, and :Query
	def handler_query_finish(self, data):
		
		query = data.get('query')[0]
		
		if data.get('PrefixDecl'):
			query = algebra.ExpressionFactory.factory('prefix', data.get('PrefixDecl')[0], query)

		if data.get('BaseDecl'):
			query = algebra.ExpressionFactory.factory('prefix', data.get('BaseDecl')[0], query)
		
		self.add_prod_datum('query', query)

	# [2]	  Prologue					::=		  BaseDecl? PrefixDecl*
	def handler_prologue_finish(self, data):
		self.add_prod_data('BaseDecl', data.get('BaseDecl'))
		if data.get('PrefixDecl'):
			self.add_prod_data('PrefixDecl', data.get('PrefixDecl'))

	# [3]	  BaseDecl		::=		  'BASE' IRI_REF
	def handler_basedecl_finish(self, data):
		self.base_uri = self.uri(data['iri'][-1])
		if not options.get('resolve_uris'):
			self.add_prod_datum('BaseDecl', data['iri'][-1])

	# [4] PrefixDecl := 'PREFIX' PNAME_NS IRI_REF";
	def handler_prefixdecl_finish(self, data):
		if data.get('iri'):
			self.prefix(data['prefix'], data['iri'][-1])
			self.add_prod_data('PrefixDecl', data['iri'].insert(0,data['prefix']+":"))

	# [5]	  SelectQuery				::=		  'SELECT' ( 'DISTINCT' | 'REDUCED' )? ( Var+ | '*' ) DatasetClause* WhereClause SolutionModifier
	def handler_selectquery_finish(self, data):
		query = self.merge_modifiers(data)
		self.add_prod_datum('query', query)
		
	# [6]	  ConstructQuery			::=		  'CONSTRUCT' ConstructTemplate DatasetClause* WhereClause SolutionModifier
	def handler_constructquery_finish(self, data):
		query = self.merge_modifiers(data)
		template = data.get('ConstructTemplate')
		if not template:
			template = []
		self.add_prod_datum('query', algebra.ExpressionFactory.factory('construct', template, query))

	# [7]	  DescribeQuery				::=		  'DESCRIBE' ( VarOrIRIref+ | '*' ) DatasetClause* WhereClause? SolutionModifier	
	def handler_describequery_finish(self, data):		
		query = self.merge_modifiers(data)
		to_describe = data.get('VarOrIRIref')
		if not to_describe:
			to_describe = []
		query = algebra.ExpressionFactory.factory('describe', to_describe, query)
		self.add_prod_datum('query', query)
		
	# [8]     AskQuery                  ::=       'ASK' DatasetClause* WhereClause
	def handler_askquery_finish(self, data):
		query = self.merge_modifiers(data)
		self.add_prod_datum('query', algebra.ExpressionFactory.factory('ask', query))

	# [10]    DefaultGraphClause        ::=       SourceSelector
	def handler_defaultgraphclause_finish(self, data):
		self.add_prod_datum('dataset', data.get('IRIref'))

    # [11]    NamedGraphClause          ::=       'NAMED' SourceSelector
	def handler_namedgraphclause_finish(self, data):
		data.get('IRIref').insert(0, 'named')
		self.add_prod_data('dataset', data.get('IRIref'))
					
	# [14]	  SolutionModifier			::=		  OrderClause? LimitOffsetClauses?			
	def handler_solutionmodifier_finish(self, data):
		self.add_prod_datum('order', data.get('order'))
		self.add_prod_datum('slice', data.get('slice'))
	
	# [15]	  LimitOffsetClauses		::=		  ( LimitClause OffsetClause? | OffsetClause LimitClause? )
	def handler_limitoffsetclauses_finish(self, data):
		if data.get('limit') or data.get('offset'):
			if data.get('limit'):
				limit = data['limit'][-1]
			else:
				limit = '_'

			if data.get('offset'):
				offset = data['offset'][-1]
			else:
				offset = '_'		
				
			self.add_prod_data('slice', offset, limit)	 
				
	# [16]	  OrderClause				::=		  'ORDER' 'BY' OrderCondition+	 
	def handler_orderclause_finish(self, data):
		res = data.get('OrderCondition')
		if res:
			if res[0] in ['asc','desc']:
				res = [res]
			self.add_prod_data('order', res)
			
	# [17]	  OrderCondition			::=		  ( ( 'ASC' | 'DESC' ) BrackettedExpression ) | ( Constraint | Var )
	def handler_ordercondition_finish(self, data):
		if data.get('OrderDirection'):
			self.add_prod_datum('OrderCondition', [data.get('OrderDirection') + data.get('Expression')])
		else:
			self.add_prod_datum('OrderCondition', data.get('Constraint') or data.get('Var'))
			
	# [18]	  LimitClause				::=		  'LIMIT' INTEGER
	def handler_limitclause_finish(self, data):
		self.add_prod_datum('limit', data.get('literal'))
		
	# [19]	  OffsetClause				::=		  'OFFSET' INTEGER
	def handler_offsetclause_finish(self, data):
		self.add_prod_datum('offset', data.get('literal'))
		
	# [20] GroupGraphPattern ::= '{' TriplesBlock? ( ( GraphPatternNotTriples | Filter ) '.'? TriplesBlock? )* '}'
	def handler_groupgraphpattern_finish(self, data):
		query_list = data.get('query_list')
		
		if query_list:
			lhs = None
			if data.get('query'):
				lhs = data.get('query')[0]
			
			while (len(query_list) > 0):
				rhs = query_list.pop(0)
				if not isinstance(rhs, algebra.Operator):
					rhs = algebra.ExpressionFactory.factory('join', 'placeholder', rhs)
				
				if isinstance(rhs, algebra.LeftJoin):
					lhs = lhs or Query()
				
				if lhs:
					if rhs.operands[0] == 'placeholder':
						rhs.operands[0] = lhs
					else:
						rhs = algebra.Join(lhs, rhs)
					
				lhs = rhs
				
				if lhs.operands[0] == 'placeholder':
					lhs = lhs.operands[1]
				
			if isinstance(lhs, algebra.Join) or isinstance(lhs, algebra.Union):
				if lhs.operands[0] == 'placeholder':
					lhs = lhs.operands[1]
			res = lhs
		elif data.get('query'):
			res = data.get('query')[0]

		if data.get('filter'):
			expr, query = self.flatten_filter(data.get('filter'))
			query = res or Query()
			res = algebra.Filter(expr, query)
			
		self.add_prod_datum('query', res)
				
		
	def handler__graphpatternnottriples_or_filter_dot_opt_triplesblock_opt_finish(self, data):
		lhs = data.get('_GraphPatternNotTriples_or_Filter')
		rhs = data.get('query')
		if lhs:
			self.add_prod_datum('query_list', lhs)
		if rhs:
			rhs = algebra.ExpressionFactory.factory('join', 'placeholder', rhs[0])
		if rhs:
			self.add_prod_data('query_list', rhs)
		self.add_prod_datum('filter', data.get('filter'))

	def handler__graphpatternnottriples_or_filter_finish(self, data):
		self.add_prod_datum('filter', data.get('filter'))
		if data.get('query'):
			res = data.get('query')[0]
			if not isinstance(res, algebra.Operator):
				res = algebra.ExpressionFactory.factory('join', 'placeholder', res)
			self.add_prod_data('_GraphPatternNotTriples_or_Filter', res)

	# [21]	  TriplesBlock ::= TriplesSameSubject ( '.' TriplesBlock? )?
	def handler_triplesblock_finish(self, data):
		query = Query()
		for p in data.get('pattern'):
			query.append(p)
			
		if data.get('query'):
			for q in data.get('query'):
				for p in q.patterns:
					query.append(p)

		self.add_prod_datum('query', query)

	# [23]	  OptionalGraphPattern		::=		  'OPTIONAL' GroupGraphPattern		
	def handler_optionalgraphpattern_finish(self, data):
		if data.get('query'):
			expr = None
			query = data.get('query')[0]
			if isinstance(query, algebra.Filter):
				expr, query = query.operands
				self.add_prod_data('query', algebra.ExpressionFactory.factory('leftjoin', 'placeholder', query, expr))
			else:
				self.add_prod_data('query', algebra.ExpressionFactory.factory('leftjoin', 'placeholder', query))

	# [24]	  GraphGraphPattern			::=		  'GRAPH' VarOrIRIref GroupGraphPattern
	def handler_graphgraphpattern_finish(self, data):
		if data.get('query'):
			context = data.get('VarOrIRIref')[-1]
			bgp = data.get('query')[0]
			if context:
				self.add_prod_data('query', ExpressionFactory.factory('graph', context, bgp))
			else:
				self.add_prod_data('query', bgp)

	# [25]	  GroupOrUnionGraphPattern	::=		  GroupGraphPattern ( 'UNION' GroupGraphPattern )*
	def handler_grouporuniongraphpattern_finish(self, data):
		res = data['query'][0]
		if data.get('union'):
			while len(data.get('union')) > 0:
				lhs = res
				rhs = data.get('union').pop(0)
				res = algebra.ExpressionFactory.factory('union', lhs, rhs)
						
		self.add_prod_datum('query', res)		
			
	def handler__union_groupgraphpattern_star_finish(self, data):
		if data.get('query'):
			self.add_prod_data('union', data.get('query')[0])

		if data.get('union'):
			self.add_prod_data('union', data.get('union')[0])

	# [26]	  Filter					::=		  'FILTER' Constraint
	def handler_filter_finish(self, data):
		self.add_prod_datum('filter', data.get('Constraint'))

	# [27]	  Constraint				::=		  BrackettedExpression | BuiltInCall | FunctionCall
	def handler_constraint_finish(self, data):
		if data.get('Expression'):
			res = data.get('Expression')[0]
			self.add_prod_data('Constraint', data.get('Expression')[0])
		elif data.get('BuiltInCall'):
			self.add_prod_datum('Constraint', data.get('BuiltInCall'))
		elif data.get('Function'):
			self.add_prod_datum('Constraint', data.get('Function'))
			
	# [28]	  FunctionCall				::=		  IRIref ArgList
	def handler_functioncall_finish(self, data):
		self.add_prod_data('Function', data.get('IRIref') + data.get('ArgList'))

	# [29]	  ArgList					::=		  ( NIL | '(' Expression ( ',' Expression )* ')' )
	def handler_arglist_finish(self, data):
		for v in data.values():
			self.add_prod_datum('ArgList', v)	 

	# [30]	  ConstructTemplate ::=		  '{' ConstructTriples? '}'		
	def handler_constructtemplate_start(self):
		self.nd_var_gen = False

	# [30]	  ConstructTemplate ::=		  '{' ConstructTriples? '}'		
	def handler_constructtemplate_finish(self, data):
		self.nd_var_gen = "0"
		self.add_prod_datum('ConstructTemplate', data.get('pattern'))
		self.add_prod_datum('ConstructTemplate', data.get('ConstructTemplate'))
		
	# [32]	  TriplesSameSubject ::= VarOrTerm PropertyListNotEmpty | TriplesNode PropertyList		
	def handler_triplessamesubject_finish(self, data):
		self.add_prod_datum('pattern', data.get('pattern'))
				
	# [33]	  PropertyListNotEmpty ::= Verb ObjectList ( ';' ( Verb ObjectList )? )*				
	def handler_propertylistnotempty_start(self, data):
		subject = self.prod_data[-1].get('VarOrTerm') or self.prod_data[-1].get('TriplesNode') or self.prod_data[-1].get('GraphNode')
		if self.validate and not subject:
			self.error(None, "Expected VarOrTerm or TriplesNode or GraphNode", { 'production' : 'PropertyListNotEmpty'} )
		data['Subject'] = subject

	def handler_propertylistnotempty_finish(self, data):
		self.add_prod_datum('pattern', data.get('pattern'))
		
	# [35]	  ObjectList ::= Object ( ',' Object )*		
	def handler_objectlist_start(self, data):
		data['Subject'] = self.prod_data[-1].get('Subject')
		data['Verb'] = self.prod_data[-1].get('Verb')[-1]

	def handler_objectlist_finish(self, data):
		self.add_prod_datum('pattern', data.get('pattern'))
		
	# [36]	  Object ::= GraphNode
	def handler_object_finish(self, data):
		obj = data.get('VarOrTerm') or data.get('TriplesNode') or data.get('GraphNode')
		if obj:
			self.add_pattern('Object', {'subject' : self.prod_data[-1].get('Subject'), 'predicate' : self.prod_data[-1].get('Verb'), 'object' : obj })
			self.add_prod_datum('pattern', data.get('pattern'))

	# [37]	  Verb ::=		 VarOrIRIref | 'a'
	def handler_verb_finish(self, data):
		for v in data.values():
			self.add_prod_datum('Verb', v)
			
	# [38]	  TriplesNode ::= Collection | BlankNodePropertyList
	def handler_triplesnode_start(self, data):
		data['TriplesNode'] = self.gen_node()

	def handler_triplesnode_finish(self, data):
		self.add_prod_datum('pattern', data.get('pattern'))
		self.add_prod_datum('TriplesNode', data.get('TriplesNode'))
		
	# [40]	  Collection ::= '(' GraphNode+ ')'		
	def handler_collection_start(self, data):
		data['Collection'] = self.prod_data[-1].get('TriplesNode')
	
	def handler_collection_finish(self, data):
		self.add_prod_datum('pattern', data.get('pattern'))
		
		first = col = data.get('Collection')
		li = flatten(data.get('GraphNode'))
		li = filter(lambda x: x != None, li)
		last = li.pop()
		for r in li:
			self.add_pattern('Collection', { 'subject' : first, 'predicate' : URI.intern("http://www.w3.org/1999/02/22-rdf-syntax-ns#first"), 'object' : r })
			rest = self.gen_node()
			self.add_pattern('Collection', { 'subject' : first, 'predicate' : URI.intern("http://www.w3.org/1999/02/22-rdf-syntax-ns#rest"), 'object' : rest})
			first = rest
			
		if last:
			self.add_pattern('Collection', { 'subject' : first, 'predicate' : URI.intern("http://www.w3.org/1999/02/22-rdf-syntax-ns#first"), 'object' : last})
		
			self.add_pattern('Collection', { 'subject' : first, 'predicate' : URI.intern("http://www.w3.org/1999/02/22-rdf-syntax-ns#rest"), 'object' : URI.intern("http://www.w3.org/1999/02/22-rdf-syntax-ns#nil")})

	# [41]	  GraphNode ::= VarOrTerm | TriplesNode 
	def handler_graphnode_finish(self, data):
		term = data.get('VarOrTerm') or data.get('TriplesNode')
		self.add_prod_datum('pattern', data.get('pattern'))
		self.add_prod_datum('GraphNode', term)	
		
	# [42]	  VarOrTerm ::= Var | GraphTerm		
	def handler_varorterm_finish(self, data):
		for v in data.values():
			self.add_prod_datum('VarOrTerm', v)		
		
	# [45]	  GraphTerm ::= IRIref | RDFLiteral | NumericLiteral | BooleanLiteral | BlankNode | NIL		
	def handler_graphterm_finish(self, data):
		self.add_prod_datum('GraphTerm', data.get('IRIref') or data.get('literal') or data.get('BlankNode') or data.get('NIL')) 
		
	# [46] Expression ::=		ConditionalOrExpression
	def handler_expression_finish(self, data):
		self.add_prod_datum('Expression', data.get('Expression'))
		
	# [47]	  ConditionalOrExpression	::=		  ConditionalAndExpression ( '||' ConditionalAndExpression )*		
	def handler_conditionalorexpression_finish(self, data):
		self.add_operator_expressions('OR', data)
		
	def handler__or_conditionalandexpression_finish(self, data):
		self.accumulate_operator_expressions('ConditionalOrExpression', 'OR', data)

	# [48]	  ConditionalAndExpression	::=		  ValueLogical ( '&&' ValueLogical )*		
	def handler_conditionalandexpression_finish(self, data):
		self.add_operator_expressions('AND', data)
		
	def handler__and_valuelogical_star_finish(self, data):
		self.accumulate_operator_expressions('ConditionalAndExpression', '_AND', data)
		
   # [50] RelationalExpression ::= NumericExpression (	
	def handler_relationalexpression_finish(self, data):
		if data.get('_Compare_Numeric'):
			data['_Compare_Numeric'] = data.get('_Compare_Numeric')[:1] + data.get('Expression') + data.get('_Compare_Numeric')[1:]
			self.add_prod_datum('Expression', algebra.ExpressionFactory.factory(data.get('_Compare_Numeric')))
		else:
			self.add_prod_datum('Expression', data.get('Expression'))
			
	def handler__compare_numericexpression_opt_finish(self, data):			
		if data.get('RelationalExpression'):
			self.add_prod_datum('_Compare_Numeric', data.get('RelationalExpression') + data.get('Expression'))

	# [52]	  AdditiveExpression ::= MultiplicativeExpression ( '+' MultiplicativeExpression | '-' MultiplicativeExpression )*			
	def handler_additiveexpression_finish(self, data):
		self.add_operator_expressions('_AddSub', data)
		
	def handler__add_sub_multiplicativeexpression_star_finish(self, data):
		self.accumulate_operator_expressions('AdditiveExpression', '_Add_Sub', data)

	# [53]	  MultiplicativeExpression	::=		  UnaryExpression ( '*' UnaryExpression | '/' UnaryExpression )*
	def handler_multiplicativeexpression_finish(self, data):
		self.add_operator_expressions('_Mul_Div', data)
		
	def handler__mul_div_unaryexpression_star_finish(self, data):
		self.accumulate_operator_expressions('MultiplicativeExpression', '_Mul_Div', data)
		
	# [54] UnaryExpression ::=	'!' PrimaryExpression | '+' PrimaryExpression | '-' PrimaryExpression | PrimaryExpression
	def handler_unaryexpression_finish(self, data):
		if data.get('UnaryExpression') == "!":
			self.add_prod_datum('Expression', algebra.ExpressionFactory.factory("not", data.get('Expression')[0]))
		elif data.get('UnaryExpression') == "-":
			e = data.get('Expression')[0]
			if isinstance(e, literal.Numeric):
				self.add_prod_datum('Expression', -e)
			else:
				self.add_prod_datum('Expression', algebra.ExpressionFactory.factory('minus', e))
		else:
			self.add_prod_datum('Expression', data.get('Expression'))
			
		if data.get('UnaryExpression') in ["'","!","+","-"]:
			self.add_prod_data('Expression', data.get('UnaryExpression') + data.get('Expression'))
		else:
			self.add_prod_data('Expression', data.get('Expression'))

	# [55] PrimaryExpression ::= BrackettedExpression | BuiltInCall | IRIrefOrFunction | RDFLiteral | NumericLiteral | BooleanLiteral | Var
	def handler_primaryexpression_finish(self, data):
		if data.get('Expression'):
			self.add_prod_datum('Expression', data.get('Expression'))
		elif data.get('BuiltInCall'):
			self.add_prod_datum('Expression', data.get('BuilInCall'))		
		elif data.get('IRIref'):
			self.add_prod_datum('Expression', data.get('IRIref'))		
		elif data.get('Function'):
			self.add_prod_datum('Expression', data.get('Function'))		
		elif data.get('literal'):
			self.add_prod_datum('Expression', data.get('literal'))		
		elif data.get('Var'):
			self.add_prod_datum('Expression', data.get('Var'))
			
		self.add_prod_datum('UnaryExpression', data.get('UnaryExpression')) 
			
	# [57] BuiltInCall ::= 'STR' '(' Expression ')'
		#					 | 'LANG' '(' Expression ')'
		#					 | 'LANGMATCHES' '(' Expression ',' Expression ')'
		#					 | 'DATATYPE' '(' Expression ')'
		#					 | 'BOUND' '(' Var ')'
		#					 | 'sameTerm' '(' Expression ',' Expression ')'
		#					 | 'isIRI' '(' Expression ')'
		#					 | 'isURI' '(' Expression ')'
		#					 | 'isBLANK' '(' Expression ')'
		#					 | 'isLITERAL' '(' Expression ')'
		#					 | RegexExpression				

	def handler_builtincall_finish(self, data):
		if data.get('regex'):
			data.get('regex').insert(0, 'regex')
			self.add_prod_datum('BuiltInCall', algebra.ExpressionFactory.new(*data.get('regex')))
		elif data.get('BOUND'):
			data.get('Var').insert(0, 'bound')
			self.add_prod_datum('BuiltInCall', algebra.ExpressionFactory.new(*data.get('Var')))
		elif data.get('BuiltinCall'):
			self.add_prod_data('BuiltInCall', algebra.ExpressionFactory.new(*(data.get('BuiltInCall') + data.get('Expression')))) 
			
	# [58]	  RegexExpression			::=		  'REGEX' '(' Expression ',' Expression ( ',' Expression )? ')'
	def handler_regexexpression_finish(self, data):				
		self.add_prod_datum('regex', data.get('Expression'))
		
	# [59]	  IRIrefOrFunction			::=		  IRIref ArgList?		
	def handler_irireforfunction_finish(self, data):
		if data.get('ArgList'):
			self.add_prod_data('Function', data.get('IRIref') + data['ArgList'])
		else:
			self.add_prod_data('IRIref', data.get('IRIref'))

	# [60]	  RDFLiteral ::= String ( LANGTAG | ( '^^' IRIref ) )?
	def handler_rdfliteral_finish(self, data):
		if data.get('string'):
			lit = data.copy()
			str = lit.pop('string')[0]
			
			if lit.get('IRIref'):
				lit['datatype'] = lit.pop('IRIref')[-1]
				
			if lit.get('language'):
				lit['language'] = lit.pop('language')[-1]
				
			if str:
				self.add_prod_datum('literal', Literal(str, lit))	

	# [63]	  NumericLiteralPositive	::=		  INTEGER_POSITIVE | DECIMAL_POSITIVE | DOUBLE_POSITIVE 
	def handler_numericliteralpositive_finish(self, data):
		self.add_prod_datum('literal', flatten(data.values())[-1])
		self.add_prod_datum('UnaryExpression', data.get('UnaryExpression'))

	# [64]	  NumericLiteralNegative ::= INTEGER_NEGATIVE | DECIMAL_NEGATIVE | DOUBLE_NEGATIVE
	def handler_numericliteralnegative_finish(self, data):
		self.add_prod_datum('literal', abs(float(flatten(data.values())[-1])))
		
	# [67]	  IRIref ::= IRI_REF | PrefixedName
	def handler_iriref_finish(self, data):
		self.add_prod_datum('IRIref', data.get('iri'))
		
	# [68]	  PrefixedName ::= PNAME_LN | PNAME_NS
	def handler_prefixedname_finish(self, data):
		self.add_prod_datum('iri', data.get('PrefixedName'))

	def merge_modifiers(self, data):
		if data.get('query'):
			query = data.get('query')[0]
		else:
			query = Query()

		if data.get('order'):
			query = algebra.ExpressionFactory.factory('order', data.get('order')[0], query)
		
		if data.get('Var'):
			query = algebra.ExpressionFactory.factory('project', data.get('Var'), query)
			
		if data.get('DISTINCT_REDUCED'):
			query = algebra.ExpressionFactory.factory(data.get('DISTINCT_REDUCED')[0], query)			
			
		if data.get('slice'):
			query = algebra.ExpressionFactory.factory('slice', data.get('slice')[0], data.get('slice')[1], query)
			
		if data.get('dataset'):
			query = algebra.ExpressionFactory.factory('dataset', data.get('dataset'), query)
			
		return query

	def contexts(self, production):
		if not production:
			return None
		context = {}
		if hasattr(self, "handler_%s_start" % production.lower()):
			context['start'] = getattr(self, "handler_%s_start" % production.lower())

		if hasattr(self, "handler_%s_finish" % production.lower()):
			context['finish'] = getattr(self, "handler_%s_finish" % production.lower())
		
		return context if len(context) else None

	def add_operator_expressions(self, production, data):		
		res = data.get('Expression')
		if data.get(production):
			while len(data.get(production)) > 0:
				res = [data.production.pop(0) + res + data[production].pop(0)]
		self.add_prod_datum('Expression', res)
		
	def accumulate_operator_expressions(self, operator, production, data):
		if data.get('operator'):
			self.add_prod_datum(production, [data.get(operator), data.get('Expression')])
			self.add_prod_datum(production, data.get(production))
		else:
			self.add_prod_datum('Expression', data.get('Expression'))
		
	def add_pattern(self, production, options): 
		self.progress(production, 'add_pattern: %s' % options)
		self.progress(production, '[\'pattern\',  %s, %s, %s' % (options.get('subject'), options.get('predicate'), options.get('object')))
		triple = {}
		for r,v in options.items():
			if isinstance(v,list) and len(flatten(v)) == 1:
				v = flatten(v)[0]
			if self.validate and not isinstance(v, Term):
				self.error("add_pattern", "Expected %s to be a resource, but it was %s" % (r, v), {'production' : production})
			triple[r] = v	
		self.add_prod_datum('pattern', Pattern(triple)) 

	def on_start(self, prod):
		context = self.contexts(prod)
		self.productions.append(prod)
		if context:
			self.progress("%s(:start):%d" % (prod, len(self.prod_data[-1])), self.prod_data[-1])
			data = {}
			if context.get('start'):
				context['start'](data)
			self.prod_data.append(data)
		else:
			self.progress("%s(:start)" % prod, "")

	def on_finish(self):
		prod = self.productions.pop()
		context = self.contexts(prod)
		if context:
			data = self.prod_data.pop()						
			if context.get('finish'):
				context['finish'](data)
			self.progress("%s(:finish):%d" % (prod, len(self.prod_data[-1])), self.prod_data[-1], {'depth' : len(self.productions) +1 })
		else:
			self.progress("%s(:finish)" % prod, "", {'depth' : len(self.productions) +1 })

	def on_token(self, production, token):
		if len(self.productions) > 0:
			parent_prod = self.productions[-1]
			if parent_prod == '_Add_Sub_MultiplicativeExpression_Star':
				if production in ['+','-']:
					self.add_prod_datum('AdditiveExpression', production)
			elif parent_prod == 'UnaryExpression':
				if production in ['!','+','-']:
					self.add_prod_datum('UnaryExpression', production)
			elif parent_prod in ['NumericLiteralPositive','NumericLiteralNegative','NumericLiteral']:
				if production in ['+','-']:
					self.add_prod_datum('NumericLiteral', production)
			else:
				if production == 'a':
					self.add_prod_datum('Verb', URI.intern("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"))
				elif production == 'ANON':
					self.add_prod_datum('BlankNode', self.gen_node())
				elif production in ['ASC','DESC']:
					self.add_prod_datum('OrderDirection', token.lower())
				elif production == 'BLANK_NODE_LABEL':
					self.add_prod_datum('BlankNode', self.gen_node(token))
				elif production == 'BoooleanLiteral':
					self.add_prod_datum('literal', Literal(token, {'datatype' : vocab.XSD.get_prop('boolean')}))
				elif production == 'BOUND':
					self.add_prod_datum('BOUND', 'bound')
				elif production == 'DATATYPE':
					self.add_prod_datum('BuiltInCall', 'datatype')
				elif production == 'DECIMAL':
					self.add_prod_datum('literal', Literal(token, {'datatype' : vocab.XSD.get_prop('decimal')}))
				elif production in ['DISTINCT', 'REDUCED']:
					self.add_prod_datum('DISTINCT_REDUCED', token.lower()) 
				elif production == 'DOUBLE':
					self.add_prod_datum('literal', Literal(token, {'datatype' : vocab.XSD.get_prop('double')}))
				elif production == 'INTEGER':
					self.add_prod_datum('literal', Literal(token, {'datatype' : vocab.XSD.get_prop('integer')}))
				elif production == 'IRI_REF':
					self.add_prod_datum('iri', self.uri(token)) 
				elif production == 'ISBLANK':
					self.add_prod_datum('BuiltInCall', 'isBLANK') 
				elif production == 'ISLITERAL':
					self.add_prod_datum('BuiltInCall', 'isLITERAL') 
				elif production == 'ISIRI':
					self.add_prod_datum('BuiltInCall', 'isIRI')
				elif production == 'ISURI':
					self.add_prod_datum('BuiltInCall', 'isURI')
				elif production == 'LANG':
					self.add_prod_datum('BuiltInCall', 'lang')
				elif production == 'LANGMATCHES':
					self.add_prod_datum('BuiltInCall', 'langMatches')
				elif production == 'LANGTAG':
					self.add_prod_datum('language', token) 
				elif production == 'NIL':
					self.add_prod_datum('NIL', RDF["nil"]) 
				elif production == 'PNAME_LN':
					self.add_prod_datum('PrefixedName', self.ns(*token)) 
				elif production == 'PNAME_NS':
					self.add_prod_datum('PrefixedName', self.ns(token, None))
					self.prod_data[-1]['prefix'] = token
				elif production == 'STR':
					self.add_prod_datum('BuiltInCall', 'str') 
				elif production == 'SAMETERM':
					self.add_prod_datum('BuiltInCall', 'sameTerm') 
				elif production in ['STRING_LITERAL1', 'STRING_LITERAL2', 'STRING_LITERAL_LONG1', 'STRING_LITERAL_LONG2']:
					self.add_prod_datum('string', token) 
				elif production in ['VAR1', 'VAR2']:
					self.add_prod_datum('Var', Variable(token)) 
				elif production in ['*', '/']:
					self.add_prod_datum('MultiplicativeExpression', production) 
				elif production in ['=', '!=', '<', '>', '<=', '>=']:
					self.add_prod_datum('RelationalExpression', production) 
				elif production == '&&':
					self.add_prod_datum('ConditionalAndExpression', production) 
				elif production == '||':
					self.add_prod_datum('ConditionalOrExpression', production) 
			self.progress("%s<%s(:token)" % (production, parent_prod), "%s: %s" % (token, self.prod_data[-1]), {'depth' : (len(self.productions) + 1)})
		else:
			self.error("%s(:token)" % parent_prod, "Token has no parent production", { 'production' : production})

	def uri(self, value, append = None):
		uri = self.options.get('base_uri')
		if uri:
			uri += value
		else:
			uri = URI(value)
		if append:
			uri += append
		return uri

	def prefix(self, name, uri = None):
		if len(name) == 0:
			name = None
 		name = str(name)
		if uri:
			self.options['prefixes'][name] = uri
		return self.options['prefixes'].get(name)

	def ns(self, prefix, suffix):
		base = self.prefix(prefix)
		if base == None:
			base = ""
		else:
			base = str(base)
			
		if "#" in base:
			suffix = re.sub("^\#","", suffix)
		
		self.debug("ns(%s)"%repr(prefix), "base: '%s' , suffix: '%s'" %(base, suffix))
		if suffix == None:
			suffix = ""
			
		uri = self.uri(base + suffix)
		if not self.options.get('resolve_uris'):
			uri._qname = "%s:%s" % (prefix,suffix)
		return uri
		
		
		
		
		
		
		
		
		
			
		
		
		
