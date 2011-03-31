from yardflib import Query
from utils import flatten

class GroupQuery(list):
	
	def __init__(self, queries = [], operation = 'join', options = {}):
		self.queries = filter(lambda x: x!=None, flatten(queries))
		super(GroupQuery, self).__init__(queries)
		self.operation = operation
		
	def to_sxa(self):
		return [operation] + map(self, lambda x: x.to_sxa())

