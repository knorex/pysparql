def flatten(input):
	output = []
	stack = []
	stack.extend(reversed(input))
	while stack:
		top = stack.pop()
		if isinstance(top, (list, tuple)):
			stack.extend(reversed(top))
		else:
			output.append(top)
	return output
	
def to_sse(obj):
	if hasattr(obj, 'to_sse'):
		return obj.to_sse()
	elif isinstance(obj, list):
		return [to_sse(o) for o in obj]
	else:
		return str(obj)