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