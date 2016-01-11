class XContentTypeOptionsAnalyzer:
	def __init__(self):
		pass

	def analyze(self, parse_results, headers, content):
		results = parse_results["X-Content-Type-Options"]
		parts = []

		if results["status"] == "X_CONTENT_TYPE_OPTIONS_NONE":
			parts.append({
				"type" : "warning",
				"message" : "X-Content-Type is not specified. Browser can attempt to infer the response type based of the content, the URL or how it was requested. This may lead to indesirable behavior which can have a security impact."
			})

		return "X-Content-Type-Options Header", parts