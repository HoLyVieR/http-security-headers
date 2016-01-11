class XFrameOptionsAnalyzer:
	def __init__(self):
		pass

	def analyze(self, parse_results, headers, content):
		results = parse_results["X-Frame-Options"]
		parts = []

		if results["status"] == "X_FRAME_OPTIONS_NONE":
			parts.append({
				"type" : "warning",
				"message" : "X-Content-Type is not specified. This page is susceptible to clickjacking attack."
			})

		return "X-Frame-Options Header", parts