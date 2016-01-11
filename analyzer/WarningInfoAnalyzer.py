class WarningInfoAnalyzer:
	def __init__(self):
		pass

	def analyze(self, parse_results, headers, content):
		parts = []

		for key in parse_results:
			for info in parse_results[key]["info"]:
				parts.append({
					"type" : "info",
					"message" : info
				})

			for info in parse_results[key]["warning"]:
				parts.append({
					"type" : "warning",
					"message" : info
				})

		return "Warning and Information", parts