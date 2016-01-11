class StrictTransportSecurityAnalyzer:
	def __init__(self):
		pass

	def analyze(self, parse_results, headers, content):
		results = parse_results["Strict-Transport-Security"]
		parts = []

		max_age = results["max-age"]
		includeSubdomains = results["includeSubDomains"]
		preload = results["preload"]

		if results["status"] == "STRICT_TRANSPORT_SECURITY_NONE":
			parts.append({
				"type" : "warning",
				"message" : "Strict-Transport-Security is not specified. Your website is more susceptible to downgrade attack."
			})

		if results["status"] == "STRICT_TRANSPORT_SECURITY_DEFINED":
			if not includeSubdomains:
				parts.append({
					"type" : "info",
					"message" : "Strict-Transport-Security is only defined for the current domain. Subdomains aren't protected."
				})

			if not preload:
				parts.append({
					"type" : "info",
					"message" : "Strict-Transport-Security is not defined to be on the preload list of browsers. Your website is susceptible to downgrade attack the first time a user visit it."
				})

		return "Strict-Transport-Security Header", parts