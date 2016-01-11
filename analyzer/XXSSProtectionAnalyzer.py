class XXSSProtectionAnalyzer:
	def __init__(self):
		pass

	def analyze(self, parse_results, headers, content):
		results = parse_results["X-XSS-Protection"]
		parts = []

		if results["status"].startswith("X_XSS_PROTECTION_DISABLED"):
			parts.append({
				"type" : "error",
				"message" : "X-XSS-Protection is turned off. No browser will attempt to detect and block XSS attack for that page."
			})

		if results["status"] == "X_XSS_PROTECTION_NONE":
			parts.append({
				"type" : "warning",
				"message" : "X-XSS-Protection is turned on by default on most browser, but there are older browser for which you must explicitely set this value for it to be activated."
			})

		if results["status"] == "X_XSS_PROTECTION_ENABLED" or results["status"] == "X_XSS_PROTECTION_NONE":
			parts.append({
				"type" : "info",
				"message" : "X-XSS-Protection is configured to only filter out detected content. If content is reflected at multiple places in the page and the browser doesn't detect all of them, the XSS attack will still be succesful."
			})

		return "X-XSS-Protection Header", parts