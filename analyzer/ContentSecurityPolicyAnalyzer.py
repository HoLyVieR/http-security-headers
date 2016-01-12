class ContentSecurityPolicyAnalyzer:
	def __init__(self):
		pass

	def analyze(self, parse_results, headers, content):
		results = parse_results["Content-Security-Policy"]
		parts = []

		if results["status"] == "CONTENT_SECURITY_POLICY_NONE":
			parts.append({
				"type" : "warning",
				"message" : "Content-Security-Policy is not specified. This header helps reducing the attack surface of any XSS attack."
			})

		if results["status"] == "CONTENT_SECURITY_POLICY_REPORT_ONLY":
			parts.append({
				"type" : "info",
				"message" : "Content-Security-Policy is activated in 'Report-Only' mode. Content-Security-Policy violation won't be blocked, but will be reported to the report uri."
			})

		if not results["status"] == "CONTENT_SECURITY_POLICY_NONE":
			self._validate_unsafe_configuration(parse_results, headers, content, parts)
			self._validate_csp_violation(parse_results, headers, content, parts)

		return "Content-Security-Policy Header", parts

	def _validate_csp_violation(self, parse_results, headers, content, parts):
		# TODO : Detect if content in the page violates the CSP value
		pass

	def _validate_unsafe_configuration(self, parse_results, headers, content, parts):
		policy = parse_results["Content-Security-Policy"]["policy"]

		unsafe_vectors = [
			# Generic
			{ 
				"script-src" : ["'unsafe-inline'"], 
				"type" : "warning",
				"message" : "The policy allows inline JavaScript. In most XSS scenario an attacker can inject inline JavaScript."
			},
			{ 
				"script-src" : ["data:"], 
				"type" : "warning",
				"message" : "Data URI is an insecure source of data. Data URI can be forged to return any content."
			},
			{ 
				"script-src" : ["*"], 
				"type" : "warning",
				"message" : "Allowing script execution from any domain is unsafe."
			},
			{
				"style-src" : ["*"],
				"font-src" : ["*"],
				"type" : "info",
				"message" : "Allowing CSS and Font from any domain can lead to data leakage. See http://mksben.l0.cm/2015/10/css-based-attack-abusing-unicode-range.html"
			},
			{
				"style-src" : ["data:"],
				"font-src" : ["*"],
				"type" : "info",
				"message" : "Allowing CSS from Data URI and Font from any domain can lead to data leakage. See http://mksben.l0.cm/2015/10/css-based-attack-abusing-unicode-range.html"
			},

			# Site specific
			{
				"script-src" : ["'unsafe-eval'", "https://*.googleapis.com/"],
				"type" : "warning",
				"message" : "Google API hosts a lot of framework like AngularJS that will eval attributes of HTML content. This is a known vector of Content-Security-Policy bypass."
			},
			{
				"script-src" : ["'unsafe-eval'", "https://ajax.googleapis.com/"],
				"type" : "warning",
				"message" : "Google API hosts a lot of framework like AngularJS that will eval attributes of HTML content. This is a known vector of Content-Security-Policy bypass."
			},
			{
				"script-src" : ["'unsafe-eval'", "http://*.googleapis.com/"],
				"type" : "warning",
				"message" : "Google API hosts a lot of framework like AngularJS that will eval attributes of HTML content. This is a known vector of Content-Security-Policy bypass."
			},
			{
				"script-src" : ["'unsafe-eval'", "http://ajax.googleapis.com/"],
				"type" : "warning",
				"message" : "Google API hosts a lot of framework like AngularJS that will eval attributes of HTML content. This is a known vector of Content-Security-Policy bypass."
			},

			# Public website
			{
				"script-src" : ["https://githubusercontent.com"],
				"type" : "warning",
				"message" : "'githubusercontent.com' is a website that anyone can host code on."
			},
			{
				"script-src" : ["https://*.githubusercontent.com"],
				"type" : "warning",
				"message" : "'githubusercontent.com' is a website that anyone can host code on."
			},
			{
				"script-src" : ["https://gist.githubusercontent.com"],
				"type" : "warning",
				"message" : "'githubusercontent.com' is a website that anyone can host code on."
			},
			{
				"script-src" : ["https://raw.githubusercontent.com"],
				"type" : "warning",
				"message" : "'githubusercontent.com' is a website that anyone can host code on."
			}
		]

		for vector in unsafe_vectors:
			valid = True

			for attribute_name in vector:
				if attribute_name == "message" or attribute_name == "type":
					continue

				for value in vector[attribute_name]:
					if not value in policy[attribute_name]:
						valid = False
						break

				if not valid:
					break

			if valid:
				parts.append(vector)

