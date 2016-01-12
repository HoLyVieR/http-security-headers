class PublicKeyPinsAnalyzer:
	def __init__(self):
		pass

	def analyze(self, parse_results, headers, content):
		results = parse_results["Public-Key-Pins"]
		parts = []

		if results["status"] == "PUBLIC_KEY_PINS_NONE":
			parts.append({
				"type" : "warning",
				"message" : "Public-Key-Pins is not specified. If an attacker can compromise a CA, he could generate certificate that will be accepted by your user."
			})

		if results["status"] == "PUBLIC_KEY_PINS_REPORT_ONLY":
			parts.append({
				"type" : "warning",
				"message" : "Public-Key-Pins is activated in 'Report-Only' mode. Certificate that are not specified in this header will be accepted, but you will receive notification of it."
			})

		if results["status"] == "PUBLIC_KEY_PINS_REPORT_DEFINED":
			# 15 days threadshold
			if results["max-age"] > 15 * 24 * 60 * 60:
				parts.append({
					"type" : "info",
					"message" : "Public-Key-Pins is activated, but it has a really long max-age value. Having long max-age value hinders revocation if one of the certification is compromised."
				})

			# 15 minutes threadshold
			if results["max-age"] < 15 * 60:
				parts.append({
					"type" : "warning",
					"message" : "Public-Key-Pins is activated, but it has a really short max-age value. Having short max-age value can nullify the effect of the header if the information is expired every time the user visits the website."
				})

		if not results["status"] == "PUBLIC_KEY_PINS_NONE":
			if results["report-uri"] is None:
				parts.append({
					"type" : "info",
					"message" : "No 'report-uri' is configured for the header Public-Key-Pins. You won't be notified of certificate rejected by browser."
				})


		return "Public-Key-Pins Header", parts