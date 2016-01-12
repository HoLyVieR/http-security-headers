import base64

class PublicKeyPinsParser:
	def __init__(self):
		pass

	def parse(self, headers, content):
		analysis = { 
			"status" : "", 
			"warning" : [], 
			"info" : [],
			"max-age" : None,
			"includeSubDomains" : None,
			"pin-sha256" : None,
			"report-uri" : None
		}

		found = False

		for header in headers:
			if header[0].lower() == "Public-Key-Pins".lower():
				self._parse_public_key_pins(header[1], analysis)
				analysis["status"] = "PUBLIC_KEY_PINS_REPORT_DEFINED"
				found = True
				break

			if header[0].lower() == "Public-Key-Pins-Report-Only".lower():
				if not "report-uri" in header[1]:
					analysis["warning"].append("Public Key Pins is set to report only, but no 'report-uri' is defined.")

				self._parse_public_key_pins(header[1], analysis)
				analysis["status"] = "PUBLIC_KEY_PINS_REPORT_ONLY"
				found = True
				break

		if not found:
			analysis["status"] = "PUBLIC_KEY_PINS_NONE"

		return "Public-Key-Pins", analysis

	def _parse_public_key_pins(self, value, analysis):
		components = value.strip().split(";")
		max_age = None
		includeSubDomains = False
		pin_sha256 = None
		report_uri = None

		for component in components:
			if not "=" in component:
				component += "="

			key, value = component.strip().split("=", 1)

			if key == "max-age":
				max_age = int(value)

			if key == "includeSubDomains":
				includeSubDomains = True

			if key == "pin-sha256":
				if pin_sha256 is None:
					pin_sha256 = []

				if value[0] == "\"":
					value = value[1:-1]

				pin_sha256.append(base64.b64decode(value).encode("hex"))

			if key == "report-uri":
				report_uri = value

		
		analysis["max-age"] = max_age
		analysis["includeSubDomains"] = includeSubDomains
		analysis["pin-sha256"] = pin_sha256
		analysis["report-uri"] = report_uri

		# Remove quote
		if analysis["report-uri"][0] == "\"":
			analysis["report-uri"] = analysis["report-uri"][1:-1]