class StrictTransportSecurityParser:
	def __init__(self):
		pass

	def parse(self, headers, content):
		analysis = { 
			"status" : "", 
			"warning" : [], 
			"info" : [],
			"max-age" : 0,
			"preload" : False,
			"includeSubDomains" : False
		}

		found = False

		for header in headers:
			if header[0].lower() == "Strict-Transport-Security".lower():
				components = header[1].strip().split(";")
				max_age = None
				includeSubDomains = False
				preload = False

				for component in components:
					if not "=" in component:
						component += "="

					key, value = component.strip().split("=")

					if key == "max-age":
						max_age = int(value)

					if key == "includeSubDomains":
						includeSubDomains = True

					if key == "preload":
						preload = True

				# Max age == 0, means that HSTS is explicitely disabled
				if not max_age == 0:
					analysis["status"] = "STRICT_TRANSPORT_SECURITY_DEFINED"
					analysis["preload"] = preload
					analysis["max-age"] = max_age
					analysis["includeSubDomains"] = includeSubDomains
					found = True

				# First header found is the one analyzed by the browser
				break


		if not found:
			analysis["status"] = "STRICT_TRANSPORT_SECURITY_NONE"

		return "Strict-Transport-Security", analysis
		

