class XXSSProtectionParser:
	def __init__(self):
		pass

	def parse(self, headers, content):
		analysis = { 
			"status" : "", 
			"warning" : [], 
			"info" : [],
			"actived" : None,
			"mode" : None
		}

		found = False

		for header in headers:
			if header[0].lower() == "X-XSS-Protection".lower():
				parts = header[1].split(";")
				activated = parts[0].strip()
				mode = parts[1].split("=")[1].strip() if len(parts) > 1 else None

				if activated in ["0", "1"]:
					analysis["actived"] = activated == "1"
					analysis["mode"] = mode

					if mode == "block" and activated == "0":
						analysis["warning"].append("Mode 'block' for the 'X-XSS-Protection' doesn't have any effect when the value is '0'.")

					status = "X_XSS_PROTECTION"
					
					if analysis["actived"]:
						status += "_ENABLED"
					else:
						status += "_DISABLED"

					if mode == "block":
						status += "_MODE_BLOCK"

					analysis["status"] = status
					found = True

				# First header found is the one analyzed by the browser
				break

		if not found:
			analysis["status"] = "X_XSS_PROTECTION_NONE"

		return "X-XSS-Protection", analysis