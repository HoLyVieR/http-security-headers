class XContentTypeOptionsParser:
	def __init__(self):
		pass

	def parse(self, headers, content):
		analysis = { 
			"status" : "", 
			"warning" : [], 
			"info" : []
		}

		found = False

		for header in headers:
			if header[0].lower() == "X-Content-Type-Options".lower():
				if not header[1] == "nosniff":
					analysis["warning"].append("X-Content-Type-Options can only have the value 'nosniff'")
				else:
					found = True

		if found:
			analysis["status"] = "X_CONTENT_TYPE_OPTIONS_NOSNIFF"
		else:
			analysis["status"] = "X_CONTENT_TYPE_OPTIONS_NONE"

		return "X-Content-Type-Options", analysis
		

