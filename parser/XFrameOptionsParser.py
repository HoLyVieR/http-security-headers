from bs4 import BeautifulSoup

class XFrameOptionsParser:
	def __init__(self):
		pass

	def parse(self, headers, content):
		results = []

		for header in headers:
			if header[0].lower() == "X-Frame-Options".lower():
				results.append(header[1])

		analysis = { 
			"status" : "", 
			"warning" : [], 
			"info" : [],
			"allow-from" : None
		}

		if len(results) == 0:
			analysis["status"] = "X_FRAME_OPTIONS_NONE"

		if len(results) > 1:
			if results.count(results[0]) == len(results):
				results = results[0]
			else:
				analysis["warning"].append("Conflicting value found in multiple X-Frame-Options header. This can have variable effect on browsers. Assuming no header are specified.")
				analysis["status"] = "X_FRAME_OPTIONS_NONE"
			
		if len(results) == 1:
			value = results[0].strip()

			if value == "SAMEORIGIN":
				analysis["status"] = "X_FRAME_OPTIONS_SAMEORIGIN"

			elif value == "DENY":
				analysis["status"] = "X_FRAME_OPTIONS_DENY"

			elif value.startswith("ALLOW-FROM "):
				analysis["status"] = "X_FRAME_OPTIONS_ALLOW_FROM"
				analysis["allow-from"]= value[11:]

		html_page = BeautifulSoup(content, 'html.parser')
		meta_tags = html_page.find_all('meta')

		for meta in meta_tags:
			if "http-equiv" in meta and meta["http-equiv"] == "X-Frame-Options":
				analysis["warning"].append("You should not set X-Frame-Options through meta tags. See : https://www.owasp.org/index.php/Clickjacking_Defense_Cheat_Sheet#Common_Defense_Mistakes")

		return "X-Frame-Options", analysis
