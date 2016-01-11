DEFAULT_SRC_FILLER = ["child-src", "connect-src", "font-src", "img-src", "media-src", "object-src", "script-src", "style-src"]

class ContentSecurityPolicyParser:
	def __init__(self):
		pass

	def parse(self, headers, content):
		analysis = { 
			"status" : "", 
			"warning" : [], 
			"info" : [],
			"policy" : { 
				"img-src" : None, 
				"script-src" : None,
				"child-src" : None,
				"frame-src" : None,
				"connect-src" : None,
				"font-src" : None,
				"media-src" : None,
				"object-src" : None,
				"style-src" : None,
				"manifest-src" : None,
				"base-uri" : None,
				"plugin-types" : None,
				"referrer" : None,
				"reflected-xss" : None,
				"report-uri" : None,
				"sandbox" : None,
				"upgrade-insecure-requests" : None
			}
		}

		found = False
		found_report = False

		for header in headers:
			if header[0].lower() == "Content-Security-Policy".lower() and not found:
				self._parse_policy(header[1], analysis["policy"], analysis["info"])
				analysis["status"] = "CONTENT_SECURITY_POLICY_DEFINED"

				# First header found is the one analyzed by the browser
				found = True

			if header[0].lower() == "Content-Security-Policy-Report-Only".lower() and not found_report:
				if not "report-uri" in header[1]:
					analysis["warning"].append("Content Security Policy is set to report only, but no 'report-uri' is defined.")

				self._parse_policy(header[1], analysis["policy"], analysis["info"])
				analysis["status"] = "CONTENT_SECURITY_POLICY_REPORT_ONLY"
				found_report = True

		if not found and not found_report:
			analysis["status"] = "CONTENT_SECURITY_POLICY_NONE"

		if analysis["policy"]["child-src"] is None and not analysis["policy"]["frame-src"] is None:
			analysis["warning"].append("'frame-src' has been deprecated and replaced with 'child-src' in CSP 2.0. For better browser support, you should also use 'child-src'.")

		return "Content-Security-Policy", analysis

	def _parse_policy(self, value, policy, info):
		components = value.split(";")

		for component in components:
			if component.strip() == "":
				continue
				
			parts = component.split(" ")
			directive_name = parts[0]
			attributes = parts[1:]

			if not directive_name in policy and not directive_name == "default-src":
				info.append("'%s' was ignored since it's either experimental or unsupported." % directive_name)
				continue

			if directive_name == "default-src":
				for directive in DEFAULT_SRC_FILLER:
					# default-src only overrides directive that aren't defined.
					if policy[directive] is None:
						policy[directive] = attributes
				
				continue

			# Single value directive only keep the first value
			if directive_name in ["sandbox", "base-uri", "report-uri", "reflected-xss", "referrer"]:
				attributes = attributes[0]

			policy[directive_name] = attributes

