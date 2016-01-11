import re

from jinja2 import Template

TEMPLATE_HTML = """

<html>
<head>
	<title>{{ title }}</title>

	{% for file in javascript %}
		<script type="text/javascript" src="{{ file }}"></script>
	{% endfor %}

	{% for file in css %}
		<link type="text/css" href="{{ file }}" rel="stylesheet" />
	{% endfor %}
</head>
<body>
	<div class="container">
		<h1>{{ title }}</h1>

		<div class="panel-group" id="accordion" role="tablist" aria-multiselectable="true">
			<!-- RAW HEADERS -->
			<div class="panel panel-default">
				<div class="panel-heading" role="tab">
					<!-- TITLE -->
					<h4>
						<a role="button" data-toggle="collapse" aria-expanded="true" aria-controls="collapseRawHeader" href="#collapseRawHeader">Raw headers</a>
					</h4>
					<!-- /TITLE -->
				</div>
				<div id="collapseRawHeader" class="panel-collapse collapse in" role="tabpanel">
				<div class="panel-body">
					<!-- CONTENT -->
					<table class="table">
						{% for header in headers | sort(attribute=0) %}
						<tr>
							<td style="width: 250px" class="active"><b>{{ header[0] }}</b></td>
							<td>{{ header[1] }}</td>
						</tr>
						{% endfor %}
					</table>
					<!-- /CONTENT -->
				</div>
				</div>
			</div>

			<!-- PARSED HEADER -->
			<div class="panel panel-default">
				<div class="panel-heading" role="tab">
					<!-- TITLE -->
					<h4>
						<a role="button" data-toggle="collapse" aria-expanded="true" aria-controls="collapseParsedHeader" href="#collapseParsedHeader">Parsed headers</a>
					</h4>
					<!-- /TITLE -->
				</div>
				<div id="collapseParsedHeader" class="panel-collapse collapse in" role="tabpanel">
				<div class="panel-body">
					<!-- CONTENT -->
					<table class="table">
						{% for header in parsed | sort %}
						<tr>
							<td style="width: 250px"  class="active"><b>{{ header }}</b></td>
							<td>
								<ul>
									{% for item in parsed[header] | sort %}
										{% if not item in ["warning", "info", "policy"] and not parsed[header][item] == None %}
											<li><b>{{ item | capitalize }}</b> : {{ parsed[header][item] }}</li>
										{% endif %}

										{% if item == "policy" %}
											<li>
												<b>Policy</b> : <br />
												<ul>
													{% for policy_name in parsed[header]["policy"] | sort %}
														{% if  parsed[header]["policy"][policy_name] %}
														<li>
															<b>{{ filters["csp_name"](policy_name) }}</b><br />
															<ul>
																{% for policy_value in parsed[header]["policy"][policy_name] %}
																	<li>{{ filters["csp_value"](policy_value) }}</li>
																{% endfor %}
															</ul><br />
														</li>
														{% endif %}
													{% endfor %}
												</ul>
											</li>
										{% endif %}
									{% endfor %}
								</ul>
							</td>
						</tr>
						{% endfor %}
					</table>
					<!-- /CONTENT -->
				</div>
				</div>
			</div>

			<!-- ANALYSIS -->
			<div class="panel panel-default">
				<div class="panel-heading" role="tab">
					<!-- TITLE -->
					<h4>
						<a role="button" data-toggle="collapse" aria-expanded="true" aria-controls="collapseAnalysis" href="#collapseAnalysis">Analysis</a>
					</h4>
					<!-- /TITLE -->
				</div>
				<div id="collapseAnalysis" class="panel-collapse collapse in" role="tabpanel">
				<div class="panel-body">
					<!-- CONTENT -->
					{% for report_name in report %}
					<h3>{{ report_name }}</h3>

					<ul>
						{% for report_element in report[report_name] %}
							{%if report_element["type"] == "warning" %}
								<li><div class="alert alert-warning">{{ report_element["message"] }}</div></li>
							{% endif %}

							{%if report_element["type"] == "error" %}
								<li><div class="alert alert-danger">{{ report_element["message"] }}</div></li>
							{% endif %}

							{%if report_element["type"] == "info" %}
								<li><div class="alert alert-info">{{ report_element["message"] }}</div></li>
							{% endif %}
						{% endfor %}
					</ul><br />
					{% endfor %}
					<!-- /CONTENT -->
				</div>
				</div>
			</div>
		</div>
	</div>
</body>
</html>

"""

class HTMLOutput:
	def __init__(self):
		pass

	def output(self, url, headers, content, report, parsed_results):
		template = Template(TEMPLATE_HTML)
		result = template.render({
			"title"      : "HTML Report - " + url,
			"javascript" : [ "https://ajax.googleapis.com/ajax/libs/jquery/2.1.3/jquery.min.js", "https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js" ],
			"css"        : [ "https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css" ],
			"report"     : report,
			"parsed"     : parsed_results,
			"headers"    : headers,
			"filters"    : {  "csp_name" : self._csp_name, "csp_value" : self._csp_value } 
		})

		return result

	def _csp_name(self, value):
		# Source : https://developer.mozilla.org/en-US/docs/Web/Security/CSP/CSP_policy_directives
		human_text = { 
			"base-uri" : "URIs that a user agent may use as the document base URL are limited to",
			"child-src" : "Valid sources for web workers and nested browsing contexts loaded using elements such as &lt;frame&gt; and &lt;iframe&gt; are limited to",
			"connect-src" : "Valid sources for fetch, XMLHttpRequest, WebSocket, and EventSource connections are limited to",
			"font-src" : "Valid sources for fonts loaded using @font-face are limited to",
			"frame-src" : "Valid sources for web workers and nested browsing contexts loading using elements such as &lt;frame&gt; and &lt;iframe&gt; are limited to",
			"img-src" : "Valid sources of images and favicons are limited to",
			"manifest-src" : "Which manifest can be applied to the resource is limited to ",
			"media-src" : "Valid sources for loading media using the &lt;audio&gt; and &lt;video&gt; elements are limited to",
			"object-src" : "Valid sources for the &lt;object&gt;, &lt;embed&gt;, arend &lt;applet&gt; elements are limited to",
			"plugin-types" : "Valid plugins that the user agent may invoke are limited to",
			"referrer" : "Information in the referer (sic) header for links away from a page is limited to",
			"reflected-xss" : "Instruction to the user agent to activate or deactivate any heuristics used to filter or block reflected cross-site scripting attacks is set to",
			"report-uri" : "Content Security Policy violation will be reported to",
			"sandbox" : "Instruction to apply restrictions to a page's actions including preventing popups, preventing the execution of plugins and scripts, and enforcing a same-origin policy is set to",
			"script-src" : "Valid sources for JavaScript are limited to",
			"style-src" : "Valid sources for stylesheets are limited to",
			"upgrade-insecure-requests" : "Instruction to the user agents to treat all of a site's unsecure URL's (those serverd over HTTP) as though they have been replaced with secure URL's (those served over HTTPS) is set to"
		}
		return human_text[value]

	def _csp_value(self, value):
		magic_value = {
			"*" : "All domain",
			"'none'" : "No URLs will match",
			"'self'" : "Origin of the page",
			"'unsafe-inline'" : "Inline resources",
			"'unsafe-eval'" : "eval() and similar methods for creating code from strings",
			"data:" : "Data URIs",
			"mediastream:" : "Mediastream URIs",
			"blob:" : "Blob URIs",
			"filesystem:" : "Filesystem URIs"
		}

		if value in magic_value:
			return "<b>" + magic_value[value] + "</b>"

		prefix = ""
		suffix = ""
		suffix2 = ""

		protocol_match = re.search("^([a-z\\-]+)\\:\\/\\/", value)

		if protocol_match:
			suffix2 = "using the protcol '%s' " % protocol_match.group(1)
			value = value[len(protocol_match.group(0)):]

		if value[:2] == "*.":
			value = value[2:]
			prefix = "Subdomains of "

		if value[-2:] == ":*":
			value = value[:-2]
			suffix = " on any port "

		return prefix + "<b>" + value + "</b> " + suffix + suffix2
