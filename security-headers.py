# Python dependencies
import argparse
import urlparse
import httplib

# Internal
import parser.XFrameOptionsParser
import parser.XContentTypeOptionsParser
import parser.StrictTransportSecurityParser
import parser.XXSSProtectionParser
import parser.ContentSecurityPolicyParser
import parser.PublicKeyPinsParser

import analyzer.WarningInfoAnalyzer
import analyzer.XXSSProtectionAnalyzer
import analyzer.XContentTypeOptionsAnalyzer
import analyzer.StrictTransportSecurityAnalyzer
import analyzer.XFrameOptionsAnalyzer
import analyzer.PublicKeyPinsAnalyzer
import analyzer.ContentSecurityPolicyAnalyzer

import output.HTMLOutput

USER_AGENT = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"

def get_connection(url):
	uri_parts = urlparse.urlparse(url)

	# For domain only prefix, we assume "https"
	if uri_parts.scheme == "":
		uri_parts = urlparse.urlparse("https://" + url)

	connection = None
	scheme = uri_parts.scheme.lower()

	if scheme == "http":
		connection = httplib.HTTPConnection(uri_parts.netloc)
	
	if scheme == "https":
		connection = httplib.HTTPSConnection(uri_parts.netloc)
	
	if connection is None:
		raise Exception("Unknown or supported URL scheme '%s'" % scheme)

	request_path = uri_parts.path

	if request_path == "":
		request_path = "/"

	if not uri_parts.query == "":
		request_path += "?"
		request_path += uri_parts.query

	return connection, request_path

def get_http_response(url):
	connection, request_path = get_connection(url)
	connection.request("GET", request_path, "", { "User-Agent" : USER_AGENT })
	response = connection.getresponse()
	headers = response.getheaders()
	content = response.read()

	return headers, content

def get_analysis(headers, content):
	# Parse the different headers
	list_parser = [
		parser.XFrameOptionsParser.XFrameOptionsParser(),
		parser.XContentTypeOptionsParser.XContentTypeOptionsParser(),
		parser.StrictTransportSecurityParser.StrictTransportSecurityParser(),
		parser.XXSSProtectionParser.XXSSProtectionParser(),
		parser.ContentSecurityPolicyParser.ContentSecurityPolicyParser(),
		parser.PublicKeyPinsParser.PublicKeyPinsParser()
	]

	parse_results = {}

	for parser_ in list_parser:
		key, result = parser_.parse(headers, content)
		parse_results[key] = result

	# Analyze the value obtained from the previous step
	list_analyzer = [
		analyzer.WarningInfoAnalyzer.WarningInfoAnalyzer(),
		analyzer.XXSSProtectionAnalyzer.XXSSProtectionAnalyzer(),
		analyzer.XContentTypeOptionsAnalyzer.XContentTypeOptionsAnalyzer(),
		analyzer.StrictTransportSecurityAnalyzer.StrictTransportSecurityAnalyzer(),
		analyzer.XFrameOptionsAnalyzer.XFrameOptionsAnalyzer(),
		analyzer.PublicKeyPinsAnalyzer.PublicKeyPinsAnalyzer(),
		analyzer.ContentSecurityPolicyAnalyzer.ContentSecurityPolicyAnalyzer()
	]

	report = {}

	for analyzer_ in list_analyzer:
		section_name, result = analyzer_.analyze(parse_results, headers, content)
		is_empty = result is None or len(result) == 0

		if not is_empty or args.include_empty_section:
			report[section_name] = result

	return report, parse_results

if __name__ == "__main__":
	arg_parser = argparse.ArgumentParser()
	arg_parser.add_argument("url", help="URL to test")
	arg_parser.add_argument("--output_type", help="The format for which you want the report to be. Possible value are : html.", default="html")
	arg_parser.add_argument("--output_file", help="File to output the report. When this option is not specified, stdout is used.")
	arg_parser.add_argument("--include_empty_section", help="If the empty section of the report should be included.", default=False, action='store_const', const=True)
	args = arg_parser.parse_args()

	if args.output_type and args.output_type.lower() == "html":
		output_inst = output.HTMLOutput.HTMLOutput()
	else:
		print("Unsupported output type '%s'." % args.output_type)
		exit()

	headers, content = get_http_response(args.url)
	report, parse_results = get_analysis(headers, content)
	output = output_inst.output(args.url, headers, content, report, parse_results)

	if args.output_file is None:
		print(output)
	else:
		open(args.output_file, "wb").write(output)