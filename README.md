# HTTP Security Headers

Command line utilities that helps you analyze the security header of a website. It provides the following features :

 - Display the raw header
 - Display a parsed view for the security headers
   - Content-Security-Policy
   - Public-Key-Pins
   - Strict-Transport-Security
   - X-Content-Type-Options
   - X-Frame-Options
   - X-XSS-Protection
 - Analyze the value of the headers and display error, warning and notable information about those value.

# How to use

    python security-headers.py https://www.facebook.com --output_file facebook.html
    
    
# Help

    python security-headers.py -h
