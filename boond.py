##############################
#        by MrBOOND          #
#     Telegram:@BO_NND       #
##############################
import sys
import os
import json
import re
import socket
import threading
import argparse
import shodan
import time
import secrets
from colorama import Fore, Style
from colorama import init as colorama_init
from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI
from bs4 import BeautifulSoup
from pysecuritytrails import SecurityTrails, SecurityTrailsError
from gevent import Timeout
from pyfiglet import Figlet
import requests
import random
from ye import *

parser = argparse.ArgumentParser(description='BOOND - A Content Delivery Network recon tool')

parser.add_argument('target_domain', metavar='domain', help='Domain to scan')

parser.add_argument('--write', action='store_true', help="Write results to a target.com-results.txt file")

args = parser.parse_args()

target_domain = args.target_domain
write = args.write

valid_subdomains = []
ip_addresses = []
not_cloudflare = []
akamai = []

class api_keys:
    securitytrails = None
    shodan = None

api_keys.shodan = "V948Q3dPtLDXFyZmCn8T36JCIU7VM6Y3"
api_keys.securitytrails = "96uUlRw1WURdi1DPXHQVybKxLr1rzwZE"

user_agent_strings = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9",
    "Mozilla/5.0 (iPad; CPU iPhone OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) GSA/6.0.51363 Mobile/11D257 Safari/9537.53",
    "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.152 Safari/537.36 LBBROWSER",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:37.0) Gecko/20100101 Firefox/37.0",
    "Mozilla/5.0 (Windows NT 6.2; ARM; Trident/7.0; Touch; rv:11.0; WPDesktop; Lumia 1520) like Gecko",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.65 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:42.0) Gecko/20100101 Firefox/42.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 7_0_6 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11B651 Safari/9537.53"
]

def dnsdumpster():
    try:
        response = requests.get("https://dnsdumpster.com", verify=True)
        status_code = response.status_code
    except requests.exceptions.ConnectionError:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.MAGENTA}dnsdumpster.com{Style.RESET_ALL} seems to be down, skipping . . .")

    if status_code != 200:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.MAGENTA}dnsdumpster.com{Style.RESET_ALL} isn't responding the way we want to, skipping . . .")
    else:
        print(f"{Fore.MAGENTA}[+]{Style.RESET_ALL} DNSDumpster output for {Fore.GREEN}{target_domain}{Style.RESET_ALL}")

        try:
            results = DNSDumpsterAPI().search(target_domain)['dns_records']['host']
            for result in results:
                result_domain = result['domain']
                try:
                    print(f"{Fore.CYAN}[☣]{Style.RESET_ALL} {Fore.GREEN}{result_domain}{Style.RESET_ALL} ")
                    if result_domain in valid_subdomains is not None:
                        pass
                    else:
                        valid_subdomains.append(result_domain)
                except Exception:
                    pass
        except Exception as e:
            print(f"{e}")

def certificate_search():
        crt_agent = random.choice(user_agent_strings)
        headers = {
            'User-Agent': crt_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Referer': 'https://crt.sh/',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'Sec-GPC': '1',
            'Cache-Control': 'max-age=0'
        }
        params = {
            'q': target_domain
        }
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((target_domain, 443))

        if result != 0:
            return f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.MAGENTA}{target_domain}{Style.RESET_ALL} doesn't seem to be using HTTPS, skipping certificate search"

        try:
            response = requests.get('https://crt.sh/', params=params, headers=headers)
            status_code = response.status_code
        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.MAGENTA}crt.sh{Style.RESET_ALL} isn't responding the way we want to, skipping . . .")

        if status_code != 200:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.MAGENTA}crt.sh{Style.RESET_ALL} isn't responding the way we want to, skipping . . .")
        else:
            print(f"{Fore.MAGENTA}[+]{Style.RESET_ALL} Getting subdomains from {Fore.MAGENTA}{target_domain}'s{Style.RESET_ALL} SSL certificate . . .")
            print(f"{Fore.MAGENTA}[+]{Style.RESET_ALL} This might take a while, hang tight")

            soup = BeautifulSoup(response.text, 'html.parser')
            tables = soup.find_all('table')

            for table in tables:
                for domain in table.find_all('td'):
                    for dm in domain:
                        if target_domain in dm and " " not in dm and dm not in valid_subdomains:
                            print((f"{Fore.CYAN}[ ☠ ]{Style.RESET_ALL}  {Fore.GREEN}{dm}{Style.RESET_ALL} "))
                            valid_subdomains.append(dm)

def securitytrails_get_subdomains():
    try:
        response = requests.get("https://api.securitytrails.com")
        status_code = response.status_code
    except requests.exceptions.ConnectionError:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.MAGENTA}securitytrails.com{Style.RESET_ALL} seems to be down, skipping . . . ")
    if status_code != 200:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.MAGENTA}securitytrails.com{Style.RESET_ALL} isn't responding the way we want to, skipping . . .")
    else:
        print(f"{Fore.MAGENTA}[+]{Style.RESET_ALL} SecurityTrails API subdomain scan output for: {Fore.GREEN}{target_domain}{Style.RESET_ALL}")
        st = SecurityTrails(api_keys.securitytrails)
        try:
            st.ping()
        except SecurityTrailsError:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Invalid API key")
            exit()
        subdomains_st = st.domain_subdomains(target_domain)
        for subdomain in subdomains_st['subdomains']:
            result_domain = f"{subdomain.strip()}.{target_domain}"
            print(f"{Fore.CYAN}[+]{Style.RESET_ALL} {Fore.GREEN}{result_domain}{Style.RESET_ALL}")
            if subdomain in valid_subdomains is not None:
                pass
            else:
                valid_subdomains.append(result_domain)


def sub_enum():
    print(f"{Fore.MAGENTA}[+]{Style.RESET_ALL} Checking common subdomains . . .")
    for subdomain in subdomains:
        url = f'http://{subdomain}.{target_domain}'  # Requests needs a valid HTTP(s) schema
        sub_enum_agent = {
            'User-Agent': random.choice(user_agent_strings)
        }
        try:
            requests.get(url, headers=sub_enum_agent, timeout=5)
        except requests.ConnectionError:
            pass
        except requests.exceptions.Timeout:
            pass
        except ConnectionRefusedError:
            pass
        else:
            final_url = url.replace("http://", "")  # (?) socket.gethostbyname doesn't like "http://"
            print(f"{Fore.CYAN}[+]{Style.RESET_ALL} {Fore.GREEN}{final_url}{Style.RESET_ALL} is a valid domain")
            if subdomain in valid_subdomains is not None:
                pass
            else:
                valid_subdomains.append(final_url)

def sub_ip():
    print(f"{Fore.MAGENTA}[+]{Style.RESET_ALL} Getting subdomain IP addresses . . .")
    for subdomain in valid_subdomains:
        try:
            subdomain_ip = socket.gethostbyname(subdomain)
        except socket.gaierror:
            print(f"{Fore.RED}[-]{Style.RESET_ALL}  {Fore.RED}{subdomain}{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}[+]{Style.RESET_ALL} {Fore.GREEN}{subdomain}{Style.RESET_ALL}  {Fore.GREEN}{subdomain_ip}{Style.RESET_ALL}")
            if subdomain_ip in ip_addresses is not None:
                pass
            else:
                ip_addresses.append(subdomain_ip)

def is_cf_ip():
    for ip in ip_addresses:
        print(f"{Fore.MAGENTA}[+]{Style.RESET_ALL}  {Fore.GREEN}{ip}{Style.RESET_ALL}  Cloudflar")
        agent = random.choice(user_agent_strings)
        is_cf_agent = {
            'User-Agent': agent
        }
        try:
            head = requests.head(f"http://{ip}", headers=is_cf_agent, timeout=5)
            headers = head.headers
            global ip_country
            ip_country = requests.get(f"http://ip-api.com/csv/{ip}?fields=country").text.strip()
            if 'CF-ray' in headers is not None:
                cloudflare = True
                print(f"{Fore.CYAN}[+]{Style.RESET_ALL} {Fore.CYAN}{ip}{Style.RESET_ALL} is Cloudflare")
                ray_id = head.headers['CF-ray']
                print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Ray-ID: {Fore.CYAN}{ray_id}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Country: {ip_country}")
            if 'CF-ray' not in headers:
                print(f"{Fore.GREEN}[-]{Style.RESET_ALL} {Fore.RED}{ip}{Style.RESET_ALL} is NOT Cloudflare")
                if ip in not_cloudflare is not None:
                    pass
                else:
                    not_cloudflare.append(ip)
        except ConnectionError:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Couldn't connect to {Fore.GREEN}{ip}{Style.RESET_ALL}, skipping . . .")
        except ConnectionRefusedError:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Connection to {Fore.GREEN}{ip}{Style.RESET_ALL} refused, skipping . . .")
        except Exception:
            pass

def is_akamai():
    is_akamai = False
    for ip in not_cloudflare:
        print(f"{Fore.MAGENTA}[➜]{Style.RESET_ALL}  {Fore.GREEN}{ip}{Style.RESET_ALL}  Akamai . . .")
        is_akamai_agent = random.choice(user_agent_strings)
        akamai_user_agent = {
            'User-Agent': is_akamai_agent
        }
        try:
            head = requests.head(f"http://{ip}", headers=akamai_user_agent)
            headers = head.headers
            if 'x-akamai' in headers is not None:
                is_akamai = True
                akamai.append(ip)
                print(f"{Fore.CYAN}[+]{Style.RESET_ALL} {Fore.CYAN}{ip}{Style.RESET_ALL} is Akamai")
                print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Country: {ip_country}")
            if 'Server' in headers is not None:
                server = headers['Server']
                if 'AkamaiGHost' in server is not None:
                    is_akamai = True
                    akamai.append(ip)
                    print(f"{Fore.CYAN}[+]{Style.RESET_ALL} {Fore.CYAN}{ip}{Style.RESET_ALL} Server detected as {Fore.GREEN}AkamaiGHost{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Country: {ip_country}")
            if is_akamai == False:
                print(f"{Fore.GREEN}[-]{Style.RESET_ALL} {Fore.RED}{ip}{Style.RESET_ALL} ")
        except ConnectionError:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Couldn't connect to {Fore.GREEN}{ip}{Style.RESET_ALL}, skipping . . .")
        except ConnectionRefusedError:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Connection to {Fore.GREEN}{ip}{Style.RESET_ALL} refused, skipping . . .")
        except Exception:
            pass


def shodan_lookup_main():
    if not not_cloudflare:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} No leaked IP addresses found\n")
        sys.exit()
    try:
        api = shodan.Shodan(api_keys.shodan)
        for ip in not_cloudflare:
            print(f"{Fore.MAGENTA}[+]{Style.RESET_ALL} Shodan results for {Fore.GREEN}{ip}{Style.RESET_ALL}")
            results = api.host(ip)
            country = results["country_name"]
            isp = results['isp']
            hostname = results['hostnames']
            domains = results['domains']
            ports = results['ports']
            os = results['os']
            none = True
            if isp is not None:
                none = False
                print(f"{Fore.CYAN}[+]{Style.RESET_ALL} ISP: {Fore.GREEN}{isp}{Style.RESET_ALL}")
            if country is not None:
                none = False
                print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Country: {Fore.GREEN}{country}{Style.RESET_ALL}")
            if hostname is not None:
                none = False
                print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Hostname(s): {Fore.GREEN}{hostname}{Style.RESET_ALL}")
            if domains is not None:
                none = False
                print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Domain(s): {Fore.GREEN}{domains}{Style.RESET_ALL}")
            if ports is not None:
                none = False
                print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Open port(s): {Fore.GREEN}{ports}{Style.RESET_ALL}")
            if os is not None:
                none = False
                print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Operating system: {Fore.GREEN}{os}{Style.RESET_ALL}")
            if none == True:
                print(f"{Fore.RED}[-]{Style.RESET_ALL} No results for {Fore.GREEN}{ip}{Style.RESET_ALL}")
    except shodan.APIError as api_error:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} No Shodan API key supplied or the key is invalid")


def subcert_query(domain_name, outputfile):
    regex = "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}"

    p = re.compile(regex)

    if re.search(p, domain_name):
        print(Fore.BLUE + "=========================================================")
    else:
        print("Invalid Domain Name")
        sys.exit(0)

    user_agents = []
    user_agents.append('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/605.1.15 (KHTML, like Gecko)')
    user_agents.append('Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko')
    user_agents.append(
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36')
    user_agents.append(
        'Mozilla/5.0 (X11; CrOS armv7l 12105.100.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.144 Safari/537.36')

    url = "https://crt.sh/?q=" + domain_name + "&output=json"
    headers = {}
    headers['User-Agent'] = secrets.choice(user_agents)

    resp = requests.get(url, headers=headers)
    resp = resp.text
    site_json = json.loads(resp)
    if len(site_json) < 2:
        print("\n[" + Fore.RED + "*" + Fore.WHITE + "] " + "No Results Found \n")
        sys.exit(0)

    first_list = []
    temp_list = []
    temp2_list = []
    temp3_list = []
    final_list = []

    for i in site_json:
        name = str(i['name_value'])
        first_list.append(name)

    for j in first_list:
        if j not in temp_list:
            temp_list.append(j)

    for k in range(len(temp_list)):
        a = temp_list[k]
        b = a.split('\n')
        temp2_list.append(b)

    def remove_nested(temp2_list):
        for i in temp2_list:
            if type(i) == list:
                remove_nested(i)
            else:
                temp3_list.append(i)

    remove_nested(temp2_list)

    for i in temp3_list:
        if i not in final_list:
            final_list.append(i)

    ip = ''

    if outputfile:
        f = open(outputfile, "a+")

    with Timeout(10):
        for i in final_list:
            try:
                if re.search(p, i):
                    ip = socket.gethostbyname(i)
                    if not ip:
                        continue
                    else:
                        print(" [" + Fore.GREEN + "*" + Fore.WHITE + "] " + str(ip) + "   -   " + str(i))
                    if outputfile:
                        f.write(str(i) + "\n")
            except:
                print(" [" + Fore.GREEN + "*" + Fore.WHITE + "] " + str(ip) + "   -   www." + str(i))
                continue

    if outputfile:
        f.close()


def separator():
    print(f"{Fore.YELLOW}={Style.RESET_ALL}" * 50)

def thread(function):
    separator()
    thread = threading.Thread(target=function)
    thread.start()
    thread.join()


def main():
    try:
        start_time = time.perf_counter()
        ascii = Figlet(font='slant', width=100)
        ascii_render = ascii.renderText("BOOND") 
        print(f"{Fore.GREEN}{ascii_render}")
        print("##############################") 
        print("#        by MrBOOND          #")
        print("#     Telegram:@BO_NND       #") 
        print("##############################")
        thread(dnsdumpster)
        thread(certificate_search)
        thread(sub_enum)
        if api_keys.securitytrails is not None:
            thread(securitytrails_get_subdomains)
        if api_keys.securitytrails is None:
            separator()
            print(f"{Fore.RED}[-]{Style.RESET_ALL} No SecurityTrails API key supplied, skipping . . .")
        thread(sub_ip)
        thread(is_cf_ip)
        thread(is_akamai)
        if api_keys.shodan is not None:
            thread(shodan_lookup_main)
        if api_keys.shodan is None:
            separator()
            print(f"{Fore.RED}[-]{Style.RESET_ALL} No Shodan API key supplied, skipping . . .")
        if write:
            with open(f"{target_domain}-results.txt", "w") as file:
                for subdomain in valid_subdomains:
                    file.write(f"VALID SUBDOMAIN: {subdomain}\n")
                for ip in not_cloudflare:
                    file.write(f"LEAKED IP: {ip}\n")
            print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Saved results in {Fore.GREEN}{target_domain}-results.txt{Style.RESET_ALL}")

        separator()
        print(f"{Fore.MAGENTA}[+]{Style.RESET_ALL} Running subcert query for additional subdomains")
        subcert_query(target_domain, f"{target_domain}-subcert-results.txt")

        perf = (time.perf_counter() - start_time)
        took = int(perf)
        print(f"{Fore.MAGENTA}[+]{Style.RESET_ALL} Finished in {took} seconds")

    except KeyboardInterrupt:
        print("[+] Keyboard interrupt detected, exiting...")
    except Exception as e:
        print(f"[-] Exception occurred\n--> {e}")

if __name__ == "__main__":
    main()


