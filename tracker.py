#!/usr/bin/env python3
"""
Script Name: c2-tracker
Description: Track C2 server using shodan queries
"""

# Import necessary modules
import os
from dotenv import load_dotenv
from shodan import Shodan, APIError
import logging


# Logging 
logging.basicConfig(
    format='%(asctime)s,%(msecs)d %(levelname)-8s %(message)s',
    datefmt='%Y-%m-%d:%H:%M:%S',
    level=logging.INFO
    )

def stdlog(msg):
    '''standard infologging'''
    logging.info(msg)

def errlog(msg):
    '''standard error logging'''
    logging.error(msg)

def shodan():
    api_key = os.environ["SHODAN_API_KEY"].strip()
    api = Shodan(api_key)

    try:
        api_info = api.info()
        remaining_queries = api_info["usage_limits"]["query_credits"]
        query_credits = remaining_queries - api_info["scan_credits"]
        if query_credits > 0:
            stdlog("Shodan usage: "+ str(query_credits) + "/" + str(remaining_queries))
        else:
            errlog("No more Shodan credit ("+ str(query_credits) + "/" + str(remaining_queries)+")")
            exit(1)
    except APIError as error:
        errlog("Error while retrieving API info: " + str(error))

    # https://michaelkoczwara.medium.com/hunting-c2-with-shodan-223ca250d06f
    # https://michaelkoczwara.medium.com/cobalt-strike-c2-hunting-with-shodan-c448d501a6e2
    # https://twitter.com/MichalKoczwara/status/1591750513238118401?cxt=HHwWgsDUiZGqhJcsAAAA
    # https://github.com/BushidoUK/OSINT-SearchOperators/blob/main/ShodanAdversaryInfa.md
    # https://twitter.com/MichalKoczwara/status/1641119242618650653
    # https://twitter.com/MichalKoczwara/status/1641676761283850241
    queries = {
        "Cobalt Strike C2": [
            "ssl.cert.serial:146473198",
            "hash:-2007783223 port:50050",
            "ssl.jarm:07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2",
            "product:'Cobalt Strike Beacon'",
            "http.html:cs4.4",
            "ssl:foren.zik"
            ],
        "Metasploit Framework C2": [
            "ssl:MetasploitSelfSignedCA",
            "http.favicon.hash:-127886975",
            "http.html:msf4"
            ],
        "Covenant C2": [
            "ssl:Covenant http.component:Blazor",
            "http.favicon.hash:-737603591"
            ],
        "Mythic C2": [
            "ssl:Mythic port:7443",
            "http.favicon.hash:-859291042"
            ],
        "Brute Ratel C4": [
            "http.html_hash:-1957161625",
            "product:'Brute Ratel C4'"
            ],
        "Posh C2": [ "ssl:P18055077" ],
        "Sliver C2": [
            "ssl:multiplayer ssl:operators",
            "http.html:sliver-client",
            '"HTTP/1.1 404 Not Found" "Cache-Control: no-store, no-cache, must-revalidate" "Content-Length: 0" -"Server:" -"Pragma:"'
            ],
        "Deimos C2": [ "http.html_hash:-14029177" ],
        "PANDA C2":  [ "http.html:PANDA http.html:layui" ],
        "NimPlant C2" : [
            "Nimplant C2 Server",
            "http.html_hash:-1258014549"
            ],
        "Havoc C2": [ "ssl:postalCode=3540 ssl.jarm:3fd21b20d00000021c43d21b21b43de0a012c76cf078b8d06f4620c2286f5e" ],
        "GoPhish": [
            "http.html:'Gophish - Login'",
            "http.favicon.hash:803527991"
        ],
        "AcidRain Stealer": [ 'http.html:"AcidRain Stealer"' ],
        "Misha Stealer": [ "http.title:misha http.component:UIKit" ],
        "Patriot Stealer": [
            "http.favicon.hash:274603478",
            "http.html:patriotstealer"
        ],
        "RAXNET Bitcoin Stealer": [ "http.favicon.hash:-1236243965" ],
        "Titan Stealer": [ 'http.html:"Titan Stealer"' ],
        "Hachcat Cracking Tool": [ "http.html:hashcat"],
        "Collector Stealer": [
            'http.html:"Collector Stealer"',
            'http.html:getmineteam'
        ],
        "Mystic Stealer": [
            "http.title:'Mystic Stealer v1.2 -  Login'",
            "http.favicon.hash:-442056565"
        ],
        "BurpSuite": [ "http.html:BurpSuite" ],
        "PowerSploit" : [ "http.html:PowerSploit" ],
        "XMRig Monero Cryptominer": [
            "http.html:XMRig",
            "http.favicon.hash:-782317534",
            "http.favicon.hash:1088998712"
        ]
    }

    ip_set_from_all_products = set()
    count_of_all_ips = 0
    count_of_products = 0
    for product in queries:
        count_of_products += 1
        count_of_product_ips = 0
        ip_set_from_product = set()
        for query in queries[product]:
            stdlog("Product: " + product + ", Query: " + query)
            try:
                for result in api.search_cursor(query):
                    ip = str(result["ip_str"])
                    ip_set_from_product.add(ip)
                    ip_set_from_all_products.add(ip)
            except APIError as error:
                errlog(error)
        product_ips_file = open(f"data/{product} IPs.txt", "w")
        for ip in ip_set_from_product:
            product_ips_file.write(f"{ip}\n")
            count_of_product_ips += 1
        product_ips_file.closed
        stdlog("Created data/"+ product + " IPs.txt with " + str(count_of_product_ips) + " unique IP addresses from SHODAN")

    all_ips_file = open("data/all.txt", "a")
    for ip in ip_set_from_all_products:
        all_ips_file.write(f"{ip}\n")
        count_of_all_ips += 1
    stdlog("Created SHODAN all data with " + str(count_of_all_ips) +" unique IP addresses")


if __name__ == '__main__':
    print('')
    print('░▒█▀▀▄░█▀█░░░░▀▀█▀▀░█▀▀▄░█▀▀▄░█▀▄░█░▄░█▀▀░█▀▀▄')
    print('░▒█░░░░▒▄▀░▀▀░░▒█░░░█▄▄▀░█▄▄█░█░░░█▀▄░█▀▀░█▄▄▀')
    print('░▒█▄▄▀░█▄▄░░░░░▒█░░░▀░▀▀░▀░░▀░▀▀▀░▀░▀░▀▀▀░▀░▀▀v1')
    print('')
    load_dotenv()
    if 'SHODAN_API_KEY' not in os.environ:
        errlog("The SHODAN_API_KEY environment variable is not defined.")
        exit(1)  # Exit the script with a non-zero status code
    # query Shodan
    shodan()
