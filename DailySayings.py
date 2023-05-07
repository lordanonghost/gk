import argparse
import whois
import requests
import socket
import dns.resolver
import telnetlib
import urllib.robotparser
from urllib.parse import urlparse



def get_whois_info(domain):
    w = whois.whois(domain)
    return w


def get_robots_txt(url):
    domain = url.split("//")[-1].split("/")[0]
    robots_txt_url = f"{url}/robots.txt"
    response = requests.get(robots_txt_url)
    if response.status_code == 200:
        return response.text
    else:
        return f"No robots.txt file found for {domain}"


def get_ip_address(domain):
    ip = socket.gethostbyname(domain)
    return ip


def get_index_html(url):
    response = requests.get(url)
    if response.status_code == 200:
        return response.text
    else:
        return f"Failed to retrieve index.html for {url}"

    def get_banner_info(url):
        try:
            ip = socket.gethostbyname(urlparse(url).hostname)
            tn = telnetlib.Telnet(ip)
            banner = tn.read_all().decode("utf-8")
            tn.close()
            return banner
        except Exception as e:
            return f"Failed to retrieve banner information: {str(e)}"

    def get_dns_info(domain):
        records = {}
        try:
            answers = dns.resolver.resolve(domain, 'A')
            records['A'] = [str(rdata) for rdata in answers]
            answers = dns.resolver.resolve(domain, 'AAAA')
            records['AAAA'] = [str(rdata) for rdata in answers]
            answers = dns.resolver.resolve(domain, 'CNAME')
            records['CNAME'] = [str(rdata) for rdata in answers]
            answers = dns.resolver.resolve(domain, 'MX')
            records['MX'] = [str(rdata.exchange) for rdata in answers]
            answers = dns.resolver.resolve(domain, 'NS')
            records['NS'] = [str(rdata) for rdata in answers]
            answers = dns.resolver.resolve(domain, 'TXT')
            records['TXT'] = [str(rdata) for rdata in answers]
        except dns.resolver.NoAnswer:
            records['error'] = "No DNS records found for the domain."
        except dns.resolver.NXDOMAIN:
            records['error'] = "Domain does not exist."
        except dns.resolver.Timeout:
            records['error'] = "DNS resolution timed out."
        return records


#more function
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Website Scanner")

    parser.add_argument("url", type=str, help="URL of the website to scan")
    parser.add_argument("--whois", action="store_true", help="Get WHOIS information")
    parser.add_argument("--robots", action="store_true", help="Get robots.txt content")
    parser.add_argument("--ip", action="store_true", help="Get IP address information")
    parser.add_argument("--index", action="store_true", help="Get index.html content")
    parser.add_argument("--banner", action="store_true", help="Get banner information")
    parser.add_argument("--dns", action="store_true", help="Get DNS information")

    args = parser.parse_args()

    website_url = args.url
    domain = website_url.split("//")[-1].split("/")[0]

    if args.whois:
        whois_info = get_whois_info(domain)
        print("WHOIS Information:")
        print(whois_info)

    if args.robots:
        robots_txt = get_robots_txt(website_url)
        print("\nrobots.txt Content:")
        print(robots_txt)

    if args.ip:
        ip_address = get_ip_address(domain)
        print("\nIP Address:")
        print(ip_address)

    if args.index:
        index_html = get_index_html(website_url)
        print("\nindex.html Content:")
        print(index_html)

        if args.banner:
            banner_info = get_banner_info(website_url)
            print("Banner Information:")
            print(banner_info)

        if args.dns:
            dns_info = get_dns_info(domain)
            print("\nDNS Information:")
            if "error" in dns_info:
                print(dns_info["error"])
            else:
                for record_type, records in dns_info.items():
                    print(f"{record_type}:")
                    for record in records:
                        print(record)
                    print()