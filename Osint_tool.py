# === Importing Required Libraries ===
import whois                       # For WHOIS lookup (domain registration details)
import dns.resolver               # For DNS record enumeration
import requests                   # To make HTTP requests (IP geolocation, APIs)
from bs4 import BeautifulSoup     # For scraping HTML (used in social media scraping)

# === Defining the Main Class ===
class OSINTTool:
    def __init__(self, domain, securitytrails_api_key=None):
        self.domain = domain                        # Target domain (e.g., facebook.com)
        self.api_key = securitytrails_api_key       # Optional API key for passive DNS

    # === 1. WHOIS Lookup ===
    def whois_lookup(self):
        print("\n[+] WHOIS Lookup:")
        try:
            w = whois.whois(self.domain)           # Perform WHOIS lookup
            for key, value in w.items():           # Display all the key-value pairs from WHOIS result
                print(f"{key}: {value}")
        except Exception as e:
            print(f"WHOIS lookup failed: {e}")

    # === 2. DNS Enumeration ===
    def dns_enumeration(self):
        print("\n[+] DNS Enumeration:")
        try:
            records = ['A', 'AAAA', 'MX', 'NS', 'TXT']    # DNS record types to check
            for record in records:
                try:
                    answers = dns.resolver.resolve(self.domain, record)  # Query DNS records
                    for rdata in answers:
                        print(f"{record}: {rdata}")       # Print each record found
                except Exception:
                    pass                                 # Ignore individual record errors
        except Exception as e:
            print(f"DNS Enumeration failed: {e}")

    # === 3. IP Geolocation ===
    def ip_geolocation(self):
        print("\n[+] IP Geolocation:")
        try:
            # Get IP address using Google's DNS resolver API
            ip = requests.get(f"https://dns.google/resolve?name={self.domain}&type=A").json()['Answer'][0]['data']
            # Get geolocation info of that IP using ip-api
            response = requests.get(f"http://ip-api.com/json/{ip}")
            geo = response.json()
            for key, value in geo.items():                # Display geolocation details
                print(f"{key}: {value}")
        except Exception as e:
            print(f"IP Geolocation failed: {e}")

    # === 4. Social Media Scraping (Demo using Twitter) ===
    def social_media_scrape(self):
        print("\n[+] Social Media Scraping (Twitter Demo):")
        try:
            # Create search URL (this is just a simulation)
            url = f"https://twitter.com/search?q={self.domain}&src=typed_query"
            headers = {'User-Agent': 'Mozilla/5.0'}  # Add User-Agent to avoid blocks
            response = requests.get(url, headers=headers)
            soup = BeautifulSoup(response.text, 'html.parser')  # Parse HTML content
            print("Twitter scraping completed (demo only, real scraping requires login/API).")
        except Exception as e:
            print(f"Twitter scraping failed: {e}")

    # === 5. Passive DNS Lookup using SecurityTrails API ===
    def passive_dns(self):
        print("\n[+] Passive DNS Lookup (SecurityTrails):")
        if not self.api_key:
            print("No API key provided. Skipping passive DNS.")
            return
        try:
            # API endpoint for subdomain data
            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            headers = {
                'Content-Type': 'application/json',
                'APIKEY': self.api_key
            }
            response = requests.get(url, headers=headers)
            data = response.json()
            subdomains = data.get('subdomains', [])        # Get list of subdomains
            for sub in subdomains:
                print(f"Subdomain: {sub}.{self.domain}")
        except Exception as e:
            print(f"Passive DNS failed: {e}")

    # === Run All Functions Together ===
    def run_all(self):
        print(f"\n===== Starting OSINT for: {self.domain} =====")
        self.whois_lookup()
        self.dns_enumeration()
        self.ip_geolocation()
        self.social_media_scrape()
        self.passive_dns()
        print(f"\n===== OSINT Completed for: {self.domain} =====")


# === MAIN EXECUTION BLOCK ===
if __name__ == "__main__":
    # Get user input
    target_domain = input("Enter the domain to investigate: ")
    api_key = input("Enter your SecurityTrails API key (leave blank to skip): ").strip()
    api_key = api_key if api_key else None

    # Create an instance of the OSINTTool class
    tool = OSINTTool(domain=target_domain, securitytrails_api_key=api_key)
    
    # Run all methods
    tool.run_all()
