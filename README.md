# BOOND - Domain Reconnaissance Tool

## Description
BOOND is a Content Delivery Network (CDN) reconnaissance tool written in Python. It is designed to help security professionals and researchers gather information about a target domain, including subdomains, IP addresses, SSL certificates, and potential cloud service providers.

## Features
- Subdomain enumeration using DNSDumpster, SecurityTrails, and common subdomain checks.
- SSL certificate search using crt.sh for additional subdomains.
- IP address retrieval for discovered subdomains.
- Detection of Cloudflare and Akamai services based on HTTP responses.
- Shodan integration for additional information on non-Cloudflare IP addresses.
- Subcert query for obtaining more subdomains.

## Requirements
- Python 3.x
- Required Python packages (install using `pip install -r requirements.txt`):
  - colorama
  - dnsdumpster
  - pysecuritytrails
  - shodan
  - requests
  - beautifulsoup4
  - gevent
  - pyfiglet

## Usage
1. Clone the repository:
   ```bash
   git clone https://github.com/BOONNDD/domins_scan_cloudflare.git
   cd domins_scan_cloudflare
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the tool with the target domain:
   ```bash
   python boond.py example.com
   ```
   - Optional: Use the `--write` flag to save results to a file.

4. Review the results:
   - Valid subdomains are displayed along with their IP addresses.
   - Cloudflare detection for identified IP addresses.
   - Shodan results for non-Cloudflare IP addresses (if Shodan API key is provided).

## Optional: Shodan API Key
To enhance results, you can obtain a Shodan API key by signing up on the [Shodan website](https://www.shodan.io/). Add the key to the `api_keys.shodan` variable in the script.

## Optional: SecurityTrails API Key
If you have a SecurityTrails API key, add it to the `api_keys.securitytrails` variable in the script.

## Saving Results
If you want to save the results to a file, use the `--write` flag:
```bash
python boond.py example.com --write
```

Results will be saved in files named `target_domain-results.txt` and `target_domain-subcert-results.txt`.

## Disclaimer
This tool is intended for educational and research purposes only. Use it responsibly and ensure compliance with legal and ethical standards.

## Contributing
Contributions are welcome! Feel free to open issues or pull requests.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
