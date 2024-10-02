# Hacking-Cheat-Sheet
This Cheat sheet includes almost all tools for hacking.

Website Hacking Cheat-Sheet

Web Attack Cheat Sheet

Table of Contents

Discovering
Targets
IP Enumeration
Subdomain Enumeration
Wayback Machine
Cache
Crawling
Wordlist
Directory Bruteforcing
Parameter Bruteforcing
DNS and HTTP detection
Acquisitions/Names/Addresses/Contacts/Emails/etc.
HTML/JavaScript Comments
Google Dorks
Content Security Policy (CSP)
Tiny URLs Services
GraphQL
General
Enumerating
Fingerprint
Buckets
Cloud Enumeration
Containerization
Visual Identification
Scanning
Static Application Security Testing
Dependency Confusion
Send Emails
Search Vulnerabilities
Web Scanning
HTTP Request Smuggling
Subdomain Takeover
SQLi (SQL Injection)
XSS
Repositories Scanning
Secret Scanning
Google Dorks Scanning
CORS Misconfigurations
Monitoring
CVE
Attacking
Brute Force
Exfiltration
General
Manual
Payloads
Bypass
Deserialization
SSRF (Server-Side Request Forgery)
OAuth
DNS Rebinding
SMTP Header Injection
Web Shell
Reverse Shell
SQLi (SQL Injection)
XSS
XPath Injection
LFI (Local File Inclusion)
SSTI (Server Side Template Injection)
Information Disclosure
WebDAV (Web Distributed Authoring and Versioning)
Generic Tools
AI
General
Discovering
Targets
https://github.com/arkadiyt/bounty-targets-data
# This repo contains data dumps of Hackerone and Bugcrowd scopes (i.e. the domains that are eligible for bug bounty reports).

https://chaos.projectdiscovery.io
# We actively collect and maintain internet-wide assets' data, this project is meant to enhance research and analyse changes around DNS for better insights.

https://chaos-data.projectdiscovery.io/index.json
# Project Discovery Chaos Data

https://learn.microsoft.com/en-us/exchange/client-developer/web-service-reference/getfederationinformation-operation-soap
# The GetFederationInformation operation provides information about the federation status of the organization, such as the target URI to be used when requesting tokens that are targeted at this organization, and the other domains that the organization has also federated.

$ curl -s -X POST -H $'Content-Type: text/xml; charset=utf-8' -H $'SOAPAction: \"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation\"' -H $'User-Agent: AutodiscoverClient' -H $'Connection: close' --data-binary $'<?xml version=\"1.0\" encoding=\"utf-8\"?>\x0d\x0a<soap:Envelope xmlns:exm=\"http://schemas.microsoft.com/exchange/services/2006/messages\" xmlns:ext=\"http://schemas.microsoft.com/exchange/services/2006/types\" xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">\x0d\x0a\x09<soap:Header>\x0d\x0a\x09\x09<a:Action soap:mustUnderstand=\"1\">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>\x0d\x0a\x09\x09<a:To soap:mustUnderstand=\"1\">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>\x0d\x0a\x09\x09<a:ReplyTo>\x0d\x0a\x09\x09\x09<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>\x0d\x0a\x09\x09</a:ReplyTo>\x0d\x0a\x09</soap:Header>\x0d\x0a\x09<soap:Body>\x0d\x0a\x09\x09<GetFederationInformationRequestMessage xmlns=\"http://schemas.microsoft.com/exchange/2010/Autodiscover\">\x0d\x0a\x09\x09\x09<Request>\x0d\x0a\x09\x09\x09\x09<Domain>contoso.com</Domain>\x0d\x0a\x09\x09\x09</Request>\x0d\x0a\x09\x09</GetFederationInformationRequestMessage>\x0d\x0a\x09</soap:Body>\x0d\x0a</soap:Envelope>' https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc | xmllint --format -
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:a="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformationResponse</a:Action>
    <h:ServerVersionInfo xmlns:h="http://schemas.microsoft.com/exchange/2010/Autodiscover" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
      <h:MajorVersion>15</h:MajorVersion>
      <h:MinorVersion>20</h:MinorVersion>
      <h:MajorBuildNumber>7316</h:MajorBuildNumber>
      <h:MinorBuildNumber>39</h:MinorBuildNumber>
      <h:Version>Exchange2015</h:Version>
    </h:ServerVersionInfo>
  </s:Header>
  <s:Body>
    <GetFederationInformationResponseMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
      <Response xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
        <ErrorCode>NoError</ErrorCode>
        <ErrorMessage/>
        <ApplicationUri>outlook.com</ApplicationUri>
        <Domains>
          <Domain>contoso.com</Domain>
          <Domain>CONTOSO18839.onmicrosoft.com</Domain>
          <Domain>contoso18839.microsoftonline.com</Domain>
        </Domains>
        <TokenIssuers>
          <TokenIssuer>
            <Endpoint>https://login.microsoftonline.com/extSTS.srf</Endpoint>
            <Uri>urn:federation:MicrosoftOnline</Uri>
          </TokenIssuer>
        </TokenIssuers>
      </Response>
    </GetFederationInformationResponseMessage>
  </s:Body>
</s:Envelope>
IP Enumeration
http://www.asnlookup.com
# This tool leverages ASN to look up IP addresses (IPv4 & IPv6) owned by a specific organization for reconnaissance purposes.

https://github.com/pielco11/fav-up
# Lookups for real IP starting from the favicon icon and using Shodan.
python3 favUp.py --favicon-file favicon.ico -sc

https://stackoverflow.com/questions/16986879/bash-script-to-list-all-ips-in-prefix
# List all IP addresses in a given CIDR block
nmap -sL -n 10.10.64.0/27 | awk '/Nmap scan report/{print $NF}'

https://kaeferjaeger.gay/?dir=cdn-ranges/
# Lists of IP ranges used by CDNs (Cloudflare, Akamai, Incapsula, Fastly, etc). Updated every 30 minutes.

https://kaeferjaeger.gay/?dir=ip-ranges/
# Lists of IP ranges from: Google (Cloud & GoogleBot), Bing (Bingbot), Amazon (AWS), Microsoft (Azure), Oracle (Cloud) and DigitalOcean. Updated every 6 hours.

https://netlas.io/
# Internet intelligence apps that provide accurate technical information on IP addresses, domain names, websites, web applications, IoT devices, and other online assets.

https://github.com/zidansec/CloudPeler
# This tools can help you to see the real IP behind CloudFlare protected websites.

https://github.com/christophetd/CloudFlair
# CloudFlair is a tool to find origin servers of websites protected by CloudFlare (or CloudFront) which are publicly exposed and don't appropriately restrict network access to the relevant CDN IP ranges.

https://github.com/projectdiscovery/cdncheck
# cdncheck is a tool for identifying the technology associated with dns / ip network addresses.

https://github.com/Warflop/cloudbunny
# CloudBunny is a tool to capture the origin server that uses a WAF as a proxy or protection.

Subdomain Enumeration
https://web.archive.org/web/20211127183642/https://appsecco.com/books/subdomain-enumeration/
# This book intendes to be a reference for subdomain enumeration techniques.

https://celes.in/posts/cloudflare_ns_whois
# Enumerating all domains from a cloudflare account by nameserver correlation.

https://github.com/knownsec/ksubdomain
# ksubdomain是一款基于无状态子域名爆破工具，支持在Windows/Linux/Mac上使用，它会很快的进行DNS爆破，在Mac和Windows上理论最大发包速度在30w/s,linux上为160w/s的速度。
ksubdomain -d example.com

https://github.com/OWASP/Amass
# The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
amass enum -passive -dir /tmp/amass_output/ -d example.com -o dir/example.com

https://github.com/projectdiscovery/subfinder
# subfinder is a subdomain discovery tool that discovers valid subdomains for websites by using passive online sources.
subfinder -r 8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1 -t 10 -v -d example.com -o dir/example.com

https://github.com/infosec-au/altdns
# Altdns is a DNS recon tool that allows for the discovery of subdomains that conform to patterns. Altdns takes in words that could be present in subdomains under a domain (such as test, dev, staging) as well as takes in a list of subdomains that you know of.
altdns -i subdomains.txt -o data_output -w words.txt -r -s results_output.txt

https://github.com/Josue87/gotator
# Gotator is a tool to generate DNS wordlists through permutations.
gotator -sub domains.txt -perm permutations.txt -depth 2 -numbers 5 > output.txt

https://github.com/nsonaniya2010/SubDomainizer
# SubDomainizer is a tool designed to find hidden subdomains and secrets present is either webpage, Github, and external javascripts present in the given URL.
python3 SubDomainizer.py -u example.com -o dir/example.com

https://github.com/projectdiscovery/uncover
# uncover is a go wrapper using APIs of well known search engines to quickly discover exposed hosts on the internet.

https://dns.bufferover.run/dns?q=example.com
# Powered by DNSGrep (https://github.com/erbbysam/DNSGrep)
# A utility for quickly searching presorted DNS names. Built around the Rapid7 rdns & fdns dataset.

https://crt.sh/?q=example.com
# Certificate Search

https://censys.io/certificates?q=parsed.subject_dn%3AO%3DExample+Organization
# Censys is the most reputable, exhaustive, and up-to-date source of Internet scan data in the world, so you see everything.

https://www.shodan.io/search?query=ssl%3AExample
# Shodan is the world's first search engine for Internet-connected devices.

https://fullhunt.io/
# If you don't know all your internet-facing assets, which ones are vulnerable, FullHunt is here for you.

https://github.com/xiecat/fofax
# fofax is a fofa query tool written in go, positioned as a command-line tool and characterized by simplicity and speed.
fofax -q 'app="APACHE-Solr"'

https://publicwww.com
# Find any alphanumeric snippet, signature or keyword in the web pages HTML, JS and CSS code.

https://en.fofa.info
# FOFA is a search engine for global cyberspace mapping belonging to Beijing Huashun Xin'an Technology Co., Ltd.
# Through continuous active detection of global Internet assets, more than 4 billion assets and more than 350,000 fingerprint rules have been accumulated, identifying most software and hardware network assets. Asset data supports external presentation and application in various ways and can perform hierarchical portraits of assets based on IP.

https://getodin.com/
# ODIN is a powerful internet scanning tool that empowers users with real-time threat detection, comprehensive vulnerability assessment, and smart, fast, and free capabilities, making it a versatile solution for enhancing cybersecurity.

https://www.zoomeye.org
# ZoomEyeis China's first and world-renowned cyberspace search engine driven by 404 Laboratory of Knownsec. Through a large number of global surveying and mapping nodes, according to the global IPv4, IPv6 address and website domain name databases，it can continuously scan and identify multiple service port and protocols 24 hours a day, and finally map the whole or local cyberspace.

https://securitytrails.com/list/email/dns-admin.example.com
# Total Internet Inventory with the most comprehensive data that informs with unrivaled accuracy.
curl --request POST --url 'https://api.securitytrails.com/v1/domains/list?apikey={API_Key}&page=1&scroll=true' --data '{"filter":{"apex_domain":"example.com"}}' | jq -Mr '.records[].hostname' >> subdomains.txt
curl --request POST --url 'https://api.securitytrails.com/v1/domains/list?apikey={API_Key}&page=1&scroll=true' --data '{"filter":{"whois_email":"domains@example.com"}}' | jq -Mr '.records[].hostname' >> domains.txt

https://viewdns.info/reversewhois
# This free tool will allow you to find domain names owned by an individual person or company.

https://www.whoxy.com
# Our WHOIS API returns consistent and well-structured WHOIS data in XML & JSON format. Returned data contain parsed WHOIS fields that can be easily understood by your application.

https://github.com/MilindPurswani/whoxyrm
# A reverse whois tool based on Whoxy API based on @jhaddix's talk on Bug Hunter's Methodology v4.02.
whoxyrm -company-name "Example Inc."

https://opendata.rapid7.com/
# Offering researchers and community members open access to data from Project Sonar, which conducts internet-wide surveys to gain insights into global exposure to common vulnerabilities.

https://openintel.nl/
# The goal of the OpenINTEL measurement platform is to capture daily snapshots of the state of large parts of the global Domain Name System. Because the DNS plays a key role in almost all Internet services, recording this information allows us to track changes on the Internet, and thus its evolution, over longer periods of time. By performing active measurements, rather than passively collecting DNS data, we build consistent and reliable time series of the state of the DNS.

https://github.com/ninoseki/mihari
# Mihari is a framework for continuous OSINT based threat hunting.

https://github.com/ProjectAnte/dnsgen
# This tool generates a combination of domain names from the provided input. Combinations are created based on wordlist. Custom words are extracted per execution.

https://github.com/resyncgg/ripgen
# A rust-based version of the popular dnsgen python utility.

https://github.com/d3mondev/puredns
# Fast domain resolver and subdomain bruteforcing with accurate wildcard filtering.

https://github.com/projectdiscovery/dnsx
# Fast and multi-purpose DNS toolkit allow to run multiple DNS queries.

https://github.com/glebarez/cero
# Cero will connect to remote hosts, and read domain names from the certificates provided during TLS handshake.

https://cramppet.github.io/regulator/index.html
# Regulator: A unique method of subdomain enumeration

https://github.com/blechschmidt/massdns
# MassDNS is a simple high-performance DNS stub resolver targeting those who seek to resolve a massive amount of domain names in the order of millions or even billions.
massdns -r resolvers.txt -o S -w massdns.out subdomains.txt

https://github.com/trickest/resolvers
# The most exhaustive list of reliable DNS resolvers.

https://github.com/n0kovo/n0kovo_subdomains
# An extremely effective subdomain wordlist of 3,000,000 lines, crafted by harvesting SSL certs from the entire IPv4 space.

https://labs.detectify.com/how-to/advanced-subdomain-reconnaissance-how-to-enhance-an-ethical-hackers-easm/
# Many EASM programs limit the effectiveness of subdomain enumeration by relying solely on pre-made tools. The following techniques show how ethical hackers can expand their EASM program beyond the basics and build the best possible subdomain asset inventory.

Wayback Machine
https://github.com/tomnomnom/waybackurls
# Accept line-delimited domains on stdin, fetch known URLs from the Wayback Machine for *.domain and output them on stdout.
cat subdomains.txt | waybackurls > waybackurls.txt

https://github.com/tomnomnom/hacks
# Hacky one-off scripts, tests etc.
cat waybackurls.txt | go run /root/Tools/hacks/anti-burl/main.go | tee waybackurls_valid.txt

https://github.com/lc/gau
# getallurls (gau) fetches known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl for any given domain.
cat domains.txt | gau --threads 5

Cache
https://portswigger.net/research/practical-web-cache-poisoning
# Web cache poisoning has long been an elusive vulnerability, a 'theoretical' threat used mostly to scare developers into obediently patching issues that nobody could actually exploit.
# In this paper I'll show you how to compromise websites by using esoteric web features to turn their caches into exploit delivery systems, targeting everyone that makes the mistake of visiting their homepage.

https://www.giftofspeed.com/cache-checker
# This tool lists which web files on a website are cached and which are not. Furthermore it checks by which method these files are cached and what the expiry time of the cached files is.

https://youst.in/posts/cache-poisoning-at-scale/
# Even though Web Cache Poisoning has been around for years, the increasing complexity in technology stacks constantly introduces unexpected behaviour which can be abused to achieve novel cache poisoning attacks. In this paper I will present the techniques I used to report over 70 cache poisoning vulnerabilities to various Bug Bounty programs.

https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner
# Web Cache Vulnerability Scanner (WCVS) is a fast and versatile CLI scanner for web cache poisoning developed by Hackmanit.
wcvs -u https://example.com -hw "file:/home/user/Documents/wordlist-header.txt" -pw "file:/home/user/Documents/wordlist-parameter.txt"

Crawling
https://github.com/jaeles-project/gospider
# Fast web spider written in Go.
gospider -s "https://example.com/" -o output -c 20 -d 10

https://github.com/xnl-h4ck3r/xnLinkFinder
# This is a tool used to discover endpoints (and potential parameters) for a given target.

https://github.com/hakluke/hakrawler
# Fast golang web crawler for gathering URLs and JavaScript file locations. This is basically a simple implementation of the awesome Gocolly library.
echo https://example.com | hakrawler

https://github.com/projectdiscovery/katana
# A next-generation crawling and spidering framework.
katana -u https://example.com

https://geotargetly.com/geo-browse
# Geo Browse is a tool designed to capture screenshots of your website from different countries.

https://commoncrawl.org/
# We build and maintain an open repository of web crawl data that can be accessed and analyzed by anyone.

https://github.com/bitquark/shortscan
# Shortscan is designed to quickly determine which files with short filenames exist on an IIS webserver. Once a short filename has been identified the tool will try to automatically identify the full filename.
shortscan https://example.com/

Wordlist
https://portswigger.net/bappstore/21df56baa03d499c8439018fe075d3d7
# Scrapes all unique words and numbers for use with password cracking.

https://github.com/ameenmaali/wordlistgen
# wordlistgen is a tool to pass a list of URLs and get back a list of relevant words for your wordlists.
cat hosts.txt | wordlistgen

https://github.com/danielmiessler/SecLists
# SecLists is the security tester's companion. It's a collection of multiple types of lists used during security assessments, collected in one place. List types include usernames, passwords, URLs, sensitive data patterns, fuzzing payloads, web shells, and many more.

https://github.com/swisskyrepo/PayloadsAllTheThings
# A list of useful payloads and bypasses for Web Application Security. Feel free to improve with your payloads and techniques.

https://github.com/fuzzdb-project/fuzzdb
# FuzzDB was created to increase the likelihood of finding application security vulnerabilities through dynamic application security testing.

https://github.com/google/fuzzing
# This project aims at hosting tutorials, examples, discussions, research proposals, and other resources related to fuzzing.

https://wordlists.assetnote.io
# This website provides you with wordlists that are up to date and effective against the most popular technologies on the internet.

https://github.com/trickest/wordlists
# Real-world infosec wordlists, updated regularly.

https://github.com/the-xentropy/samlists
# The wordlists are created by trawling through huge public datasets. The methods employed are a bit different based on the noisiness of the data source.

Directory Bruteforcing
https://github.com/ffuf/ffuf
# A fast web fuzzer written in Go.
ffuf -H 'User-Agent: Mozilla' -v -t 30 -w mydirfilelist.txt -b 'NAME1=VALUE1; NAME2=VALUE2' -u 'https://example.com/FUZZ'

https://githu
