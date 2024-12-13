# Sublist3r2
Porting of Sublist3r subdomain enumeration tool in Rust. Credit to https://github.com/aboul3la/Sublist3r.

```bash
./sublist3r2 --help                      
Usage: sublist3r2 [OPTIONS] --domain <DOMAIN>

Options:
  -d, --domain <DOMAIN>
          

  -e, --engines <ENGINES>
          Comma separated list of engines to use
          
          [default: google,yahoo,bing,baidu,dnsdumpster,virustotal,crt]

  -u, --user-agent <USER_AGENT>
          [default: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.2903.86"]

      --max-requests <MAX_REQUESTS>
          Maximum number of pages to search per engine
          
          [default: 0]

  -v, --verbose
          

  -s, --sleep <SLEEP>
          Time to sleep between requests for each engine
          
          [default: 3]

  -o, --output-file <OUTPUT_FILE>
          Output file

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

```bash
./sublist3r2 -d snapchat.com -e google,virustotal,baidu -v
[*] Enumerating subdomains now for snapchat.com
[*] Searching now in google...
[*] Searching now in virustotal...
[*] Searching now in baidu...
[+] Found 10 subdomains with baidu
[+] Found 16 subdomains with google
[+] Found 182 subdomains with virustotal
[+] Total unique subdomains found: 182
...
```