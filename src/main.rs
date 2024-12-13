use std::fs::File;
use std::io::Write;
use std::collections::{HashSet, HashMap};

use std::path::PathBuf;
use std::{thread, time};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::blocking::{Client, ClientBuilder};
use reqwest::header::{HeaderMap, AUTHORIZATION, HeaderValue};

use base64::prelude::*;
use regex::Regex;

use clap::Parser;


#[derive(Parser)]
#[clap(version, about)]
struct Args {
    // Target domain
    #[clap(short, long, required = true)]
    domain: String,

    // List of engines
    #[clap(short, long, use_value_delimiter = true, required = false,
        long_help = "Comma separated list of engines to use",
        default_value = "google,yahoo,bing,baidu,dnsdumpster,virustotal,crt")]
    engines: Vec<String>,

    #[clap(short, long,
        default_value = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
        (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.2903.86",
        required = false)]
    user_agent: String,

    #[clap(long, default_value_t = 0, required = false,
        long_help = "Maximum number of pages to search per engine")]
    max_requests: u32,

    #[clap(short, long, required = false, default_value_t = false)]
    verbose: bool,

    #[clap(short, long, required = false, default_value_t = 3,
        long_help = "Time to sleep between requests for each engine")]
    sleep: u32,

    #[clap(short, long, required = false, default_value = None,
        long_help = "Output file")]
    output_file: Option<PathBuf>,
}


// Write data to file
fn write_to_file(filename: Option<PathBuf>, data: &str) -> std::io::Result<()> {
    if let Some(filename) = filename {
        let mut file = File::create(filename)?;
        file.write_all(data.as_bytes())?;
    }
    Ok(())
}

// Return the first match of a regex in a string
fn extract_with_regex(input: &str, regex: &str) -> Option<String> {
    let re = Regex::new(regex).unwrap();
    if let Some(caps) = re.captures(input) {
        if let Some(matched) = caps.get(1) {
            return Some(matched.as_str().to_string())
        }
    }
    None
}

struct CommonEngine {
    search: String,
    base_url: String,
    engine_name: String,
    client: Client,
    max_pages: u32,
    sleep_time: time::Duration,
    extract_regex: String,
    verbose: bool,
}

impl CommonEngine {
    fn new(search: &str, base_url: &str, engine_name: &str,
        user_agent: &str, max_pages: u32, sleep_time: u32,
        extract_regex: &str, verbose: bool) -> CommonEngine {
        let client = ClientBuilder::new()
            .user_agent(user_agent)
            .timeout(Duration::from_secs(60))
            .build()
            .unwrap();
        CommonEngine {
            search: search.to_string(),
            base_url: base_url.to_string(),
            engine_name: engine_name.to_string(),
            client: client,
            max_pages: max_pages,
            sleep_time: time::Duration::from_secs(sleep_time as u64),
            extract_regex: extract_regex.to_string(),
            verbose
        }
    }
}


trait BaseEngine: Send {
    fn get_engine(&self) -> &CommonEngine;

    fn get_search(&self) -> &String {
        &self.get_engine().search
    }

    fn get_base_url(&self) -> String {
        self.get_engine().base_url.clone()
    }
    
    fn get_engine_name(&self) -> String {
        self.get_engine().engine_name.clone()
    }

    fn get_max_pages(&self) -> u32 {
        self.get_engine().max_pages
    }

    fn get_sleep(&self) -> time::Duration {
        self.get_engine().sleep_time
    }

    fn get_client(&self) -> &Client {
        &self.get_engine().client
    }

    fn get_extract_regex(&self) -> String {
        self.get_engine().extract_regex.clone()
    }

    fn get_verbose(&self) -> bool {
        self.get_engine().verbose
    }

    fn send_request(&self, base_url: &str, query: &Vec<(String, String)>)
        -> String {
        let res = self.get_client().get(base_url).query(&query).send()
            .and_then(|res| res.text())
            .unwrap_or_else(|_e| {
                if self.get_verbose() {
                    println!("[!] Error while sending request to {}", base_url);
                }
                "".to_string()
            });
        res
    }

    fn check_max_pages(&self, num: u32) -> bool {
        if self.get_max_pages() == 0 {
            return false;
        }
        return num >= self.get_max_pages();
    }

    fn enumerate(&self) -> HashSet<String>{
        let mut subdomains: HashSet<String> = HashSet::new();
        let mut subdomains_len: u32 = 0;
        let mut num: u32 = 0;
        loop {
            // Execute the query and add the found subdomains to the list
            let query = self.generate_query_parameters(&subdomains);
            let response = self.send_request(&self.get_base_url(), &query);
            subdomains.extend(self.extract_domains(&response));

            // Update number of requests
            num = num + 1;

            // Check if the number of subdomains has increased or
            // if the maximum number of requests has been reached
            if subdomains_len == subdomains.len() as u32 ||
                self.check_max_pages(num) {
                break;
            }
            // Sleep if necessary
            thread::sleep(self.get_sleep());
            
            // Update the number of found subdomains
            subdomains_len = subdomains.len() as u32;
        }
        if self.get_verbose() {
            println!("[+] Found {} subdomains with {}",
                subdomains.len(), self.get_engine_name());
        }
        subdomains
    }

    fn extract_domains(&self, response: &str) -> HashSet<String> {
        let mut subs = HashSet::new();
        let re = Regex::new(&self.get_extract_regex()).unwrap();
        for cap in re.captures_iter(response) {
            if let Some(sub) = cap.get(1) {
                subs.insert(sub.as_str().to_string());
            }
        }
        subs
    }

    fn generate_query_parameters(&self, found: &HashSet<String>)
        -> Vec<(String, String)>;
}


struct GoogleEngine {
    engine: CommonEngine,
}

struct YahooEngine {
    engine: CommonEngine,
}

struct BingEngine {
    engine: CommonEngine,
}

struct BaiduEngine {
    engine: CommonEngine,
}

struct DnsDumpsterEngine {
    engine: CommonEngine,
}

struct VirustotalEngine {
    engine: CommonEngine,
    page_size: u32,
}

struct CrtEngine {
    engine: CommonEngine,
}

impl BaseEngine for GoogleEngine {
    fn get_engine(&self) -> &CommonEngine {
        &self.engine
    }

    fn generate_query_parameters(&self, found: &HashSet<String>)
        -> Vec<(String, String)> {
        let mut query = format!("site:{}",
            self.engine.search);
        for sub in found.iter() {
            query = format!("{} -site:{}", query, sub);
        }
        vec![("q".to_string(), query)]
    }
}

impl BaseEngine for YahooEngine {
    fn get_engine(&self) -> &CommonEngine {
        &self.engine
    }
    
    fn generate_query_parameters(&self, found: &HashSet<String>)
        -> Vec<(String, String)> {
        let mut query = format!("site:{}",
            self.engine.search);
        for sub in found.iter() {
            query = format!("{} -domain:{}", query, sub);
        }
        vec![("p".to_string(), query)]
    }
}

impl BaseEngine for BingEngine {
    fn get_engine(&self) -> &CommonEngine {
        &self.engine
    }

    fn generate_query_parameters(&self, found: &HashSet<String>)
            -> Vec<(String, String)> {
        let mut query = format!("site:{}",
            self.engine.search);
        for sub in found.iter() {
            query = format!("{} -{}", query, sub);
        }
        vec![("q".to_string(), query)]
    }
}

impl BaseEngine for BaiduEngine {
    fn get_engine(&self) -> &CommonEngine {
        &self.engine
    }

    fn generate_query_parameters(&self, found: &HashSet<String>)
            -> Vec<(String, String)> {
        let mut query = format!("site:{}",
            self.engine.search);
        for sub in found.iter() {
            query = format!("{} -site:{}", query, sub);
        }
        vec![("wd".to_string(), query)]
    }
}

impl BaseEngine for DnsDumpsterEngine {
    fn get_engine(&self) -> &CommonEngine {
        &self.engine
    }

    fn enumerate(&self) -> HashSet<String>{
        let mut subdomains: HashSet<String> = HashSet::new();

        // Retrieve the auth token
        let response = self.send_request(&self.get_base_url(), &vec![]);
        let token = match extract_with_regex(
            &response,
            r#"\{"Authorization":\s*"(.*?)"\}"#
        ) {
            Some(t) => t,
            None => {
                if self.get_verbose() {
                    println!("[!] Error while retrieving auth token for {}",
                        self.get_engine_name());
                }
                return subdomains
            }
        };

        let auth_header = match HeaderValue::from_str(token.as_str()) {
            Ok(auth_header) => auth_header,
            Err(_) => {
                if self.get_verbose() {
                    println!("[!] Error while creating auth token header for {}",
                        self.get_engine_name());
                }
                return subdomains
            } 
        };
        
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, auth_header);
        
        // Retrieve the subdomains
        let api_url = "https://api.dnsdumpster.com/htmld/";
        let mut form = HashMap::new();
        form.insert("target", self.get_engine().search.clone());
        let response = self.get_client().post(api_url)
            .headers(headers)
            .form(&form)
            .send()
            .and_then(|res| res.text())
            .unwrap_or_else(|_| "".to_string());

        subdomains.extend(self.extract_domains(&response));
        if self.get_verbose() {
            println!("[+] Found {} subdomains with {}",
                subdomains.len(), self.get_engine_name());
        }
        subdomains
    }

    fn generate_query_parameters(&self, _found: &HashSet<String>)
            -> Vec<(String, String)> {
        vec![("q".to_string(), self.engine.search.clone())]
    }
}

impl BaseEngine for VirustotalEngine {
    fn get_engine(&self) -> &CommonEngine {
        &self.engine
    }

    // Virustotal requires special headers in its requests
    fn send_request(&self, base_url: &str, query: &Vec<(String, String)>)
        -> String {
        let mut headers = HeaderMap::new();
        headers.insert("X-Tool", HeaderValue::from_static("vt-ui-main"));
        headers.insert("X-VT-Anti-Abuse-Header", HeaderValue::from_static("MTA="));
        headers.insert("Accept-Ianguage", HeaderValue::from_static("en-US,en;q=0.9,es;q=0.8"));
        
        self.get_client().get(base_url).headers(headers).query(&query).send()
            .and_then(|res| res.text())
            .unwrap_or_else(|_e| {
                if self.get_verbose() {
                    println!("[!] Error while sending request to {}", base_url);
                }
                "".to_string()
            })
    }

    fn enumerate(&self) -> HashSet<String>{
        let mut subdomains = HashSet::new();
        let mut subdomains_len: u32 = 0;
        let mut num: u32 = 0;
        let mut params = self.generate_query_parameters(&subdomains);
        loop {
            let response = self.send_request(&self.get_base_url(), &params);
            subdomains.extend(self.extract_domains(&response));

            num = num + 1;

            if subdomains_len == subdomains.len() as u32 ||
                self.check_max_pages(num) {
                break;
            }
            
            thread::sleep(self.get_sleep());
            subdomains_len = subdomains.len() as u32;

            // Update the parameters for paging
            let cursor = format!("{{\"offset\":{}}}", num * self.page_size);
            // base64 encode the cursor
            let encoded = BASE64_STANDARD.encode(cursor.as_bytes());
            params = self.generate_query_parameters(&HashSet::new());
            params.push(("cursor".to_string(), encoded));
        }

        if self.get_verbose() {
            println!("[+] Found {} subdomains with {}",
                subdomains.len(), self.get_engine_name());
        }
        subdomains
    }

    fn generate_query_parameters(&self, _found: &HashSet<String>)
            -> Vec<(String, String)> {
        vec![("relationship".to_string(), "resolutions".to_string()),
            ("limit".to_string(), self.page_size.to_string())]
    }
}

impl BaseEngine for CrtEngine {
    fn get_engine(&self) -> &CommonEngine {
        &self.engine
    }

    fn send_request(&self, base_url: &str, _query: &Vec<(String, String)>)
        -> String {
        let mut headers = HeaderMap::new();
        headers.insert("Accept", 
        HeaderValue::from_static(
            "Accept: text/html,application/xhtml+xml,\
            application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,\
            application/signed-exchange;v=b3;q=0.7"
        ));
        self.get_client().get(base_url)
            .query(&self.generate_query_parameters(&HashSet::new()))
            .send()
            .and_then(|res| res.text())
            .unwrap_or_else(|_e| {
                if self.get_verbose() {
                    println!("[!] Error while sending request to {}", base_url);
                }
                "".to_string()
            })
    }

    fn extract_domains(&self, response: &str) -> HashSet<String> {
        let mut subs = HashSet::new();

        let regex = format!("<TD>(.*?{})</TD>", self.get_search());
        let re = Regex::new(&regex).unwrap();
        for cap in re.captures_iter(response) {
            if let Some(sub) = cap.get(1) {
                // If the match contains a <BR> tag, split it and get each subdomain
                let sub_str = sub.as_str();
                for part in sub_str.split("<BR>") {
                    if !part.contains("*") {
                        subs.insert(part.to_string());
                    }
                }
            }
        }
        subs
    }

    fn generate_query_parameters(&self, _found: &HashSet<String>)
            -> Vec<(String, String)> {
        vec![("q".to_string(), self.engine.search.clone())]
    }
}

fn create_engine(engine_type: &str, search: &str,
    user_agent: &str, max_requests: u32,
    sleep: u32, verbose: bool) -> Box<dyn BaseEngine + Send> {
    match engine_type {
        "google" => Box::new(GoogleEngine {
            engine: CommonEngine::new(
                search,
                "https://www.google.com/search",
                "google",
                user_agent,
                max_requests,
                sleep,
                format!("(?:https://|http://)([-a-z0-9\\.]+{})", search).as_str(),
                verbose,
            ),
        }),
        "yahoo" => Box::new(YahooEngine {
            engine: CommonEngine::new(
                search,
                "https://search.yahoo.com/search",
                "yahoo",
                user_agent,
                max_requests,
                sleep,
                format!("(?:https%3a%2f%2f|http%3a%2f%2f)([-a-z0-9\\.]+{})", search).as_str(),
                verbose,
            ),
        }),
        "bing" => Box::new(BingEngine {
            engine: CommonEngine::new(
                search,
                "https://www.bing.com/search",
                "bing",
                user_agent,
                max_requests,
                sleep,
                format!("(?:https://|http://)([-a-z0-9\\.]+{})", search).as_str(),
                verbose,
            ),
        }),
        "baidu" => Box::new(BaiduEngine {
            engine: CommonEngine::new(
                search,
                "https://www.baidu.com/s",
                "baidu",
                user_agent,
                max_requests,
                sleep,
                format!("(?:>)([-a-z0-9\\.]+{})", search).as_str(),
                verbose,
            ),
        }),
        "dnsdumpster" => Box::new(DnsDumpsterEngine {
            engine: CommonEngine::new(
                search,
                "https://dnsdumpster.com/",
                "dnsdumpster",
                user_agent,
                max_requests,
                sleep,
                format!("<td>([-a-z0-9\\.]+{})</td>", search).as_str(),
                verbose,
            ),
        }),
        "virustotal" => {
            let base_url = format!("https://www.virustotal.com/ui/domains/{}/subdomains", search);
            Box::new(VirustotalEngine {
                engine: CommonEngine::new(
                    search,
                    base_url.as_str(),
                    "virustotal",
                    user_agent,
                    max_requests,
                    sleep,
                    format!("\"id\": \"([-a-z0-9\\.]+{})\"", search).as_str(),
                    verbose,
                ),
                page_size: 40,
            })
        },
        "crt" => {
            Box::new(CrtEngine {
                engine: CommonEngine::new(
                    search,
                    "https://crt.sh/",
                    "crt",
                    user_agent,
                    1, // Only one page
                    sleep,
                    "",
                    verbose,
                ),
            })
        },
        other => panic!("Unknown engine type: {}", other),
    }    
}




fn main() {
    let args = Args::parse();

    // Check domain format
    let domain_check = Regex::new("(?:[a-z0-9-]+\\.)+[a-z0-9-]{2,}").unwrap();
    if !domain_check.is_match(&args.domain) {
        panic!("Invalid domain format");
    }

    if args.verbose {
        println!("[*] Enumerating subdomains now for {}", args.domain);
    }

    // Final output hashset
    let output = Arc::new(Mutex::new(HashSet::new()));

    // Create a thread for each selected engine
    let mut handles = vec![];
    for engine_name in &args.engines {
        if args.verbose {
            println!("[*] Searching now in {}...", engine_name);
        }
        let engine = create_engine(
            engine_name,
            args.domain.as_str(),
            args.user_agent.as_str(),
            args.max_requests,
            args.sleep,
            args.verbose,
        );
        let merged_hashset = Arc::clone(&output);
        // Spawn a thread for each engine
        let handle = thread::spawn(move || {
            let o = engine.enumerate();
            let mut merged_lock = merged_hashset.lock().unwrap();
            merged_lock.extend(o);
        });
        handles.push(handle);
    }

    // Wait for all engines to finish
    for handle in handles {
        handle.join().unwrap();
    }

    // Merge the results and print the output
    let merged_lock = output.lock().unwrap();

    if args.verbose {
        println!("[+] Total unique subdomains found: {}", merged_lock.len());
    }

    if args.output_file.is_some() {
        if args.verbose {
            println!("[*] Writing output to file...");
        }
        let output = merged_lock.iter().map(|s| s.as_str()).collect::<Vec<&str>>().join("\n");
        write_to_file(args.output_file, &output)
            .unwrap_or_else(|e| {
                if args.verbose {
                    println!("[!] Error while writing to file: {}", e);
                }
            });
    }

    for sub in merged_lock.iter() {
        println!("{}", sub);
    }
}