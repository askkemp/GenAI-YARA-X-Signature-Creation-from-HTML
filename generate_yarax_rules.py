#!/usr/bin/env python3
from warcio.archiveiterator import ArchiveIterator
from google import genai
from google.genai import types
from pathlib import Path
import json
import docker
from docker.errors import DockerException
import tldextract
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import logging
logging.basicConfig(level=logging.INFO)
from genai_prices import UpdatePrices, Usage, calc_price # https://github.com/pydantic/genai-prices/blob/main/packages/python/README.md
import yara_x

#
# CONFIGURE ME
#
GOOGLE_GENAI_API_KEY = "yourkeyhere" # Your paid key
BRAND_MONITORING_URLS = ["https://www.war.gov/", "https://www.war.gov/About/", "https://www.war.gov/Spotlights/Value-of-Service/"] # A list of URLs at the same domain which will be used to create a YARA-X signatures for

# Should be able to leave all of the below configurations as default
WARC_OUTPUT_DIR = Path("WARC_FILES") # where to save WARC files
YARA_X_SIGNATURE_FILE = Path("genai_signature.yarax") # where to save the generated YARA-X signature
SCAN_RESULTS_FILE = Path("scan_results.ndjson") # where to save the results of scanning the WARC with the generated YARA-X signature
LOW_COST_MODULE_NAME = "gemini-3.1-flash-lite-preview" # ~$0.10 per query, used for URL generation
HIGH_COST_MODULE_NAME = "gemini-3.1-pro-preview" # ~$1.72 per query, used for YARA-X signature generation

#
# Leave all the below alone
#
gemini_client = genai.Client(api_key=GOOGLE_GENAI_API_KEY)

def get_registered_domain(url: str) -> str:
    """Extract the registered domain from a URL. For example, given 'https://sub.example.co.uk/page', it will return 'example.co.uk'."""
    extracted = tldextract.extract(url)
    registered_domain = extracted.top_domain_under_public_suffix # returns empty if no valid domain/suffix found
    registered_domain = registered_domain.lower() if registered_domain else None
    if registered_domain:
        return registered_domain
    else:
        logging.critical(f"Could not extract registered domain from URL: {url}. Something is very wrong...")
        exit(1)

def extract_text(response: object) -> str:
    """Extract text content from a Gemini API response object, concatenating text from all parts of all candidates."""
    chunks: list[str] = []
    candidates = getattr(response, "candidates", None) or []

    for candidate in candidates:
        content = getattr(candidate, "content", None)
        if not content:
            continue

        for part in getattr(content, "parts", None) or []:
            text = getattr(part, "text", None)
            if text:
                chunks.append(text)

    return "\n".join(chunks).strip()


def generate_url_list(client: genai.Client, content:list[str], model_name: str) -> object:
    """Generate a list of URLs related to the input domain using the Gemini API."""
    grounding_tool = types.Tool(
        google_search=types.GoogleSearch()
    )

    config = types.GenerateContentConfig(
        tools=[grounding_tool]
    )

    prompt = (
        f"Your role is similar to a website search engine. You are provided a list of related URLs. You are going to make three lists."
        "The first list contains the top 50 websites that are related to the provided input of URLs. These websites should be similar in topic, content, industry, category, or theme. The json key for this list will be top_related_urls."
        "The second list are the top 30 webpages that are using the same domain name in their URL as the list of provided input URLs. For example, if the input domain is 'example.com', you would look for websites that have 'example.com' in their URL and list the top 30 of those. It would be best to have at most half that are with a subdomain of the domain name and some that are actual different webpages (i.e., unique URIs) on the same domain. The json key for this list will be top_same_domain."
        "The third list are the top 50 websites which should not relate to the input URLs at all. These websites should be completely different in topic, content, industry, category, or theme. The json key for this list will be top_unrelated_urls."
        "You return the websites as proper URLs. You make sure that the websites are valid and active. You do not include any duplicates across the three lists. You make sure that the three lists are mutually exclusive."
        "You return all three lists in a JSON format with the keys top_related_urls, top_same_domain, and top_unrelated_urls."
        "Do not include markdown code fence. Just output JSON."
        "The input URLs are:"
        f"{content}"
    )

    return client.models.generate_content(
        model=model_name, # best to use low cost model here
        contents=prompt,
        config=config,
    )

def run_browsertrix_crawl(urls: list[str], output_dir: Path, collection_name: str) -> tuple[int, float]:
    """
    Browsertrix Crawler is a high-fidelity browser-based web archiving crawler in a single Docker container.
    Given a list of URLs, it crawls a single page scope and saves the crawl output as WARC files in the specified output directory.

    Args:
        urls: List of URLs to crawl.
        output_dir: Directory where the collection folder is created which is then where the crawl output (WARC files) will be stored.
        collection_name: Name of the collection (subdirectory) to create for this crawl.
    Returns:
        tuple[int, float]: A tuple containing the exit code of the crawl process (0 for success, non-zero for failure) and the percentage of failed pages.

    Notes:
        - This function assumes Docker is installed and the user has permission to run Docker commands.
    """

    # Collection folder is created here by Browsertrix
    crawls_dir = (output_dir / "crawls").resolve()

    image_name = "webrecorder/browsertrix-crawler:latest"
    client = docker.from_env()
    client.images.pull(image_name)

    command: list[str] = [
        "crawl",
        "--collection", # Collection name / directory to save crawl into
        collection_name,
        "--scopeType", # predefined scope of the crawl
        "page", # single webpage at the provided URL
    ]

    # Browsertrix array option format: repeat --url for each seed URL.
    for url in urls:
        command.extend(["--url", url])

    # Do not precreate the directory on the host
    volumes = {
        str(crawls_dir): {"bind": "/crawls/", "mode": "rw"},
    }

    logging.info(f"Starting Docker Browsertrix crawl for {len(urls)} URLs. Output folder: {crawls_dir}/{collection_name}")
    logging.debug(f"Docker command: {' '.join(command)}")
    
    container = client.containers.run(
        image=image_name,
        command=command,
        volumes=volumes,
        detach=True,
        remove=False,
        tty=False,
        stdin_open=False,
    )

    percent_failed = 0.0
    try:
        for line in container.logs(stream=True, follow=True):
            logging.debug(line.decode('utf-8').strip())
            try:
                line_json = json.loads(line.decode("utf-8").strip())
                message = line_json.get("message", "")
                if "Page Finished" in message:
                    details = line_json.get("details", {})
                    logging.info(f"Crawl finished: {details.get('page')}")
                if "Crawl statistics" in message:
                    details = line_json.get("details", {})
                    if len(details.get("pendingPages", [])) == 0: # Stats occure reguarly but only want the last one
                        logging.info(f"Crawl overall statistics: {details}")
                        crawl_total = details.get("total", {})
                        crawl_failed = details.get("failed", {})
                        percent_failed = crawl_failed / crawl_total * 100 if crawl_total > 0 else 0
            except json.JSONDecodeError:
                pass
        result = container.wait()
        exit_code = int(result.get("StatusCode", 1))
    finally:
        try:
            container.remove(force=False)
        except Exception:
            pass
    logging.debug(f"Browsertrix exit_code: {exit_code}. Percent failed: {percent_failed}")
    return exit_code, percent_failed

def warc_to_text(warc_file: Path) -> None:
    """
    Parse a WARC file and extract HTML payloads into one output text file per registered domain.
    The output filename contains the registered domain of the URL for the capture.
    Each output text file will contain the concatenated HTML content of all pages captured for that domain, with delimiters between pages.

    Args:
        warc_file (Path): Path to the single WARC file to process. 
    Returns:
        dict[str, list[tuple[str, str]]]: A dictionary mapping registered domains to a list of tuples, where each tuple contains a URL and its corresponding HTML content extracted from the WARC file.
        e.g. {example.com: [(url1, html1), (url2, html2)], anotherdomain.com: [(url3, html3)]]}

    """

    def decode_bytes(content: bytes) -> str:
        for enc in ("utf-8", "utf-16", "latin-1"):
            try:
                return content.decode(enc)
            except UnicodeDecodeError:
                continue
        return content.decode("utf-8", errors="replace")

    def is_html_record(record) -> bool:
        """Check if a WARC record is an HTTP response with HTML content.

        Args:
            record: warcio.recordloader.ArcWarcRecord

        Returns:
            bool: True if the record is an HTTP response with a content-type header indicating HTML content, False otherwise.
        """
        if record.rec_type != "response":
            return False
    
        http_headers = getattr(record, "http_headers", None)
        if not http_headers:
            return False
    
        content_type = (http_headers.get_header("Content-Type") or "").lower()
        return ("text/html" in content_type) or ("application/xhtml+xml" in content_type)

    # domain -> list[(url, html)]
    extracted_html: dict[str, list[tuple[str, str]]] = {}

    logging.debug("Processing file: %s", warc_file)
    try:
        with warc_file.open("rb") as stream:
            it = ArchiveIterator(stream, check_digests=True)
            for record in it: # warcio.recordloader.ArcWarcRecord
                if not is_html_record(record):
                    logging.debug(f"Skipping non-HTML record in {warc_file}")
                    continue

                url = record.rec_headers.get_header("WARC-Target-URI") or ""
                if not url: # something really wrong
                    logging.debug(f"Skipping record with missing URL in {warc_file}")
                    continue

                content = record.content_stream().read()
                html_text = decode_bytes(content)
                if not html_text.strip(): # something really wrong
                    logging.debug(f"Skipping empty HTML content for URL: {url} in {warc_file}")
                    continue

                domain = get_registered_domain(url)
                if domain not in extracted_html:
                    extracted_html[domain] = []
                extracted_html[domain].append((url, html_text))

    except Exception as exc:
        logging.exception(f"Error parsing {warc_file}: {exc}")

    if not extracted_html:
        logging.warning("No HTML responses were extracted.")
        return {}
    else:
        logging.info(f"Extracted HTML content for {sum(len(v) for v in extracted_html.values())} pages across {len(extracted_html)} unique domains from {warc_file}")

    return extracted_html


def check_pricing(client: genai.Client, input_text: str, model_name: str) -> dict[str, object]:
    """Check token count and return a readable pricing summary."""
    output_tokens_assumed = 1000 # big guess
    res = client.models.count_tokens(
        model=model_name,
        contents=input_text,
    )

    price_data = calc_price(
        Usage(input_tokens=res.total_tokens, output_tokens=output_tokens_assumed),
        model_ref=model_name,
        provider_id='google',
    )

    return {
        "model_id": model_name,
        "provider_id": "google",
        "input_tokens": res.total_tokens,
        "assumed_output_tokens": output_tokens_assumed,
        "input_price_usd": float(price_data.input_price),
        "output_price_usd": float(price_data.output_price),
        "total_price_usd": float(price_data.total_price),
    }

def fetch_html_with_gemini(client: genai.Client, content:str, model_name: str) -> object:
    """Fetch HTML content from Gemini API based on the provided content and model name."""

    prompt = (
        f"Your role is a cyber security brand monitoring expert that creates YARA-X rules based on the content of webpages. You use these created YARA-X signatures to scan websites and detect if the website is infringing on the brand."
        "Of most importance is creating a signature based on the unique characteristics of the website so that when the YARA-X signature scans a similar website, it matches correctly. In other words, the YARA-X signatures should be specific enough to find similar infringing websites but not so specific that they only find the exact same webpage."
        "Overall, the purpose of the signature is brand monitoring and finding of websites that are infringing the brand."
        "You are provided a JSON object which contains the domain you want to do brand monitoring for and a list of URLs with their corresponding HTML content for that domain. Each URL is a webpage that was captured in a crawl of the domain. The HTML content is the full HTML of the webpage. You use this information to create YARA-X signatures that can be used to find similar webpages that may be infringing on the brand. Here is an example of the JSON object: {\"example.com\":[[\"url1\",\"html1\"],[\"url2\",\"html2\"]],\"anotherdomain.com\":[[\"url3\",\"html3\"]]}"
        "The purpose of providing many examples of webpages as the same domain is so that all of the pages can be reviewed to determine what is unique across the pages that can be used to create strong YARA-X signatures for brand monitoring."
        "Four unique YARA-X signatures should be created FOR EACH DOMAIN provided. Each YARA-X signature must focus on a different detection methodology."
        "Signature number one, called readable words, will be written based on notable sentences within the page that reflect on the brand. This includes certain brand phrases, specific listed EULAs, specific trademarked terms that are brand related, etc. The condition of the signature must match on as many of these strings as possible to be effective. For example, if there are 10 notable sentences/phrases that are unique to the brand, the YARA-X signature should try to match on at least 75 percent of them in the condition to be effective. The more of these strings that are included in the condition, the better."
        "Signature number two, called tag identifiers, will be created based on the unique identifiers within the HTML/JS. with examples like like Google Tag Manager ID, Google Ads conversion ID, legacy Google Analytics ID, GA4 Measurement ID, Meta/Facebook Pixel ID, LinkedIn Insight Tag ID, X/Twitter Ads pixel ID, Hotjar site ID/version, Heap app ID, Amplitude API key/project key, Microsoft Clarity project ID, LiveChat license ID, Mixpanel project token, Drift widget/app ID, Intercom app ID, Tawk.to property/widget IDs, Crisp website ID, Tidio public key, Zendesk Chat key/widget footprint, Botpress webchat bot ID/collection ID, WidgetBot chat embed IDs, Chatwoot website token, Microsoft/Bing UET tag ID, TikTok pixel ID, Snapchat pixel ID, Pinterest tag ID, Reddit pixel ID, Quora pixel ID, Taboola account/publisher ID, Outbrain widget/account ID, Segment write key, RudderStack write key, PostHog project key, Pendo app key/subscription ID, Optimizely project/account ID, VWO account ID, AB Tasty account/site ID, Kameleoon site code, Dynamic Yield site context ID, OneTrust data-domain-script UUID, Cookiebot data-cbid UUID, Usercentrics settings ID, Didomi notice ID, Sentry DSN, Datadog RUM applicationId/clientToken, New Relic browser license key, LogRocket app ID, FullStory org ID, Cloudflare Turnstile sitekey, hCaptcha sitekey, reCAPTCHA sitekey, etc."
        "Signature number three, called ownership verification meta tags, will be created based on ownership verification meta data. You MUST match the unique verification value found in the content attribute. Do not create strings that only match the tag name itself. Use explicit key plus value patterns from the provided HTML, such as full meta snippets or regex patterns (if required for proper matching) that include both the verification key and its exact value. Examples of ownership verification meta tag names include: google-site-verification, msvalidate.01, yandex-verification, p:domain_verify, facebook-domain-verification, baidu-site-verification, naver-site-verification, 360-site-verification, sogou_site_verification, alexaVerifyID, y_key, norton-safeweb-site-verification, ahrefs-site-verification, majestic-site-verification, semrush-site-verification, site-verification, domain-verification, ownership-verification, webmaster-verification, search-verification, verification, verification-code, verification_code, verification-token, verification_token, verify-token, verify_token, verify-v1, domain_verify, site_verify."
        "Signature number four, called unique HTML/JS features, will focus on unique features of the HTML/JS code on the page. Identify what is unique to the page that will find very similar webpages."
        "Return four valid YARA-X rules for each brand monitoring domain UNLESS there is no content availble from the HTML to create that rule for which case return nothing (not even a placeholder) for that signature requirement. Return only the YARA-X rules text. The rule name of the YARA-X rule should contain the domain it is looking for. The meta field of the yara rule should contain a field called domain which contains the domain the YARA-X signature was built for. "
        "Here is the JSON object: "
        f"{content}"
    )

    return client.models.generate_content(
        model=model_name, # best to use pro model here since the prompt is complex and requires deep understanding
        contents=prompt,
    )

def validate_yara_rule(input_rule: str) -> bool:
	"""Return True when the provided YARA-X rules file compiles successfully."""
	try:
		rules = yara_x.compile(input_rule)
	except Exception as e:
		logging.critical(f"YARA-X rules failed to compile. Error: {e}")
		return False

	logging.info(f"YARA-X rules compiled successfully")
	return True

def test_yara_rules_on_text(input_rule: str, input_text: str) -> tuple[bool, list[str]]:
    """Compile the rules once and test them against every .txt file in a folder."""

    rules = yara_x.compile(input_rule)
    results = rules.scan(input_text.encode("utf-8", errors="replace"))

    if results.matching_rules:
        matching_rule_ids = [rule.identifier for rule in results.matching_rules]
        return True, matching_rule_ids # match
    else:
        return False, [] # no match

def yara_scan_warc(warc_file: Path, input_rule: str) -> list[dict]:
    """
    Process a single WARC file, scanning each record with YARA-X rules, and saving matches to an NDJSON file.
    Args:
        warc_file (Path): Path to the WARC file.
    Returns:
        list[dict]: Each dictionary contains detailed information about a matching record and the corresponding YARA-X rule that matched it.
    """

    output = list[dict]()
    rules = yara_x.compile(input_rule)
  
    with open(warc_file, 'rb') as stream:
        it = ArchiveIterator(stream, check_digests=True)
        for record in it:
            rec_offset = it.offset # Get the byte offset of the current record which is needed to quickly extract it later
            record_type = record.rec_type
            warc_headers = record.rec_headers
            record_id = warc_headers.get_header('WARC-Record-ID')
            target_uri = warc_headers.get_header('WARC-Target-URI')
            content_type = warc_headers.get_header('Content-Type')
            date = warc_headers.get_header('WARC-Date')

            # Read the payload of the warc record
            # https://github.com/webrecorder/warcio/blob/6775fb9ea3505db144a145c5a8b3ba1dfb822ac1/warcio/extractor.py#L27
            # From https://github.com/webrecorder/warcio/blob/master/README.rst: A special ArcWarcRecord.content_stream() function provides a stream that automatically decompresses and de-chunks the HTTP payload, if it is compressed and/or transfer-encoding chunked.
            content = record.content_stream().read() 
            if record.rec_type == 'response': # response: HTTP response received from server
                
                # Scan warc record content with YARA-X rules
                result = rules.scan(content)  # ScanResults object
                
                # Create detailed information for each matching rule and save as JSON lines
                for rule in result.matching_rules:
                    temp_dict = dict()
                    temp_dict['warc_file_name'] = warc_file.name
                    temp_dict['warc_file_path'] = str(warc_file)
                    temp_dict['warc_record_offset'] = rec_offset
                    temp_dict['warc_record_target_uri'] = target_uri
                    temp_dict['warc_record_id'] = record_id
                    temp_dict['warc_record_content_type'] = content_type

                    temp_dict['yara_rule_identifier'] = rule.identifier
                    temp_dict['yara_rule_namespace'] = rule.namespace
                    temp_dict['yara_rule_tags'] = list(rule.tags)
                    temp_dict['yara_rule_metadata'] = dict(rule.metadata)

                    # Collect specific YARA pattern matches
                    for pattern in rule.patterns: # Matching Patterns
                        match_count = len(list(pattern.matches))
                        if match_count == 0: # No matches for this pattern
                            continue
                        matched_content_set = set()
                        matched_content_superset_set = set()
                        for i, match in enumerate(pattern.matches): # Details for each match of this pattern

                            # Extract and show the matched content to help future analysis
                            matched_content = content[match.offset:match.offset + match.length] # exaxctly what matched

                            # To make future analysis even easier, show some context around the match
                            start = max(0, match.offset - 20)
                            end = min(len(content), match.offset + match.length + 20)
                            matched_content_superset = content[start:end]

                            if len(matched_content) > 100:
                                matched_preview = matched_content[:100] + b"(truncated at 100 bytes)"
                            else:
                                matched_preview = matched_content
                                
                            try:
                                matched_text = matched_preview.decode('utf-8', errors='replace')
                                matched_content_set.add(matched_text)
                            except:
                                matched_content_set.add(matched_preview) # bytes

                            if len(matched_content_superset) > 100:
                                matched_preview = matched_content_superset[:100] + b"(truncated at 100 bytes)"
                            else:
                                matched_preview = matched_content_superset
                                
                            try:
                                matched_text = matched_preview.decode('utf-8', errors='replace')
                                matched_content_superset_set.add(matched_text)
                            except:
                                matched_content_superset_set.add(matched_preview) # bytes
                    
                        temp_dict['yara_rule_matching_content'] = list(matched_content_set)
                        temp_dict['yara_rule_matching_content_superset'] = list(matched_content_superset_set)

                    logging.debug(temp_dict) # to watch it real-time
                    output.append(temp_dict)    
    return output


def main () -> None:

    ################################################################################
    # Pre-flight checks
    ################################################################################

    # Validate URL inputs
    for url in BRAND_MONITORING_URLS:
        if not (url.startswith("http://") or url.startswith("https://")):
            logging.critical(f"Invalid URL in BRAND_MONITORING_URLS: {url}. Each URL must start with http:// or https://. Please fix the URL and try again. Exiting...")
            exit(1)
    
    # Validate docker access since Browsertrix Crawler requires Docker
    try:
        client = docker.from_env()
        client.ping()
    except Exception as e:
        logging.critical(e)
        logging.critical("User running this script lacks access to /var/run/docker.sock. Add user to docker group or run with appropriate privileges. e.g. 'sudo usermod -a -G docker $USER'")
        exit(1)

    logging.info("Pre-flight checks passed!")
    logging.info(f"The following URLs will be used to generate a YARA-X signature for brand monitoring: {BRAND_MONITORING_URLS}")

    ################################################################################
    # Step 1 - Generate WARC for the URLs to be brand monitored
    #    - The YARA-X signature is built from the HTML of this response
    #
    ################################################################################
    logging.info(f"\nSTEP 1 - Generating WARC for the URLs to be brand monitored...")
    collection_name = "urls_to_monitor"
    crawl_exit_code, crawl_percent_failed = run_browsertrix_crawl(urls=BRAND_MONITORING_URLS, output_dir=WARC_OUTPUT_DIR, collection_name=collection_name)
    if crawl_exit_code != 0 or crawl_percent_failed > 0:
        logging.error(f"Browsertrix crawl of {BRAND_MONITORING_URLS} failed. The HTML from this download is how the WARC is created. Without a successful crawl, the WARC will not be created and there will be no HTML to extract and feed into Gemini to create YARA-X signatures. Please investigate the crawl failure. Exiting...")
        exit(1)

    ################################################################################
    # Step 2 - Extract the HTML from the WARC file for the desired brand monitoring domain(s)
    #    - HTML content is extract from the WARC and seperated by domain name
    #    - Objective is to feed the extracted HTML, which are various webpage examples for a single domain, into Gemini to create YARA-X signatures 
    ################################################################################
    logging.info(f"\nSTEP 2 - Extracting HTML content from WARC file...")
    warc_files = list((WARC_OUTPUT_DIR / "crawls" / "collections" / collection_name / "archive").glob("**/*.warc.gz")) # Should just be one warc
    if not warc_files:
        logging.critical(f"No WARC files found in {WARC_OUTPUT_DIR}/crawls/collections/{collection_name}/archive. Something is very wrong. Exiting...")
        exit(1)
    
    domain_url_html = warc_to_text(warc_file=warc_files[0]) # {example.com: [(url1, html1), (url2, html2)], anotherdomain.com: [(url3, html3)]]}
    
    ################################################################################
    # Step 3 - Generate YARA-X signature
    #    - HTML content extracted from the WARC file is fed into Gemini
    #    - Gemini creates YARA-X signatures based on the HTML content examples from the WARC
    ################################################################################
    logging.info(f"\nSTEP 3 - Generate YARA-X signature using Gemini based on HTML contents...")
    # Get latest genai model info and pricing data
    update_prices = UpdatePrices()
    update_prices.start(wait=True)

    # Determine domains from URLs that the YARA-X signatures will be built for and ensure only those domains HTML goes to Gemini for YARA-X signature creation
    registered_domains = set()
    for url in BRAND_MONITORING_URLS:
        registered_domain = get_registered_domain(url)
        registered_domains.add(registered_domain)

    for domain in domain_url_html.keys():
        if domain in registered_domains:
            send_to_gemini = json.dumps(domain_url_html[domain])  # {"example.com":[["url1","html1"],["url2","html2"]],"anotherdomain.com":[["url3","html3"]]}
            pricing_summary = check_pricing(gemini_client, send_to_gemini, HIGH_COST_MODULE_NAME)
            print(f"A cost of {pricing_summary['total_price_usd']:.4f} USD estimated for this query. Total input tokens: {pricing_summary['input_tokens']}.")
            proceed = input("--> Type 'yes' to continue and run the model: ").strip().lower()
            if proceed != "yes":
                print("Next step cancelled by user. Gemini was not called. Exiting...")
                exit(1)
            else:
                yara_signature = fetch_html_with_gemini(client=gemini_client, content=send_to_gemini, model_name=LOW_COST_MODULE_NAME)
                yara_signature = extract_text(yara_signature)

                # Save the YARA-X signature to a file for later use
                logging.info(f"Saving the generated YARA-X signature to file `{YARA_X_SIGNATURE_FILE}`...")
                with open(YARA_X_SIGNATURE_FILE, "w", encoding="utf-8") as f:
                    f.write(yara_signature)

    ################################################################################
    # Step 4 - Validation of YARA-X signature
    #    - Test if it compiles, then test against HTML, then test against WARC
    #
    ################################################################################
    logging.info(f"\nSTEP 4 - Validating YARA-X signature against HTML and WARC file...")
    # Read in saved YARA-X signature from file test_signature.yara
    #with open(YARA_X_SIGNATURE_FILE, "r", encoding="utf-8") as file:
    #    yara_signature = file.read()

    # Test compile the YARA-X signature to ensure it is valid YARA-X syntax.
    valiation = validate_yara_rule(input_rule=yara_signature)
    if not valiation:
        logging.critical("YARA-X signature failed to compile. This means there is something wrong with the signature generated by Gemini. Please investigate the signature generation process and the generated signature. Exiting...")
        exit(1)

    # Check the YARA-X signature against the input HTML   
    for domain in domain_url_html.keys():
        if domain in registered_domains:
            for url, html in domain_url_html[domain]:
                rule_match = test_yara_rules_on_text(input_rule=yara_signature, input_text=html)
                if rule_match[0]: # match
                    print(f"URL: {url} - YARA-X matches! Matching rule IDs: {rule_match[1]}")
                else:
                    logging.critical(f"URL: {url} - YARA-X does NOT match. This is a problem because the signature should match on the HTML from the WARC which is what the signature was built from. If it does not match, then there is likely an issue with the signature creation process. Exiting...")
                    exit(1)

    # Check if the YARA-X signature matches the WARC
    for warc_file in warc_files:
        results = yara_scan_warc(warc_file=warc_file, input_rule=yara_signature) # input_text is not used in the current implementation of yara_scan_warc but is left here for future use when we want to also test against extracted text files instead of just WARCs
        logging.info(f"YARA-X scan of WARC file {warc_file} completed. Number of matches found: {len(results)}. Saving results to {SCAN_RESULTS_FILE}...")
        if results:
            with open(SCAN_RESULTS_FILE, "a", encoding="utf-8") as f: # notice append mode
                f.write(json.dumps(results) + "\n") #ndjson

    ################################################################################
    # Bonus Points 
    #  - Perform more validation by testing the YARA-X signature against a larger crawl of the domain and related domains. 
    #  - Goal is to see if it matches on similar webpages and does not match on unrelated webpages. 
    ################################################################################
    # Read in saved YARA-X signature from file test_signature.yara
    with open(YARA_X_SIGNATURE_FILE, "r", encoding="utf-8") as file:
        yara_signature = file.read()
    
    print(f"\n\nWould you like to expand YARA-X rule validation? This involves using Google Gemini (low cost module) to automatically create a list of 50 URLs that are similar in type to the requested URLs, 50 that are unrelated, and 20 that are from the same domain.")
    proceed = input("--> Type 'yes' to continue ").strip().lower()
    if proceed != "yes":
        print("Next step cancelled by user. Gemini was not called.")
        print(f"All YARA-X matches can be found at {SCAN_RESULTS_FILE}. Exiting...")
        exit(1)
    
    logging.info(f"\nBonus Points - Generating expanded list of URLs to use for validation (via Gemini API)...")
    response = generate_url_list(client=gemini_client, content=BRAND_MONITORING_URLS, model_name=LOW_COST_MODULE_NAME) # dict
    url_response = extract_text(response) # dict with keys top_related_urls, top_same_domain, and top_unrelated_urls
    
    try:
        url_response =  json.loads(url_response) 
    except json.JSONDecodeError as e: # Gemini did not do a good job. BAD GEMINI! BAD!
        logging.critical(f"Failed to parse Gemini response as JSON: {e}")
        logging.critical(f"Raw Gemini response content: {extract_text(response)}")
        exit(1)
    
    top_same_domain = url_response.get("top_same_domain", [])
    top_related_urls = url_response.get("top_related_urls", [])
    top_unrelated_urls = url_response.get("top_unrelated_urls", [])
    logging.info(f"Fetched {len(top_related_urls)} related URLs, {len(top_same_domain)} same domain URLs, and {len(top_unrelated_urls)} unrelated URLs.")
    
    logging.info(f"Crawling the top same domains...")
    collection_name = "top_same_domain"
    crawl_exit_code, crawl_percent_failed = run_browsertrix_crawl(urls=top_same_domain, output_dir=WARC_OUTPUT_DIR, collection_name=collection_name)
    if crawl_exit_code != 0 or crawl_percent_failed > 50:
        logging.error(f"Browsertrix crawl of {top_same_domain} failed. Please investigate the crawl failure. Exiting...")
        exit(1)
    
    warc_files = list((WARC_OUTPUT_DIR / "crawls" / "collections" / collection_name / "archive").glob("**/*.warc.gz")) # Should be many WARCs
    for warc_file in warc_files:
        results = yara_scan_warc(warc_file=warc_file, input_rule=yara_signature) # input_text is not used in the current implementation of yara_scan_warc but is left here for future use when we want to also test against extracted text files instead of just WARCs
        logging.info(f"YARA-X scan of WARC file {warc_file} completed. Number of matches found: {len(results)}. Saving results to {SCAN_RESULTS_FILE}...")
        if results:
            with open(SCAN_RESULTS_FILE, "a", encoding="utf-8") as f: # notice append mode
                f.write(json.dumps(results) + "\n") #ndjson
    
    collection_name = "top_related_urls"
    logging.info(f"Crawling the top related URLs...")
    crawl_exit_code, crawl_percent_failed = run_browsertrix_crawl(urls=top_related_urls, output_dir=WARC_OUTPUT_DIR, collection_name=collection_name)
    if crawl_exit_code != 0 or crawl_percent_failed > 50:
        logging.error(f"Browsertrix crawl of {top_related_urls} failed. Please investigate the crawl failure. Exiting...")
        exit(1)
    
    warc_files = list((WARC_OUTPUT_DIR / "crawls" / "collections" / collection_name / "archive").glob("**/*.warc.gz")) # Should be many WARCs
    for warc_file in warc_files:
        results = yara_scan_warc(warc_file=warc_file, input_rule=yara_signature) # input_text is not used in the current implementation of yara_scan_warc but is left here for future use when we want to also test against extracted text files instead of just WARCs
        logging.info(f"YARA-X scan of WARC file {warc_file} completed. Number of matches found: {len(results)}. Saving results to {SCAN_RESULTS_FILE}...")
        if results:
            with open(SCAN_RESULTS_FILE, "a", encoding="utf-8") as f: # notice append mode
                f.write(json.dumps(results) + "\n") #ndjson
    
    collection_name = "top_unrelated_urls"
    logging.info(f"Crawling the top unrelated URLs...")
    crawl_exit_code, crawl_percent_failed = run_browsertrix_crawl(urls=top_unrelated_urls, output_dir=WARC_OUTPUT_DIR, collection_name=collection_name)
    if crawl_exit_code != 0 or crawl_percent_failed > 50:
        logging.error(f"Browsertrix crawl of {top_unrelated_urls} failed. Please investigate the crawl failure. Exiting...")
        exit(1)
    
    warc_files = list((WARC_OUTPUT_DIR / "crawls" / "collections" / collection_name / "archive").glob("**/*.warc.gz")) # Should be many WARCs
    for warc_file in warc_files:
        results = yara_scan_warc(warc_file=warc_file, input_rule=yara_signature) # input_text is not used in the current implementation of yara_scan_warc but is left here for future use when we want to also test against extracted text files instead of just WARCs
        logging.info(f"YARA-X scan of WARC file {warc_file} completed. Number of matches found: {len(results)}. Saving results to {SCAN_RESULTS_FILE}...")
        if results:
            with open(SCAN_RESULTS_FILE, "a", encoding="utf-8") as f: # notice append mode
                f.write(json.dumps(results) + "\n") #ndjson
    
    logging.info(f"\nAll additional crawling and YARA-X scanning validation is now complete. All YARA-X matches can be found at {SCAN_RESULTS_FILE}.")

if __name__ == '__main__':
    main()
