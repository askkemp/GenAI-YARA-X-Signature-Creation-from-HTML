
# Generate YARA-X Rules From Crawled HTML

## Introduction
This Python script uses Google Gemini to generate YARA-X brand monitoring focused rules that can be used to scan [Web ARChive (WARC)](https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1-annotated/ "Web ARChive (WARC)") files. The idea is to use these YARA-X rules to scan a large repository of WARC files like the monthly crawl of ~2.3 billion pages from the [Common Crawl](https://commoncrawl.org/get-started "Common Crawl") project. By scanning the Common Crawl project, you are essentially scanning the entire internet with the YARA-X rule which means you will be able to find websites that are infringing on the brand. A demonstration of how to scan the entire Common Crawl project using AWS is documented in my [other repository](https://github.com/askkemp/YARA-X-Scan-Web-ARChive-WARC/blob/main/README.md#scenerio-4-use-aws-to-mass-scan-warcs-from-common-crawl-recommended). 

The four generated YARA-X rules focus on four areas:
1. Notable sentences within the page that reflect on the brand (e.g. brand phrases, trademarks)
2. Tag and telemetry identifiers (e.g. Google Tag Manager ID, Meta/Facebook Pixel ID)
3. Ownership verification meta tags (e.g. google-site-verification)
4. Unique HTML/JS features of the HTML/JS code on the page

The YARA-X rules are generated based on the HTML collected from a headless browser running in Docker called [Browsertrix-crawler](https://github.com/webrecorder/browsertrix-crawler).

**Please note this is a prototype.**

### Workflow
Given a list of desired brand monitoring URLs, this script will generate WARCs, extract the HTML, submit it to Google Gemini for YARA-X rule creation, and then validate the rule.

1. User provides a list of URLs they would like brand monitoring YARA-X signatures created for.
2. URLs are crawled with headless browser in Docker called Browsertrix.
2. HTML content is extracted from the generated WARC files.
3. Extracted HTML is sent to Gemini to generate YARA-X signatures. It pauses to inform the user an estimated cost to run the model before continuing.
4. The returned YARA-X signature is validated to determine if it compiles, if it matches on the HTML, and if it matches on the original WARC.
5. (bonus points) The original list of URLs is sent to Google Gemini to generate a list of related, similar, and unrelated URLs. Each are then downloaded into a WARC, and then scanned with the YARA-X rule to validate its fidelity.

The script produces these files:
- Crawl artifacts in `WARC_FILES/crawls/collections/<collection_name>/...`
- Generated YARA-X rule file: `genai_signature.yarax`
- YARA-X scan results of the WARCs: `scan_results.ndjson`

## Requirements
- Python 3.11+
- Docker
- [Browsertrix-crawler](https://github.com/webrecorder/browsertrix-crawler) Docker image
- User running the script must be allowed to access Docker daemon (e.g. `sudo usermod -a -G docker $USER`)
- Google GenAI API key (paid)

## Usage
### Step 1: Edit constants within the script
At the top of `generate_yarax_rules.py` is a `# CONFIGURE ME` section which requires:

- `GOOGLE_GENAI_API_KEY`: your Google Gemini API key (paid)
- `BRAND_MONITORING_URLS`: List of URLs that will be used to generate YARA-X rules (same brand/domain family is recommended)

### Step 2: Install requirements
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
docker pull webrecorder/browsertrix-crawler
```

### Step 3: Run it!
```bash
$ python generate_yarax_rules.py

Pre-flight checks passed!
The following URLs will be used to generate a YARA-X signature for brand monitoring: ['https://www.war.gov/', 'https://www.war.gov/About/', 'https://www.war.gov/Spotlights/Value-of-Service/']

STEP 1 - Generating WARC for the URLs to be brand monitored...
Starting Docker Browsertrix crawl for 3 URLs. Output folder: WARC_FILES/crawls/urls_to_monitor
Crawl finished: https://www.war.gov/
Crawl finished: https://www.war.gov/About/
Crawl finished: https://www.war.gov/Spotlights/Value-of-Service/
Crawl overall statistics: {'crawled': 3, 'total': 3, 'pending': 0, 'failed': 0, 'limit': {'max': 0, 'hit': False}, 'pendingPages': []}

STEP 2 - Extracting HTML content from WARC file...
Extracted HTML content for 4 pages across 2 unique domains from WARC_FILES/crawls/collections/urls_to_monitor/archive/rec-f18d04b66e88-urls_to_monitor-20260319162831386-0.warc.gz

STEP 3 - Generate YARA-X signature using Gemini based on HTML contents...
A cost of 0.9177 USD estimated for this query. Total input tokens: 224916.
--> Type 'yes' to continue and run the model: yes
Saving the generated YARA-X signature to file `genai_signature.yarax`...

STEP 4 - Validating YARA-X signature against HTML and WARC file...
YARA-X rules compiled successfully
URL: https://www.war.gov/ - YARA-X matches! Matching rule IDs: ['war_gov_readable_words', 'war_gov_tag_identifiers', 'war_gov_ownership_verification', 'war_gov_unique_html_features']
URL: https://www.war.gov/About/ - YARA-X matches! Matching rule IDs: ['war_gov_readable_words', 'war_gov_tag_identifiers', 'war_gov_unique_html_features']
URL: https://www.war.gov/Spotlights/Value-of-Service/ - YARA-X matches! Matching rule IDs: ['war_gov_tag_identifiers', 'war_gov_unique_html_features']
YARA-X scan of WARC file WARC_FILES/crawls/collections/urls_to_monitor/archive/rec-f18d04b66e88-urls_to_monitor-20260319162831386-0.warc.gz completed. Number of matches found: 9. Saving results to scan_results.ndjson...


Would you like to expand YARA-X rule validation? This involves using Google Gemini (low cost module) to automatically create a list of 50 URLs that are similar in type to the requested URLs, 50 that are unrelated, and 20 that are from the same domain.
--> Type 'yes' to continue yes

Bonus Points - Generating expanded list of URLs to use for validation (via Gemini API)...
Fetched 50 related URLs, 30 same domain URLs, and 50 unrelated URLs.
Crawling the top same domains...
Starting Docker Browsertrix crawl for 30 URLs. Output folder: WARC_FILES/crawls/top_same_domain
Crawl finished: https://www.war.gov/careers/
Crawl finished: https://www.war.gov/news/
Crawl finished: https://www.war.gov/accessibility/
...
Crawl overall statistics: {'crawled': 15, 'total': 30, 'pending': 0, 'failed': 15, 'limit': {'max': 0, 'hit': False}, 'pendingPages': []}
YARA-X scan of WARC file WARC_FILES/crawls/collections/top_same_domain/archive/rec-a641eae29132-top_same_domain-20260319162946048-0.warc.gz completed. Number of matches found: 18. Saving results to scan_results.ndjson...

Crawling the top related URLs...
Starting Docker Browsertrix crawl for 50 URLs. Output folder: WARC_FILES/crawls/top_related_urls
Crawl finished: https://www.defense.gov/
Crawl finished: https://www.army.mil/
Crawl finished: https://www.navy.mil/
...
Crawl overall statistics: {'crawled': 49, 'total': 50, 'pending': 0, 'failed': 1, 'limit': {'max': 0, 'hit': False}, 'pendingPages': []}
YARA-X scan of WARC file WARC_FILES/crawls/collections/top_related_urls/archive/rec-c7ec88a52bfa-top_related_urls-20260319163515922-0.warc.gz completed. Number of matches found: 4. Saving results to scan_results.ndjson...
YARA-X scan of WARC file WARC_FILES/crawls/collections/top_related_urls/archive/rec-c7ec88a52bfa-top_related_urls-20260319163115261-0.warc.gz completed. Number of matches found: 5. Saving results to scan_results.ndjson...

Crawling the top unrelated URLs...
Starting Docker Browsertrix crawl for 50 URLs. Output folder: WARC_FILES/crawls/top_unrelated_urls
Crawl finished: https://www.cookinglight.com/
Crawl finished: https://www.lego.com/
Crawl finished: https://www.zillow.com/
Crawl finished: https://www.disney.com/
...
Crawl overall statistics: {'crawled': 35, 'total': 36, 'pending': 0, 'failed': 1, 'limit': {'max': 0, 'hit': False}, 'pendingPages': []}
YARA-X scan of WARC file WARC_FILES/crawls/collections/top_unrelated_urls/archive/rec-35757572ca44-top_unrelated_urls-20260319165340376-0.warc.gz completed. Number of matches found: 0. Saving results to scan_results.ndjson...
YARA-X scan of WARC file WARC_FILES/crawls/collections/top_unrelated_urls/archive/rec-35757572ca44-top_unrelated_urls-20260319164228770-0.warc.gz completed. Number of matches found: 0. Saving results to scan_results.ndjson...

All additional crawling and YARA-X scanning validation is now complete. All YARA-X matches can be found at scan_results.ndjson.
```

### Step 4: Understanding the Output

The Google Gemini created YARA-X signature is created at `genai_signature.yarax`. Here is an example of its creation:

```bash
rule war_gov_readable_words {
    meta:
        domain = "war.gov"
        description = "Detects war.gov by checking for unique brand phrases and mission statements."
    strings:
        $s1 = "U.S. Department of War"
        $s2 = "America's largest government agency"
        $s3 = "provide the military forces needed to deter war"
        $s4 = "ensure our nation's security"
        $s5 = "Official websites use .gov"
        $s6 = "Secure .gov websites use HTTPS"
        $s7 = "Department of War is America's largest government agency"
    condition:
        5 of them
}

rule war_gov_tag_identifiers {
    meta:
        domain = "war.gov"
        description = "Detects war.gov via unique analytics and tracking identifiers."
    strings:
        $ga = "pga4=G-SB6KFHKWNW"
        $dvids_api = "key-68bb60d16b35e"
    condition:
        all of them
}

rule war_gov_ownership_verification {
    meta:
        domain = "war.gov"
        description = "Detects war.gov via specific site verification tags."
    strings:
        $v1 = "<meta name=\"google-site-verification\" content=\"lcQS9MV5xMisePG-IKaE9ZNfyaMJ9qVLemvuOy3PRFQ\""
        $v2 = "<meta name=\"msvalidate.01\" content=\"235F405786FAB553A2A8EF5FD13514A7\""
        $v3 = "<meta name=\"msvalidate.01\" content=\"4BAA65E882EAE4403F4FAB3443D34664\""
        $v4 = "<meta name=\"google-site-verification\" content=\"nfNn_S6Ki0r3N9JWs7xQ6wLvXG7aNfgm5yKHnZMobhU\""
    condition:
        2 of them
}

rule war_gov_unique_html_features {
    meta:
        domain = "war.gov"
        description = "Detects war.gov by checking for specific UI patterns and unique JS skin variables."
    strings:
        $js = "skinvars = {\"SiteName\":\"U.S. Department of War\",\"SiteShortName\":\"Defense.gov\""
        $css = "href=\"/Portals/1/Page-Assets/home/code-push-fixes-homepage-new2.css\""
        $icon = "Logo for U.S. Department of War"
        $banner = "class=\"header_banner_flag\""
    condition:
        3 of them
}
```

The created YARA-X rule is saved by default to `genai_signature.yarax`. The script validated it against the original URLs as working correctly and if you chose the bonus option, it ran it against three additional sets of data. The below excerpt from a full run shows that after collecting the top 50 unrelated URLs (of which 49 where successful) and scaning them the created YARA-X rule, there were zero matches. This is what should happen if the YARA-X signature is unique to the original requested URLs.

```bash
Crawling the top unrelated URLs...
...
Crawl overall statistics: {'crawled': 49, 'total': 50, 'pending': 0, 'failed': 1, 'limit': {'max': 0, 'hit': False}, 'pendingPages': []}
Number of matches found: 0.
```

The matches found for all of the WARC YARA-X scans are saved by default to `scan_results.ndjson` and using `jq` is an great way to make the results easy to read.

```bash
jq -c '.[] | {warc_record_target_uri, yara_rule_identifier}'
{"warc_record_target_uri":"https://www.whitehouse.gov/","yara_rule_identifier":"whitehouse_gov_readable_words"}
{"warc_record_target_uri":"https://www.whitehouse.gov/","yara_rule_identifier":"whitehouse_gov_tag_identifiers"}
{"warc_record_target_uri":"https://www.whitehouse.gov/","yara_rule_identifier":"whitehouse_gov_unique_html_features"}
{"warc_record_target_uri":"https://www.whitehouse.gov/government/","yara_rule_identifier":"whitehouse_gov_tag_identifiers"}
{"warc_record_target_uri":"https://www.whitehouse.gov/government/","yara_rule_identifier":"whitehouse_gov_unique_html_features"}
{"warc_record_target_uri":"https://www.whitehouse.gov/news/","yara_rule_identifier":"whitehouse_gov_tag_identifiers"}
{"warc_record_target_uri":"https://www.whitehouse.gov/news/","yara_rule_identifier":"whitehouse_gov_unique_html_features"}
{"warc_record_target_uri":"https://www.whitehouse.gov/administration/","yara_rule_identifier":"whitehouse_gov_tag_identifiers"}
{"warc_record_target_uri":"https://www.whitehouse.gov/administration/","yara_rule_identifier":"whitehouse_gov_unique_html_features"}
```
Or simply use `jq` to show all of the keys and values:

```bash
  {
    "warc_file_name": "rec-c7ec88a52bfa-top_related_urls-20260319163115261-0.warc.gz",
    "warc_file_path": "WARC_FILES/crawls/collections/top_related_urls/archive/rec-c7ec88a52bfa-top_related_urls-20260319163115261-0.warc.gz",
    "warc_record_offset": 1636,
    "warc_record_target_uri": "https://www.war.gov/",
    "warc_record_id": "<urn:uuid:f7d8623a-0313-4c7d-93c9-3fcde24cb434>",
    "warc_record_content_type": "application/http; msgtype=response",
    "yara_rule_identifier": "war_gov_readable_words",
    "yara_rule_namespace": "default",
    "yara_rule_tags": [],
    "yara_rule_metadata": {
      "domain": "war.gov",
      "description": "Detects war.gov by checking for unique brand phrases and mission statements."
    },
    "yara_rule_matching_content": [
      "Department of War is America's largest government agency"
    ],
    "yara_rule_matching_content_superset": [
      "ption\" content=\"The Department of War is America's largest government agency. With our military "
    ]
  },
```
