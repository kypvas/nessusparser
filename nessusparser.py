import argparse
import csv
import re
import os

def parse_nessus_html(html_file, output_csv):
    """
    Parse Nessus HTML report with the exact structure shown in the sample.
    """
    print(f"Parsing {html_file}...")

    # Read the HTML file
    with open(html_file, 'r', encoding='utf-8') as f:
        html_content = f.read()

    print(f"Read {len(html_content)} characters from file")

    # Find the starting point - after Vulnerabilities by Host section
    start_marker = '<h6 xmlns="" id="idp' in html_content
    if not start_marker:
        print("Could not find 'Vulnerabilities by Host' section")
        return False

    # Find all vulnerability plugin section blocks - use finditer to get positions
    plugin_pattern = re.compile(r'<div xmlns="" id="(idp\d+)" style="[^"]*background: #[a-z0-9]{6}[^"]*"[^>]*onclick="toggleSection\(\'(idp\d+-container)\'\);"[^>]*>(\d+)\s*-\s*([^<]+)<div', re.DOTALL)

    plugin_matches = list(plugin_pattern.finditer(html_content))
    print(f"Found {len(plugin_matches)} plugin sections")

    # Create a global mapping of current host by scanning the entire document
    global_hosts = {}
    host_sections = re.finditer(r'<div xmlns="" id="idp\d+" style="font-size: 22px[^>]*>([0-9.]+)<div class="clear"></div>\s*</div>', html_content)
    for section in host_sections:
        host_ip = section.group(1)
        section_pos = section.start()
        global_hosts[section_pos] = host_ip

    # Sort host positions for binary search later
    host_positions = sorted(global_hosts.keys())
    print(f"Found {len(host_positions)} host sections")

    results = []

    for match in plugin_matches:
        try:
            # Get plugin info directly from match
            div_id = match.group(1)
            container_id = match.group(2)
            plugin_id = match.group(3)
            name = match.group(4)
            plugin_pos = match.start()

            # Find the nearest host section above this plugin using binary search
            host_idx = 0
            while host_idx < len(host_positions) and host_positions[host_idx] < plugin_pos:
                host_idx += 1

            if host_idx > 0:
                current_host = global_hosts[host_positions[host_idx-1]]
            else:
                current_host = ""

            # Find the container content using the container_id from the match
            container_start = html_content.find(f'id="{container_id}"', plugin_pos)
            if container_start < 0:
                continue

            container_end_marker = html_content.find('<div xmlns="" id="idp', container_start + 10)
            if container_end_marker < 0:
                container_end_marker = len(html_content)

            container_content = html_content[container_start:container_end_marker]
            
            # Extract host IP directly from the container - this is most reliable
            host = current_host  # Default
            host_pattern = re.compile(r'<td class="#ffffff">IP:</td>\s*<td class="#ffffff">([^<]+)</td>')
            host_match = host_pattern.search(container_content)
            if host_match:
                host = host_match.group(1).strip()
            
            # Extract fields
            synopsis = extract_field(container_content, "Synopsis")
            description = extract_field(container_content, "Description")
            solution = extract_field(container_content, "Solution")
            risk = extract_field(container_content, "Risk Factor")
            # HTML uses "CVSS Base Score" not "CVSS v2.0 Base Score"
            cvss_v2 = extract_field(container_content, "CVSS Base Score")
            cvss_v3 = extract_field(container_content, "CVSS v3.0 Base Score")

            # Extract port and protocol - handle both 2-part (tcp/22) and 3-part (tcp/22/ssh) formats
            protocol = ""
            port = ""
            # Try 3-part format first: protocol/port/service
            h2_pattern_3 = re.compile(r'<h2>([a-z]+)/(\d+)/([^<]+)</h2>')
            h2_match = h2_pattern_3.search(container_content)
            if h2_match:
                protocol = h2_match.group(1)
                port = h2_match.group(2)
            else:
                # Try 2-part format: protocol/port
                h2_pattern_2 = re.compile(r'<h2>([a-z]+)/(\d+)</h2>')
                h2_match = h2_pattern_2.search(container_content)
                if h2_match:
                    protocol = h2_match.group(1)
                    port = h2_match.group(2)
            
            # Extract exploitability with proper true/false values
            metasploit = "false"
            core_impact = "false"
            canvas = "false"
            
            exploit_pattern = re.compile(r'<div class="details-header">Exploitable With<.*?</div>\s*<div[^>]*>(.*?)<div class="clear">', re.DOTALL)
            exploit_match = exploit_pattern.search(container_content)
            if exploit_match:
                exploit_text = exploit_match.group(1).lower()
                
                # Look for (true) patterns
                metasploit = "true" if "metasploit (true)" in exploit_text else "false"
                core_impact = "true" if "core impact (true)" in exploit_text else "false"
                canvas = "true" if "canvas (true)" in exploit_text else "false"
            
            # Extract plugin output
            plugin_output = ""
            output_pattern = re.compile(r'<div class="details-header">Plugin Output<.*?</div>.*?<div style="[^"]*background: #eee[^"]*">(.*?)<div class="clear">', re.DOTALL)
            output_matches = output_pattern.findall(container_content)
            
            if output_matches:
                plugin_output = ' '.join([clean_html(m) for m in output_matches])
            
            # Extract CVE
            cve = ""
            cve_pattern = re.compile(r'<td class="#ffffff">CVE</td>\s*<td class="#ffffff"><a[^>]*>([^<]+)</a></td>')
            cve_match = cve_pattern.search(container_content)
            if cve_match:
                cve = cve_match.group(1).strip()
            
            # Extract See Also
            see_also = ""
            see_also_pattern = re.compile(r'<div class="details-header">See Also<.*?</div>.*?<table.*?>(.*?)</table>', re.DOTALL)
            see_also_match = see_also_pattern.search(container_content)
            if see_also_match:
                see_also_links = re.findall(r'<a[^>]*>([^<]+)</a>', see_also_match.group(1))
                if see_also_links:
                    see_also = "; ".join(see_also_links)
            
            # Add to results
            results.append([
                plugin_id,
                cve,
                cvss_v2,
                risk,
                host,
                protocol,
                port,
                name.strip(),
                synopsis,
                description,
                solution,
                see_also,
                plugin_output,
                cvss_v3,
                metasploit,
                core_impact,
                canvas
            ])
            
            if len(results) % 100 == 0:
                print(f"Processed {len(results)} vulnerabilities...")
        
        except Exception as e:
            print(f"Error processing plugin {plugin_id}: {str(e)}")
            continue
    
    print(f"Extracted data for {len(results)} vulnerabilities")
    
    if not results:
        print("No results to write!")
        return False
    
    # Define column headers
    columns = [
        "Plugin ID",
        "CVE",
        "CVSS v2.0 Base Score",
        "Risk",
        "Host",
        "Protocol",
        "Port",
        "Name",
        "Synopsis",
        "Description",
        "Solution",
        "See Also",
        "Plugin Output",
        "CVSS v3.0 Base Score",
        "Metasploit",
        "Core Impact",
        "CANVAS"
    ]
    
    # Write to CSV
    print(f"Writing {len(results)} entries to {output_csv}...")
    with open(output_csv, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(columns)
        writer.writerows(results)
    
    print(f"CSV file created: {output_csv}")
    print(f"File size: {os.path.getsize(output_csv) / (1024 * 1024):.2f} MB")
    
    return True

def extract_field(content, field_name):
    """Extract a field value using the exact pattern in the sample"""
    pattern = re.compile(r'<div class="details-header">' + re.escape(field_name) + r'<div class="clear"></div>\s*</div>\s*<div[^>]*>(.*?)<div class="clear"></div>', re.DOTALL)
    match = pattern.search(content)
    if match:
        return clean_html(match.group(1))
    return ""

def clean_html(html):
    """Clean HTML text by removing tags and normalizing whitespace"""
    if not html:
        return ""
    
    # Remove HTML tags
    text = re.sub(r'<[^>]*>', ' ', html)
    
    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    
    return text

def main():
    parser = argparse.ArgumentParser(description="Direct Nessus HTML Parser")
    parser.add_argument("--input", required=True, help="Path to the Nessus HTML file")
    parser.add_argument("--output", required=True, help="Path to the output CSV file")
    args = parser.parse_args()
    
    parse_nessus_html(args.input, args.output)

if __name__ == "__main__":
    main()