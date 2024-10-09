# Original script: https://github.com/Immersive-Labs-Sec/msrc-api
# Script modified by Robinzor
# Licensed under the MIT License: https://opensource.org/licenses/MIT

import argparse
import requests
import re
import datetime
import os

base_url = 'https://api.msrc.microsoft.com/cvrf/v2.0/'
headers = {'Accept': 'application/json'}
vuln_types = [
    'Elevation of Privilege',
    'Security Feature Bypass',
    'Remote Code Execution',
    'Information Disclosure',
    'Denial of Service',
    'Spoofing',
    'Edge - Chromium'
]

def get_second_tuesday(year, month):
    # Start at the first day of the month
    d = datetime.date(year, month, 1)
    # Find the first Tuesday (weekday 1)
    first_tuesday = d + datetime.timedelta(days=(1 - d.weekday() + 7) % 7)
    # Add one week to get the second Tuesday
    second_tuesday = first_tuesday + datetime.timedelta(weeks=1)
    return second_tuesday

def count_type(search_type, all_vulns):
    counter = 0
    for vuln in all_vulns:
        for threat in vuln['Threats']:
            if threat['Type'] == 0:
                if search_type == "Edge - Chromium":
                    if threat['ProductID'][0] == '11655':
                        counter += 1
                        break
                elif threat['Description'].get('Value') == search_type:
                    if threat['ProductID'][0] == '11655':
                        # Do not double count Chromium Vulns
                        break
                    counter += 1
                    break
    return counter

def count_exploited(all_vulns):
    counter = 0
    cves = []
    for vuln in all_vulns:
        cvss_score = 0.0
        cvss_sets = vuln.get('CVSSScoreSets', [])
        if len(cvss_sets) > 0:
            cvss_score = cvss_sets[0].get('BaseScore', 0.0)
        for threat in vuln['Threats']:
            if threat['Type'] == 1:
                description = threat['Description']['Value']
                if 'Exploited:Yes' in description:
                    counter += 1
                    cves.append(f'{vuln["CVE"]} - {cvss_score} - {vuln["Title"]["Value"]}')
                    break
    return {'counter': counter, 'cves': cves}

def exploitation_likely(all_vulns):
    counter = 0
    cves = []
    for vuln in all_vulns:
        for threat in vuln['Threats']:
            if threat['Type'] == 1:
                description = threat['Description']['Value']
                if 'Exploitation More Likely'.lower() in description.lower():
                    counter += 1
                    cves.append(f'{vuln["CVE"]} -- {vuln["Title"]["Value"]}')
                    break
    return {'counter': counter, 'cves': cves}

"""
Check the date format is yyyy-mmm.
"""
def check_data_format(date_string):
    date_pattern = '\\d{4}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)'
    if re.match(date_pattern, date_string, re.IGNORECASE):
        return True

def print_header(title):
    print("[+] Microsoft Patch Tuesday Stats")
    print(f"[+] {title}")

def main():
    parser = argparse.ArgumentParser(description='Read vulnerability stats for a patch Tuesday release.')
    parser.add_argument('security_update', help="Date string for the report query in format YYYY-mmm")
    parser.add_argument('--force', action='store_true', help="Force execution regardless of the date")
    args = parser.parse_args()
    today = datetime.date.today()
    second_tuesday = get_second_tuesday(today.year, today.month)

    # Check if today is the second Tuesday unless forced
    if not args.force and today != second_tuesday:
        print("[!] Today is not the second Tuesday of the month. Use --force to execute regardless of the date.")
        exit()

    run_patch_tuesday(args)

def run_patch_tuesday(args):
    if not check_data_format(args.security_update):
        print("[!] Invalid date format. Please use 'yyyy-mmm'")
        exit()

    # Get the list of all vulnerabilities
    get_sec_release = requests.get(f'{base_url}cvrf/{args.security_update}', headers=headers)

    if get_sec_release.status_code != 200:
        print(f"[!] That's a {get_sec_release.status_code} from MS. No release notes yet.")
        exit()

    release_json = get_sec_release.json()
    title = release_json.get('DocumentTitle', 'Release not found').get('Value')
    all_vulns = release_json.get('Vulnerability', [])
    len_vuln = len(all_vulns)
    output_directory = "history"
    filename = f"{args.security_update.replace('-', '_')}.txt"
    output_filename = os.path.join(output_directory, filename)

    with open(output_filename, 'w') as output_file:
        output_file.write("[+] Microsoft Patch Tuesday Stats\n")
        output_file.write(f"[+] {title}\n")
        output_file.write(f'[+] Found a total of {len_vuln} vulnerabilities\n')

        for vuln_type in vuln_types:
            count = count_type(vuln_type, all_vulns)
            output_file.write(f'  [-] {count} {vuln_type} Vulnerabilities\n')

        exploited = count_exploited(all_vulns)
        output_file.write(f'[+] Found {exploited["counter"]} exploited in the wild\n')
        for cve in exploited['cves']:
            output_file.write(f'  [-] {cve}\n')

        base_score = 8.0
        output_file.write('[+] Highest Rated Vulnerabilities\n')
        for vuln in all_vulns:
            title = vuln.get('Title', {'Value': 'Not Found'}).get('Value')
            cve_id = vuln.get('CVE', '')
            cvss_sets = vuln.get('CVSSScoreSets', [])
            if len(cvss_sets) > 0:
                cvss_score = cvss_sets[0].get('BaseScore', 0)
                if cvss_score >= base_score:
                    output_file.write(f'  [-] {cve_id} - {cvss_score} - {title}\n')

        exploitation = exploitation_likely(all_vulns)
        output_file.write(f'[+] Found {exploitation["counter"]} vulnerabilities more likely to be exploited\n')
        for cve in exploitation['cves']:
            output_file.write(f'  [-] {cve} - https://www.cve.org/CVERecord?id={cve.split()[0]}\n')

    print(f"Output saved to '{output_filename}'")

if __name__ == "__main__":
    main()
