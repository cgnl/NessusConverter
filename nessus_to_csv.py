#!/usr/bin/env python3

import xml.etree.ElementTree as etree
import csv
import os
import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(description="Converts Nessus files into a CSV file with semicolon delimiters.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--input_dir", type=str, help="Directory containing the Nessus files")
    group.add_argument("-f", "--input_file", type=str, help="Path to a single Nessus file")
    parser.add_argument("-o", "--output_file", type=str, required=True, help="The path to the output CSV file")
    return parser.parse_args()

def process_nessus_file(file_path, csvwriter):
    tree = etree.parse(file_path)
    root = tree.getroot()
    
    # Extracting the "Report name" as "Scan Group"
    scan_group = root.find(".//Report").attrib.get('name') if root.find(".//Report") is not None else 'N/A'

    for reportHost in root.iter('ReportHost'):
        ip = reportHost.get('name')

        for reportItem in reportHost.iter('ReportItem'):
            risk_factor = reportItem.find('risk_factor')
            if risk_factor is not None:  # Only process if risk_factor is not None
                severity = risk_factor.text
                cvss_score = reportItem.find('cvss3_base_score').text if reportItem.find('cvss3_base_score') is not None else 'N/A'
                vpr_score = reportItem.find('vpr_score').text if reportItem.find('vpr_score') is not None else 'N/A'
                plugin_id = reportItem.get('pluginID')
                plugin_name = reportItem.get('pluginName')
                port = reportItem.get('port')
                
                cves = reportItem.findall('cve')
                cve_list = ', '.join(cve.text for cve in cves) if cves else 'N/A'

                data_row = [scan_group, ip, port, cve_list, severity, cvss_score, vpr_score, plugin_id, plugin_name]
                csvwriter.writerow(data_row)

def main(input_dir, input_file, output_file):
    with open(output_file, 'w', newline='') as nessus_file:
        csvwriter = csv.writer(nessus_file, delimiter=';')
        headers = ['Scan Group', 'IP Address', 'Port', 'CVEs', 'Severity', 'CVSS Score', 'VPR Score', 'Plugin ID', 'Name']
        csvwriter.writerow(headers)

        if input_dir:
            for fileName in os.listdir(input_dir):
                if fileName.endswith(".nessus"):
                    fullPath = os.path.join(input_dir, fileName)
                    process_nessus_file(fullPath, csvwriter)
        elif input_file:
            process_nessus_file(input_file, csvwriter)

if __name__ == "__main__":
    args = parse_arguments()
    main(args.input_dir, args.input_file, args.output_file)
