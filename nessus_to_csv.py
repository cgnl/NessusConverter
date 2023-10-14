#!/usr/bin/env python3

import xml.etree.ElementTree as etree
import csv
import os
import argparse

def parse_arguments():
	parser = argparse.ArgumentParser(description="Converts Nessus files into a CSV file.")
	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument("-i", "--input_dir", type=str, help="Directory containing the Nessus files")
	group.add_argument("-f", "--input_file", type=str, help="Path to a single Nessus file")
	parser.add_argument("-o", "--output_file", type=str, required=True, help="The path to the output CSV file")
	parser.add_argument("-p", "--product", type=str, required=True, help="Product name to include in the CSV")
	return parser.parse_args()
	
def process_nessus_file(file_path, csvwriter, product_name):
    tree = etree.parse(file_path)
    root = tree.getroot()

    for reportHost in root.iter('ReportHost'):
        ip = reportHost.get('name')

        for reportItem in reportHost.iter('ReportItem'):
            vuln = reportItem.get('pluginName')
            severity = reportItem.get('severity')
            port = reportItem.get('port')  
            # Extracting CVE information
            cves = reportItem.findall('cve')
            cve_list = ', '.join(cve.text for cve in cves) if cves else 'N/A'
            data = [product_name, ip, port, vuln, severity, cve_list]  # Including product name in the data row
            csvwriter.writerow(data)

def main(input_dir, input_file, output_file, product_name):
    with open(output_file, 'w', newline='') as nessus_file:
        csvwriter = csv.writer(nessus_file)
        csvwriter.writerow(['Product', 'IP Address', 'Port', 'Vulnerability', 'Severity', 'CVEs'])

        if input_dir:
            for fileName in os.listdir(input_dir):
                if fileName.endswith(".nessus"):
                    fullPath = os.path.join(input_dir, fileName)
                    process_nessus_file(fullPath, csvwriter, product_name)
        elif input_file:
            process_nessus_file(input_file, csvwriter, product_name)

if __name__ == "__main__":
    args = parse_arguments()
    main(args.input_dir, args.input_file, args.output_file, args.product)
