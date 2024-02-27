# Nessus to CSV Converter

This Python script allows for the quick and efficient conversion of Nessus scan files (`.nessus`) to a more manageable CSV format. It's particularly useful for security professionals who need to parse and read Nessus files easily, providing the ability to specify either a directory of Nessus files or a single Nessus file for conversion. Additionally, users can specify a product name to be included in the CSV output, which adds context to the vulnerabilities listed.

## Features

- Convert multiple Nessus files in a directory or a single Nessus file to CSV format.
- Include a custom product name in the CSV output.
- The generated CSV file contains the following information:
    - Product Name
    - IP Address
    - Port
    - Vulnerability
    - Severity
    - CVEs

## Prerequisites

Before you begin, ensure you have met the following requirements:

- You have installed Python 3

## Installation

To install the Nessus to CSV Converter, follow these steps:

1. Clone this repository to your local machine
2. Navigate to the directory of the cloned repository.
3. Install the requirements by executing:
   ```bash
   pip3 install -r requirements.txt
   ```

## Usage

To use the Nessus to CSV Converter, follow these steps:

1. Open a terminal in the project's directory.
2. Use the following command structure to run the script:

```bash
python3 nessus_to_csv.py -i [input_directory] -o [output_file.csv] 
```
or

```bash
python3 nessus_to_csv.py -f [input_file.nessus] -o [output_file.csv] 
```
