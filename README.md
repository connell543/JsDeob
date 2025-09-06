[README.md](https://github.com/user-attachments/files/22184569/README.md)
JSDeob - JavaScript Deobfuscation Tool
JSDeob is a Python-based command-line tool designed to deobfuscate JavaScript code, primarily for malware analysis. It processes JavaScript and HTML files, extracting and simplifying obfuscated code by decoding string arrays, atob calls, escaped sequences, and optionally running code in a Node.js sandbox. It also supports YARA rule scanning and extracting Indicators of Compromise (IOCs) like URLs, IPs, and emails. Additionally, JSDeob can crawl websites to fetch JavaScript and HTML files for analysis.
Features

Deobfuscation: Decodes common JavaScript obfuscation techniques (string arrays, atob, hex/Unicode escapes).
Web Crawler: Fetches JavaScript and HTML files from URLs with interactive download prompts.
YARA Integration: Scans deobfuscated code for malware signatures (optional).
IOCs Extraction: Identifies URLs, IPs, emails, and suspicious functions.
Node.js Sandbox: Safely evaluates dynamic JavaScript code (optional).
Interactive CLI: User-friendly interface with command history and prompts.
Cross-Platform: Runs on Linux (developed on Kali), macOS, and Windows.

Installation
JSDeob was developed on Kali Linux but can be installed on any system with Python 3.8+. The tool is installed as a Python package, allowing you to run it with the jsdeob command.
Prerequisites

Python 3.8+: Ensure Python is installed (python3 --version).
pip: Python package manager (pip3 --version).
Node.js (optional): For sandbox mode (node --version).
YARA (optional): For YARA rule scanning (yara --version).

On Kali Linux, install prerequisites:
sudo apt update
sudo apt install python3 python3-pip nodejs

For YARA (optional):
sudo apt install yara
pip3 install yara-python

Installation Steps

Clone the Repository:
git clone https://github.com/connell543/jsdeob.git
cd jsdeob


Install the Package: JSDeob uses setup.py to install as a Python package, making the jsdeob command available globally.
pip3 install .

This installs dependencies (requests, beautifulsoup4, prompt_toolkit, colorama) and sets up the jsdeob command to run cli.py.

Verify Installation:
jsdeob --version

Output: JSDeob v1.1, Copyright 2024

Optional: Install YARA Support: If you plan to use YARA rules:
pip3 install yara-python


Optional: Install Node.js for Sandbox: If not already installed:

On Kali/Ubuntu: sudo apt install nodejs
On macOS (with Homebrew): brew install node
On Windows: Download from nodejs.org.



Directory Setup
JSDeob uses ~/jsdeob/input as the default input folder and output as the default output folder. Create these if they don't exist:
mkdir -p ~/jsdeob/input
mkdir -p output

Usage
Run jsdeob to start the interactive CLI:
jsdeob

This displays a banner and help message, then prompts for commands (jsdeob> ).
Command-Line Options
usage: jsdeob [-i INPUT_FOLDER] [-o OUTPUT_FOLDER] [options]

JSDeob - Quickly deobfuscate JavaScript files for malware analysis

options:
  -h, --help           show this help message and exit
  -i, --input INPUT    Input JS/HTML file or folder (default: '~/jsdeob/input')
  -o, --output OUTPUT  Output folder (default: 'output')
  -p, --passes PASSES  Number of deobfuscation passes (default: 3)
  -s, --sandbox        Enable Node.js sandbox for eval/Function
  -y, --yara YARA      Path to YARA rules file
  -v, --verbose        Verbose output
  --dry-run            Compute hashes only, do not write files
  --url, -u URL        URL to fetch JS/HTML from (e.g., www.example.com)
  --version            show program's version number and exit

Examples

Deobfuscate Files in Default Input Folder: Place JavaScript or HTML files in ~/jsdeob/input and run:
jsdeob

At the prompt, press Enter to use defaults:
jsdeob> 
Input path (default: ~/jsdeob/input): 
Output path (default: output): 

Output files (deobfuscated code, logs, IOCs) are saved to output/<filename>.

Deobfuscate a Specific File:
jsdeob -i ~/jsdeob/input/sample.js -o output --verbose


Crawl a Website: Fetch JavaScript/HTML from a URL, with prompts to download files:
jsdeob --url www.example.com

Example interaction:
Download https://www.example.com to /home/user/jsdeob/input/www_example_com/index.html? (y/n): y
Downloaded https://www.example.com → /home/user/jsdeob/input/www_example_com/index.html
Download https://www.example.com/script.js? (y/n): y


Use YARA Rules: Provide a YARA rules file for scanning:
jsdeob -i ~/jsdeob/input -o output -y rules.yar --verbose


Enable Sandbox Mode: Use Node.js sandbox for dynamic evaluation:
jsdeob -i ~/jsdeob/input -o output --sandbox


Dry Run (Compute Hashes Only):
jsdeob -i ~/jsdeob/input --dry-run



Output Structure
For each input file sample.js:

output/sample/deob_0.txt: Deobfuscated code.
output/sample/log_0.txt: Processing log.
output/sample/iocs_0.json: Extracted IOCs (URLs, IPs, etc.).
output/sample/sandbox_passN_0.txt (if --sandbox): Sandbox output.

Example Workflow

Place an obfuscated JavaScript file (obf.js) in ~/jsdeob/input.

Run:
jsdeob -i ~/jsdeob/input -o output --verbose


Check output/obf/deob_0.txt for deobfuscated code and output/obf/iocs_0.json for IOCs.


Troubleshooting

No JS/HTML Files Found: Ensure ~/jsdeob/input contains .js or .html files, or specify a different input path with -i.
URL Crawling Fails: Verify the URL is valid and reachable (curl www.example.com). Check your network or try http:// vs. https://.
YARA Errors: Ensure yara-python is installed and the rules file exists.
Sandbox Errors: Verify Node.js is installed (node --version).
Permission Issues: Run mkdir -p ~/jsdeob/input output to create directories with proper permissions.

Development

Dependencies: Listed in setup.py (requests, beautifulsoup4, prompt_toolkit, colorama, optional yara-python).
Testing: Developed on Kali Linux. Tested with Python 3.8+.
Contributing: Fork the repo, create a branch, and submit a pull request.

License
MIT License. See LICENSE file for details.
Author
Brandon Connell (connell543@outlook.com)
