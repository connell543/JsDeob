<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <header>
        <h1>JSDeob - JavaScript Deobfuscation Tool</h1>
        <p>
            <img src="https://img.shields.io/badge/Python-3.8%2B-blue.svg" alt="Python">
            <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
            <img src="https://img.shields.io/badge/Version-1.1-orange.svg" alt="Version">
        </p>
    </header>


 
		
<div align="center">
            <pre>
___________________________¶___¶___________________________
__________________________¶_____¶__________________________
_________________________¶_______¶_________________________
________________________¶_________¶________________________
________________________¶_________¶________________________
_______________________¶¶_________¶¶_______¶_______________
_______________¶_______¶___________¶_______¶_______________
_______________¶______¶¶___________¶¶______¶_______________
_______________¶¶_____¶¶___________¶¶_____¶¶_______________
_________¶_____¶¶_____¶¶___________¶¶_____¶¶_____¶_________
_________¶¶_____¶_____¶¶___________¶¶_____¶¶_____¶_________
_________¶¶_____¶¶____¶¶___________¶¶____¶¶_____¶¶_________
__________¶¶____¶¶¶___¶¶¶_________¶¶¶___¶¶¶____¶¶__________
___________¶¶¶___¶¶¶__¶¶¶_________¶¶¶__¶¶¶____¶¶___________
____________¶¶¶___¶¶¶__¶¶¶_______¶¶¶¶_¶¶¶___¶¶¶____________
_____________¶¶¶¶¶_¶¶¶¶¶¶¶______¶¶¶¶¶¶¶_¶¶¶¶¶_____________
_______________¶¶¶¶¶___¶¶¶¶¶¶_¶¶¶¶¶¶___¶¶¶¶¶_______________
______________¶¶¶________¶¶¶¶¶¶¶________¶¶¶¶______________
______________¶¶¶_____¶____¶¶¶¶¶____¶_____¶¶¶______________
_____________T¶¶________¶___¶¶¶___¶________¶¶¶_____________
_____________¶¶¶________¶¶___¶___¶¶________¶¶¶_____________
______________¶¶¶_______¶¶¶_____¶¶¶_______¶¶¶______________
_______________¶¶¶_____¶¶¶¶¶___¶¶¶¶¶_____¶¶¶¶______________
________________¶¶¶¶¶¶¶¶¶_¶¶___¶¶_¶¶¶¶¶¶¶¶¶________________
__________________¶¶¶¶¶___¶¶___¶¶___¶¶¶¶¶__________________
__________________________¶¶___¶¶__________________________
__________________________¶¶___¶¶__________________________
__________________________¶_____¶__________________________
_________________________¶¶_____¶¶_________________________
_________________________¶_______¶_________________________
________________________¶_________¶________________________
______________________¶_____________¶______________________
___________________________________________________________
            </pre>
</div>

 <b>JSDeob</b>
is a powerful Python-based command-line tool designed for deobfuscating JavaScript code, tailored for malware analysis. It processes JavaScript and HTML files, decoding obfuscation techniques like string arrays, <code>atob</code> calls, and hex/Unicode escapes. With features like web crawling, YARA rule scanning, and IOC extraction, it's a must-have for security researchers. Run it with the <code>jsdeob</code> command for an interactive CLI experience.
        </p>
    </section>

   <section>
        <h2>Features</h2>
        <ul>
            <li><b>Deobfuscation</b>: Simplifies JavaScript obfuscation (string arrays, <code>atob</code>, escaped sequences).</li>
            <li><b>Web Crawler</b>: Fetches JS/HTML from URLs with interactive download prompts.</li>
            <li><b>YARA Integration</b>: Scans code with YARA rules for malware detection (optional).</li>
            <li><b>IOC Extraction</b>: Identifies URLs, IPs, emails, and suspicious functions.</li>
            <li><b>Node.js Sandbox</b>: Safely evaluates dynamic code (optional).</li>
            <li><b>Interactive CLI</b>: User-friendly interface with command history.</li>
            <li><b>Cross-Platform</b>: Runs on Linux (developed on Kali), macOS, and Windows.</li>
        </ul>
    </section>

   <section>
       <h2>Installation</h2>
        <p>JSDeob was developed on <b>Kali Linux</b> but works on any system with <b>Python 3.8+</b>. Install it as a Python package to use the <code>jsdeob</code> command.</p>

   <h3>Prerequisites</h3>
        <table>
            <tr>
                <th>Requirement</th>
                <th>Description</th>
                <th>Installation (Kali)</th>
            </tr>
            <tr>
                <td>Python 3.8+</td>
                <td>Required for running JSDeob</td>
                <td><code>sudo apt install python3 python3-pip</code></td>
            </tr>
            <tr>
                <td>Node.js</td>
                <td>Optional for sandbox mode</td>
                <td><code>sudo apt install nodejs</code></td>
            </tr>
            <tr>
                <td>YARA</td>
                <td>Optional for YARA scanning</td>
                <td><code>sudo apt install yara</code><br><code>pip3 install yara-python</code></td>
            </tr>
        </table>

   <h3>Installation Steps</h3>
        <ol>
            <li><b>Clone the Repository</b>:
                <pre><code>git clone https://github.com/connell543/jsdeob.git
cd jsdeob</code></pre>
            </li>
            <li><b>Install the Package</b>:
                <pre><code>pip3 install .</code></pre>
                <p>This installs dependencies (<code>requests</code>, <code>beautifulsoup4</code>, <code>prompt_toolkit</code>, <code>colorama</code>) and sets up the <code>jsdeob</code> command.</p>
            </li>
            <li><b>Verify Installation</b>:
                <pre><code>jsdeob --version</code></pre>
                <p><b>Output</b>: <code>JSDeob v1.1, Copyright 2024</code></p>
            </li>
            <li><b>Optional Dependencies</b>:
                <ul>
                    <li>YARA: <code>pip3 install yara-python</code></li>
                    <li>Node.js: Ensure <code>node --version</code> works.</li>
                </ul>
            </li>
            <li><b>Set Up Directories</b>:
                <pre><code>mkdir -p ~/jsdeob/input output</code></pre>
            </li>
        </ol>
    </section>

   <section>
        <h2>Usage</h2>
        <p>Run <code>jsdeob</code> to launch the interactive CLI:</p>
        <pre><code>jsdeob</code></pre>
        <p>This displays a stylish ASCII banner and a <code>jsdeob&gt;</code> prompt.</p>

   <h3>Command-Line Options</h3>
        <table>
            <tr>
                <th>Option</th>
                <th>Description</th>
                <th>Example</th>
            </tr>
            <tr>
                <td><code>-h, --help</code></td>
                <td>Show help message</td>
                <td><code>jsdeob --help</code></td>
            </tr>
            <tr>
                <td><code>-i, --input</code></td>
                <td>Input JS/HTML file or folder (default: <code>~/jsdeob/input</code>)</td>
                <td><code>jsdeob -i ~/jsdeob/input</code></td>
            </tr>
            <tr>
                <td><code>-o, --output</code></td>
                <td>Output folder (default: <code>output</code>)</td>
                <td><code>jsdeob -o results</code></td>
            </tr>
            <tr>
                <td><code>-p, --passes</code></td>
                <td>Number of deobfuscation passes (default: 3)</td>
                <td><code>jsdeob -p 5</code></td>
            </tr>
            <tr>
                <td><code>-s, --sandbox</code></td>
                <td>Enable Node.js sandbox</td>
                <td><code>jsdeob -s</code></td>
            </tr>
            <tr>
                <td><code>-y, --yara</code></td>
                <td>Path to YARA rules file</td>
                <td><code>jsdeob -y rules.yar</code></td>
            </tr>
            <tr>
                <td><code>-v, --verbose</code></td>
                <td>Verbose output</td>
                <td><code>jsdeob -v</code></td>
            </tr>
            <tr>
                <td><code>--dry-run</code></td>
                <td>Compute hashes only</td>
                <td><code>jsdeob --dry-run</code></td>
            </tr>
            <tr>
                <td><code>--url, -u</code></td>
                <td>URL to fetch JS/HTML (e.g., <code>www.example.com</code>)</td>
                <td><code>jsdeob --url www.example.com</code></td>
            </tr>
            <tr>
                <td><code>--version</code></td>
                <td>Show version</td>
                <td><code>jsdeob --version</code></td>
            </tr>
        </table>

        <h3>Examples</h3>
        <ol>
            <li><b>Deobfuscate Files in Default Folder</b>:
                <p>Place files in <code>~/jsdeob/input</code> and run:</p>
                <pre><code>jsdeob</code></pre>
                <p>Press Enter at prompts to use defaults:</p>
                <pre><code>jsdeob&gt;
Input path (default: ~/jsdeob/input):
Output path (default: output):</code></pre>
            </li>
            <li><b>Deobfuscate a Specific File</b>:
                <pre><code>jsdeob -i ~/jsdeob/input/sample.js -o output --verbose</code></pre>
            </li>
            <li><b>Crawl a Website</b>:
                <pre><code>jsdeob --url www.example.com</code></pre>
                <p><b>Prompts</b>:</p>
                <pre><code>Download https://www.example.com to /home/user/jsdeob/input/www_example_com/index.html? (y/n): y
Download https://www.example.com/script.js? (y/n): y</code></pre>
            </li>
            <li><b>Use YARA Rules</b>:
                <pre><code>jsdeob -i ~/jsdeob/input -y rules.yar -v</code></pre>
            </li>
            <li><b>Sandbox Mode</b>:
                <pre><code>jsdeob -i ~/jsdeob/input -s</code></pre>
            </li>
        </ol>

   <h3>Output Structure</h3>
        <p>For each input file <code>sample.js</code>:</p>
        <ul>
            <li><code>output/sample/deob_0.txt</code>: Deobfuscated code</li>
            <li><code>output/sample/log_0.txt</code>: Processing log</li>
            <li><code>output/sample/iocs_0.json</code>: IOCs (URLs, IPs, etc.)</li>
            <li><code>output/sample/sandbox_passN_0.txt</code>: Sandbox output (if enabled)</li>
        </ul>
    </section>

   <section>
        <h2>Example Workflow</h2>
        <ol>
            <li>Save an obfuscated file to <code>~/jsdeob/input/obf.js</code>:
                <pre><code>var _0x1234=['aGVsbG8=','d29ybGQ='];function _0x5678(_0x9abc){return atob(_0x1234[_0x9abc]);}console.log(_0x5678(0)+" "+_0x5678(1));</code></pre>
            </li>
            <li>Run:
                <pre><code>jsdeob -i ~/jsdeob/input -o output -v</code></pre>
            </li>
            <li>Check <code>output/obf/deob_0.txt</code> for:
                <pre><code>console.log("hello world");</code></pre>
            </li>
        </ol>
    </section>

   <section>
        <h2>Troubleshooting</h2>
        <ul>
            <li><b>No JS/HTML Files</b>: Ensure <code>~/jsdeob/input</code> contains <code>.js</code> or <code>.html</code> files.</li>
            <li><b>URL Failures</b>: Verify the URL (<code>curl www.example.com</code>) and network connection.</li>
            <li><b>YARA Issues</b>: Install <code>yara-python</code> and check the rules file path.</li>
            <li><b>Sandbox Errors</b>: Confirm Node.js is installed (<code>node --version</code>).</li>
            <li><b>Permissions</b>: Run <code>mkdir -p ~/jsdeob/input output</code>.</li>
        </ul>
    </section>

   <section>
        <h2>Development</h2>
        <ul>
            <li><b>Dependencies</b>: See <code>setup.py</code> (<code>requests</code>, <code>beautifulsoup4</code>, <code>prompt_toolkit</code>, <code>colorama</code>, optional <code>yara-python</code>).</li>
            <li><b>Tested On</b>: Kali Linux with Python 3.8+.</li>
            <li><b>Contributing</b>: Fork, branch, and submit a pull request.</li>
        </ul>
    </section>

   <section>
        <h2>License</h2>
        <p><a href="LICENSE">MIT License</a> © 2024 Brandon Connell</p>
    </section>

   <section>
        <h2>Author</h2>
        <p>
            <b>Brandon Connell</b><br>
            <a href="mailto:connell543@outlook.com">connell543@outlook.com</a><br>
            <a href="https://github.com/connell543">GitHub</a>
        </p>
    </section>

   <footer>
        <p><a href="https://github.com/connell543/jsdeob">Star this repo</a> if you find JSDeob useful!</p>
    </footer>
</body>
</html>
