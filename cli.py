#!/usr/bin/env python3
"""
JSDeob - JavaScript Deobfuscation Tool CLI
Copyright (c) 2024 Brandon Connell
"""

import argparse
from pathlib import Path
import sys
import threading
import time
from shlex import split
from core import deobfuscate, compute_hash
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import socket


class Colors:
    INFO = ''
    SUCCESS = ''
    WARN = ''
    ERROR = ''
    RESET = ''

BANNER = r"""
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

     JSDeob - JavaScript Deobfuscation Tool
       Copyright 2024
"""

# Spinner for long operations

class Spinner:
    busy = False
    delay = 0.1

    @staticmethod
    def spinning_cursor():
        while True:
            for cursor in '|/-\\':
                yield cursor

    def __init__(self, message="Processing"):
        self.spinner_generator = self.spinning_cursor()
        self.message = message
        self.thread = None

    def __enter__(self):
        self.busy = True
        self.thread = threading.Thread(target=self.spinner_task)
        self.thread.start()
        return self

    def spinner_task(self):
        while self.busy:
            sys.stdout.write(f"\r{self.message} {next(self.spinner_generator)}")
            sys.stdout.flush()
            time.sleep(self.delay)

    def __exit__(self, exception, value, tb):
        self.busy = False
        if self.thread:
            self.thread.join()
        sys.stdout.write("\r")
        sys.stdout.flush()

# File collection

def collect_files(input_path: Path) -> list:
    """Collect JS and HTML files from folder or single file."""
    temp_files = []
    if input_path.is_file() and input_path.suffix.lower() in [".js", ".html"]:
        temp_files.append(input_path)
    elif input_path.is_dir():
        temp_files.extend(
            [f for f in input_path.glob("*.[jJ][sS]")] +
            [f for f in input_path.glob("*.[hH][tT][mM][lL]")]
        )
    return temp_files


# URL crawling

def check_domain_resolution(domain: str) -> bool:
    """Check if a domain can be resolved."""
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

def crawl_url(url: str, input_base_path: Path, session: PromptSession, max_depth=2, visited=None) -> list:
    """Crawl a URL and its linked pages, saving content to input_base_path, with user prompts."""
    if visited is None:
        visited = set()
    
    files = []
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    if url in visited or max_depth < 0:
        return files
    
    visited.add(url)
    domain = urlparse(url).netloc
    if not check_domain_resolution(domain):
        print(f"⚠️ Domain '{domain}' could not be resolved. Check the URL or your network connection.")
        return files
    
    schemes = ['https', 'http'] if url.startswith('http://') else ['http', 'https']
    
    for scheme in schemes:
        try_url = url.replace('http://', f'{scheme}://') if url.startswith('http://') else url
        try:
            r = requests.get(try_url, timeout=10)
            r.raise_for_status()
            
            domain_name = urlparse(try_url).netloc.replace(".", "_")
            path = urlparse(try_url).path.lstrip("/") or "index"
            if path.endswith("/"):
                path = path[:-1] + "_index"
            file_ext = ".html" if "<html" in r.text.lower() else ".js"
            target_path = input_base_path / domain_name / (path + file_ext)
            target_path.parent.mkdir(parents=True, exist_ok=True)
            
            
            response = session.prompt(f"Download {try_url} to {target_path}? (y/n): ", default="y").strip().lower()
            if response == 'y':
                target_path.write_text(r.text, encoding="utf-8", errors="replace")
                files.append(target_path)
                print(f"Downloaded {try_url} → {target_path}")
            
            # Extract linked URLs and downloadable files
            if file_ext == ".html":
                soup = BeautifulSoup(r.text, "html.parser")
                downloadable_links = []
                for link in soup.find_all(["a", "script"], href=True):
                    href = link.get("href")
                    if href and href.lower().endswith(('.js', '.html')):
                        abs_url = urljoin(try_url, href)
                        if urlparse(abs_url).netloc == urlparse(try_url).netloc and abs_url not in visited:
                            downloadable_links.append(abs_url)
                
                for script in soup.find_all("script", src=True):
                    src = script.get("src")
                    if src and src.lower().endswith('.js'):
                        abs_url = urljoin(try_url, src)
                        if urlparse(abs_url).netloc == urlparse(try_url).netloc and abs_url not in visited:
                            downloadable_links.append(abs_url)
                
                for link_url in downloadable_links:
                    response = session.prompt(f"Download {link_url}? (y/n): ", default="y").strip().lower()
                    if response == 'y':
                        files.extend(crawl_url(link_url, input_base_path, session, max_depth - 1, visited))
            
            return files 
        except Exception as e:
            print(f"Failed to fetch {try_url}: {e}")
            if scheme == schemes[-1]: 
                print(f"⚠️ Could not fetch {url} with either scheme. Try a different URL or check your connection.")
                return files
    
    return files

# Summary collector

summary_data = []

def deobfuscate_with_summary(*args, **kwargs):
    """Intercept prints to collect summary data for reporting."""
    global summary_data
    summary_data = []
    import builtins
    original_print = builtins.print

    def summary_print(*p_args, **p_kwargs):
        msg = " ".join(str(a) for a in p_args)
        if msg.startswith("[+] Deobfuscated code"):
            try:
                parts = msg.split("→")
                folder_path = parts[1].strip()
                deob_file = Path(folder_path) / "deob_0.txt"
                hash_val = compute_hash(deob_file.read_text(encoding="utf-8", errors="replace")) if deob_file.exists() else "N/A"
                summary_data.append({"folder": folder_path, "hash": hash_val})
            except Exception:
                pass
        original_print(*p_args, **p_kwargs)

    builtins.print = summary_print
    try:
        deobfuscate(*args, **kwargs)
    except Exception as e:
        print(f"Error in deobfuscation: {e}")
    finally:
        builtins.print = original_print

# CLI Entry

def create_parser():
    parser = argparse.ArgumentParser(
        description="JSDeob - Quickly deobfuscate JavaScript files for malware analysis",
        usage="jsdeob [-i INPUT_FOLDER] [-o OUTPUT_FOLDER] [options]",
        epilog="You can move files to ~/jsdeob/input/ manually and run without specifying -i."
    )

    parser.add_argument("-i", "--input", default=None,
                        help="Input JS/HTML file or folder (default: '~/jsdeob/input')")
    parser.add_argument("-o", "--output", default=None,
                        help="Output folder (default: 'output')")
    parser.add_argument("-p", "--passes", type=int, default=3,
                        help="Number of deobfuscation passes (default: 3)")
    parser.add_argument("-s", "--sandbox", action="store_true",
                        help="Enable Node.js sandbox for eval/Function")
    parser.add_argument("-y", "--yara", help="Path to YARA rules file")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--dry-run", action="store_true",
                        help="Compute hashes only, do not write files")
    parser.add_argument("--url", "-u", help="URL to fetch JS/HTML from (e.g., www.example.com)")
    parser.add_argument("--version", action="version",
                        version="JSDeob v1.1, Copyright 2024")

    return parser

def main():
    parser = create_parser()
    session = PromptSession(
        "jsdeob> ",
        complete_while_typing=True,
        history=InMemoryHistory(),
        enable_history_search=True
    )

    if len(sys.argv) > 1:
        args = parser.parse_args()
        process_args(args, session)
    else:
        print(BANNER)
        print("Welcome! Place JavaScript or HTML files in '~/jsdeob/input' folder by default.\n")
        print(parser.format_help())
        print("Enter a command (ie. '-i ~/jsdeob/input -o output) or press Enter to use defaults, or 'exit' to quit.")

        while True:
            try:
                command = session.prompt()
                command = command.strip()
                if command.lower() in ["exit", "quit"]:
                    print("Exiting JSDeob...")
                    break
                if command == "":
                    # Prompt for input/output paths
                    input_path = session.prompt(
                        "Input path (default: ~/jsdeob/input): ",
                        default="~/jsdeob/input"
                    ).strip()
                    output_path = session.prompt(
                        "Output path (default: output): ",
                        default="output"
                    ).strip()
                    args = parser.parse_args(
                        split(f"-i {input_path} -o {output_path} --verbose")
                    )
                    process_args(args, session)
                else:
                    args = parser.parse_args(split(command))
                    process_args(args, session)
            except KeyboardInterrupt:
                print("\nExiting JSDeob...")
                break
            except SystemExit:
                pass
            except Exception as e:
                print(f"Error: {e}")

def process_args(args, session):
    default_input = Path("~/jsdeob/input").expanduser()
    default_output = Path("output").expanduser()
    
    input_path = Path(args.input).expanduser() if args.input else default_input
    output_path = Path(args.output).expanduser() if args.output else default_output

    try:
        input_path.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"Error creating input folder {input_path}: {e}")
        print("Please ensure you have write permissions or specify a different input path.")
        return

    try:
        output_path.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"Error creating output folder {output_path}: {e}")
        print("Please ensure you have write permissions or specify a different output path.")
        return

    files = []
    if args.url:
        files.extend(crawl_url(args.url, input_path, session))
    else:
        files = collect_files(input_path)

    if not files:
        print(f"⚠️ No JS/HTML files found in {input_path}")
        return

    print(f"🔹 Processing {len(files)} file(s)...")
    try:
        with Spinner("Deobfuscating"):
            deobfuscate_with_summary(
                files,
                output_folder=str(output_path),
                passes=args.passes,
                sandbox=args.sandbox,
                yara_rules=args.yara,
                verbose=args.verbose,
                dry_run=args.dry_run
            )
    except Exception as e:
        print(f"Error during deobfuscation: {e}")
        return

    print("\n📝 Summary:")
    for e in summary_data:
        print(f"{e['folder']} [SHA256: {e['hash']}]")

if __name__ == "__main__":
    main()
