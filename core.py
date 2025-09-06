#!/usr/bin/env python3
"""
JSDeob - JavaScript Deobfuscation Core
Copyright (c) 2024 Brandon Connell
"""

import re
import json
import subprocess
from pathlib import Path
import base64
import hashlib
from bs4 import BeautifulSoup
try:
    import yara
except ImportError:
    yara = None

# ----------------------------
# Utilities
# ----------------------------

def compute_hash(text: str) -> str:
    """Compute SHA256 hash of a string."""
    try:
        return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    except Exception as e:
        print(f"Error computing hash: {e}")
        return "N/A"

def extract_js_from_html(html_content: str) -> list:
    """Extract JavaScript from HTML <script> tags or inline attributes."""
    scripts = []
    soup = BeautifulSoup(html_content, "html.parser")
    
    for script in soup.find_all("script"):
        if script.string:
            scripts.append(script.string.strip())
    
    for tag in soup.find_all(True):
        for attr in tag.attrs:
            if attr.startswith("on") and tag[attr]:
                scripts.append(tag[attr].strip())
    
    return scripts

def extract_string_arrays(js_code: str) -> dict:
    """Extract string arrays like var _0xabc = ["..."]."""
    pattern = re.compile(r"(?:var|let|const)\s+(_0x[a-f0-9]+)\s*=\s*(\[.*?\]);", re.S)
    arrays = {}
    for m in pattern.finditer(js_code):
        name, arr = m.groups()
        try:
            arr_json = arr.replace("'", '"')
            arrays[name] = json.loads(arr_json)
        except Exception:
            continue
    return arrays

def detect_decoder(js_code: str, arrays: dict) -> tuple:
    """Detect a decoder function using one of the arrays. Returns (function_name, array_name)."""
    for arr_name in arrays.keys():
        match = re.search(
            r"function\s+(_0x[a-f0-9]+)\s*\([^)]*\)\s*{[^}]*" + arr_name, js_code
        )
        if match:
            return match.group(1), arr_name
    return None, None

def eval_decoder(js_code: str, arrays: dict, decoders: dict, max_iterations=10) -> str:
    """Replace decoder function calls (e.g., _0xdef(n)) with literal strings."""
    for _ in range(max_iterations):
        changed = False
        for decoder_name, arr_name in decoders.items():
            if arr_name not in arrays:
                continue
            array = arrays[arr_name]
            # Match individual decoder calls
            pattern = re.compile(rf"\b{decoder_name}\((0x[0-9a-f]+|\d+)\)", re.S)
            def replacer(m):
                nonlocal changed
                try:
                    idx = int(m.group(1), 16) if m.group(1).startswith("0x") else int(m.group(1))
                    result = f'"{array[idx]}"'
                    changed = True
                    return result
                except Exception:
                    return m.group(0)
            js_code = pattern.sub(replacer, js_code)
        if not changed:
            break
    return js_code


def decode_atob_calls(js_code: str) -> str:
    """Statically decode atob("BASE64") calls."""
    pattern = re.compile(r'atob\s*\("([A-Za-z0-9+/=]+)"\s*\)')
    def replacer(m):
        try:
            return f'"{base64.b64decode(m.group(1)).decode("utf-8", errors="replace")}"'
        except Exception:
            return m.group(0)
    return pattern.sub(replacer, js_code)

def decode_escaped_sequences(js_code: str) -> str:
    """Decode hex (\\xNN), Unicode (\\uNNNN), and mixed escaped strings, handling surrogates."""
    pattern = re.compile(r'([\'"])((?:\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|[0-7]{1,3}|[\'"]))+)\1', re.S)
    def replacer(m):
        quote = m.group(1)
        escaped = m.group(2)
        try:
            decoded = bytes(escaped, 'ascii').decode('unicode-escape', errors='replace')
            decoded = ''.join(c for c in decoded if not (0xD800 <= ord(c) <= 0xDFFF))
            return f'{quote}{decoded}{quote}'
        except Exception:
            return m.group(0)
    return pattern.sub(replacer, js_code)

def scan_with_yara(js_code: str, rules_path: str) -> list:
    """Scan code with YARA rules if available."""
    if not yara or not Path(rules_path).exists():
        return []
    try:
        rules = yara.compile(filepath=rules_path)
        matches = rules.match(data=js_code)
        return [str(match) for match in matches]
    except Exception:
        return []

def extract_iocs(code: str, arrays: dict, decoders: dict) -> dict:
    """Extract Indicators of Compromise (IOCs) with detailed function info, resolving arguments."""
    iocs = {
        'urls': re.findall(r'https?://[^\s\'"]+', code),
        'ips': re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', code),
        'emails': re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', code),
        'hashes': re.findall(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b', code),
        'crypto_hashes': re.findall(r'\b(sha256|sha384|sha512)\b', code),
        'suspicious_functions': []
    }

    # Function context descriptions
    func_contexts = {
        'eval': 'Dynamic code execution',
        'Function': 'Dynamic function constructor',
        'XMLHttpRequest': 'Network request',
        'alert': 'User interface interaction',
        'Object.defineProperty': 'Property definition, potential object manipulation'
    }

    # Suspicious functions with details
    suspicious_funcs = list(func_contexts.keys())
    lines = code.splitlines()
    for func in suspicious_funcs:
        pattern = re.compile(rf'\b{func}\b(?:\s*\((.*?)\))?', re.S)
        for match in pattern.finditer(code):
            start = match.start()
            line_num = sum(1 for _ in code[:start].splitlines())
            line_content = lines[line_num] if line_num < len(lines) else ""
            snippet_start = max(0, start - 20)
            snippet_end = min(len(code), start + len(match.group(0)) + 20)
            snippet = code[snippet_start:snippet_end].replace('\n', ' ')
            args = match.group(1).strip().split(',') if match.group(1) else []
            args = [arg.strip() for arg in args if arg.strip()]
            # Resolve obfuscated arguments
            resolved_args = []
            for arg in args:
                resolved = eval_decoder(arg, arrays, decoders, max_iterations=5)
                resolved_args.append(resolved if resolved != arg else arg)
            iocs['suspicious_functions'].append({
                'name': func,
                'line': line_num + 1,
                'snippet': snippet,
                'arguments': resolved_args,
                'context': func_contexts.get(func, 'Unknown function')
            })

    return {k: v for k, v in iocs.items() if v}

def run_in_node(js_code: str, dump_file: str) -> tuple:
    """Run JS in Node.js sandbox to capture eval/Function outputs."""
    wrapper = f"""
const fs = require('fs');
const dumpPath = "{dump_file.replace("\\", "/")}";
function logDump(label, code) {{
    const entry = `=== ${{label}} ===\\n${{code}}\\n\\n`;
    fs.appendFileSync(dumpPath, entry);
}}
const _eval = eval;
eval = function(code) {{ logDump("eval", code); return _eval(code); }};
const _Function = Function;
Function = function(...args) {{ logDump("Function", args.join("\\n")); return _Function.apply(this, args); }};
try {{ {js_code} }} catch(e) {{ console.error("⚠️ Sandbox Error:", e.message); }}
"""
    try:
        result = subprocess.run(
            ["node", "-e", wrapper],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout, result.stderr
    except Exception as e:
        return "", f"⚠️ Node.js sandbox failed: {e}"

def beautify_js(output_file: str):
    """Run js-beautify on output file."""
    try:
        subprocess.run(["npx", "js-beautify", output_file, "-r"], check=True)
    except Exception:
        print("⚠️ Skipping beautify (install with `npm install -g js-beautify`).")

# ----------------------------
# Main deobfuscator
# ----------------------------

def deobfuscate(
    files,
    output_folder="output",
    passes=3,
    sandbox=True,
    verbose=False,
    yara_rules=None,
    dry_run=False
):
    from cli import Colors
    global_arrays = {}
    global_decoders = {}

    # Build global registry
    for f in files:
        try:
            content = Path(f).read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"{Colors.ERROR}Error reading {f}: {e}{Colors.RESET}")
            continue
        codes = [content] if f.suffix.lower() == ".js" else extract_js_from_html(content)
        for idx, code in enumerate(codes):
            try:
                arrays = extract_string_arrays(code)
                for arr_name, arr in arrays.items():
                    global_arrays[f"{f.stem}_{idx}_{arr_name}"] = arr
                decoder_name, arr_name = detect_decoder(code, arrays)
                if decoder_name and arr_name:
                    global_decoders[decoder_name] = f"{f.stem}_{idx}_{arr_name}"
            except Exception as e:
                print(f"{Colors.ERROR}Error processing script {idx} in {f}: {e}{Colors.RESET}")
                continue

    for file in files:
        sample_name = Path(file).stem
        sample_folder = Path(output_folder) / sample_name
        try:
            sample_folder.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(f"{Colors.ERROR}Error creating folder {sample_folder}: {e}{Colors.RESET}")
            continue

        try:
            content = Path(file).read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"{Colors.ERROR}Error reading {file}: {e}{Colors.RESET}")
            continue
        codes = [content] if file.suffix.lower() == ".js" else extract_js_from_html(content)

        for idx, js_code in enumerate(codes):
            deob_file = sample_folder / f"deob_{idx}.txt"
            log_file = sample_folder / f"log_{idx}.txt"
            iocs_file = sample_folder / f"iocs_{idx}.json"
            log_lines = [f"[*] Processing {file} (script {idx})"]

            current_code = js_code
            for p in range(1, passes + 1):
                log_lines.append(f"[*] Pass {p}")
                try:
                    # 1️⃣ Inline decoder function calls
                    current_code = eval_decoder(current_code, global_arrays, global_decoders)

                    # 2️⃣ Decode atob calls
                    current_code = decode_atob_calls(current_code)

                    # 3️⃣ Decode escaped sequences
                    current_code = decode_escaped_sequences(current_code)

                    # 4️⃣ Optional Node.js sandbox
                    if sandbox:
                        sandbox_file = sample_folder / f"sandbox_pass{p}_{idx}.txt"
                        try:
                            sandbox_file.write_text("", encoding="utf-8", errors="replace")
                            stdout, stderr = run_in_node(current_code, str(sandbox_file))
                            if stdout:
                                log_lines.append(stdout.strip())
                            if stderr:
                                log_lines.append(stderr.strip())
                            log_lines.append(f"[+] Sandbox output saved → {sandbox_file}")
                        except Exception as e:
                            log_lines.append(f"[!] Error in sandbox for pass {p}: {e}")
                except Exception as e:
                    log_lines.append(f"[!] Error in pass {p} for script {idx}: {e}")
                    continue

            # YARA scanning
            if yara_rules:
                try:
                    yara_matches = scan_with_yara(current_code, yara_rules)
                    if yara_matches:
                        log_lines.append(f"[+] YARA matches: {', '.join(yara_matches)}")
                        if verbose:
                            print(f"YARA matches for {file}: {yara_matches}")
                except Exception as e:
                    log_lines.append(f"[!] Error in YARA scanning: {e}")

            # Extract IOCs
            try:
                iocs = extract_iocs(current_code, global_arrays, global_decoders)
                if iocs:
                    if not dry_run:
                        try:
                            with open(iocs_file, 'w', encoding='utf-8', errors='replace') as f:
                                json.dump(iocs, f, indent=4)
                            log_lines.append(f"[+] Extracted IOCs saved → {iocs_file}")
                            if verbose:
                                log_lines.append(json.dumps(iocs, indent=2))
                        except Exception as e:
                            log_lines.append(f"[!] Error writing IOCs to {iocs_file}: {e}")
            except Exception as e:
                log_lines.append(f"[!] Error extracting IOCs: {e}")

            # Write deobfuscated file
            if not dry_run:
                try:
                    deob_file.write_text(current_code, encoding="utf-8", errors="replace")
                    beautify_js(str(deob_file))
                    log_lines.append(f"[+] Deobfuscated code → {deob_file}")
                except Exception as e:
                    log_lines.append(f"[!] Error writing deobfuscated code to {deob_file}: {e}")
                    print(f"{Colors.ERROR}Error writing {deob_file}: {e}{Colors.RESET}")
                    if isinstance(e, UnicodeEncodeError):
                        print(f"{Colors.ERROR}Problematic code snippet: {current_code[max(0, e.start-20):e.end+20]}{Colors.RESET}")

            # Write log
            if not dry_run:
                try:
                    log_file.write_text("\n".join(log_lines), encoding="utf-8", errors="replace")
                except Exception as e:
                    log_lines.append(f"[!] Error writing log to {log_file}: {e}")
                    print(f"{Colors.ERROR}Error writing {log_file}: {e}{Colors.RESET}")

            if verbose:
                print("\n".join(log_lines[-10:]))
            print(f"✅ Finished {file} (script {idx}) → {sample_folder}")
