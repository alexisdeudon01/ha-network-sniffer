import os, json, time, subprocess, threading, logging
from datetime import datetime, timezone
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

IFACE      = os.environ.get("INTERFACE", "eth0")
ES_HOST    = os.environ.get("ES_HOST", "http://localhost:9200")
ES_INDEX   = os.environ.get("ES_INDEX", "packets")
ES_USER    = os.environ.get("ES_USERNAME", "elastic")
ES_PASS    = os.environ.get("ES_PASSWORD", "")
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", 50))

buffer = []
lock = threading.Lock()

def parse_line(line):
    try:
        parts = line.strip().split()
        if len(parts) < 3: return None
        doc = {"@timestamp": datetime.now(timezone.utc).isoformat(), "raw": line.strip(), "interface": IFACE}
        try: doc["epoch"] = float(parts[0])
        except: pass
        raw = line.lower()
        if "tcp" in raw: doc["proto"] = "TCP"
        elif "udp" in raw: doc["proto"] = "UDP"
        elif "icmp" in raw: doc["proto"] = "ICMP"
        elif "arp" in raw: doc["proto"] = "ARP"
        else: doc["proto"] = "OTHER"
        for i, p in enumerate(parts):
            if p == ">":
                src = parts[i-1].rstrip(",")
                dst = parts[i+1].rstrip(":")
                if "." in src:
                    s = src.rsplit(".", 1); doc["src_ip"] = s[0]; doc["src_port"] = s[1] if len(s)>1 else ""
                if "." in dst:
                    d = dst.rsplit(".", 1); doc["dst_ip"] = d[0]; doc["dst_port"] = d[1] if len(d)>1 else ""
                break
        if "length" in line:
            try: idx = line.index("length"); doc["length"] = int(line[idx:].split()[1])
            except: pass
        return doc
    except: return None

def bulk_index(docs):
    if not docs: return
    lines = []
    for d in docs:
        lines.append(json.dumps({"index": {"_index": ES_INDEX}}))
        lines.append(json.dumps(d))
    body = "\n".join(lines) + "\n"
    try:
        r = requests.post(f"{ES_HOST}/_bulk", data=body, headers={"Content-Type": "application/x-ndjson"}, auth=(ES_USER, ES_PASS), timeout=10)
        if r.status_code not in (200, 201): log.warning(f"ES error {r.status_code}")
        else: log.info(f"Indexed {len(docs)} packets")
    except Exception as e: log.error(f"ES unreachable: {e}")

def flush_loop():
    while True:
        time.sleep(5)
        with lock:
            to_send = buffer.copy(); buffer.clear()
        if to_send: bulk_index(to_send)

threading.Thread(target=flush_loop, daemon=True).start()
log.info(f"Sniffing on {IFACE} → {ES_HOST}/{ES_INDEX}")
proc = subprocess.Popen(["tcpdump", "-l", "-n", "-tt", "-i", IFACE, "-v"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
for line in proc.stdout:
    doc = parse_line(line)
    if doc:
        with lock:
            buffer.append(doc)
            if len(buffer) >= BATCH_SIZE:
                to_send = buffer.copy(); buffer.clear()
                bulk_index(to_send)
