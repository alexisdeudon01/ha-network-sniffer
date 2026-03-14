#!/usr/bin/env python3
import subprocess, threading, json, re
from collections import deque
from flask import Flask, render_template, jsonify, request, Response
import time, os

app = Flask(__name__, template_folder='/templates')

# State
packets = deque(maxlen=500)
capture_thread = None
current_iface = None
stop_event = threading.Event()
monitor_mode_iface = None

NOISE_FILTERS = [
    'ff:ff:ff:ff:ff:ff',  # broadcast
    '224.0.0.',           # multicast
    '239.',               # multicast
    'mdns', 'ssdp',
    '255.255.255.255',
]

def get_interfaces():
    try:
        out = subprocess.check_output(['ip', 'link', 'show'], text=True)
        ifaces = re.findall(r'\d+: (\w+):', out)
        return [i for i in ifaces if i != 'lo']
    except:
        return ['eth0']

def supports_monitor(iface):
    try:
        out = subprocess.check_output(['iw', iface, 'info'], text=True, stderr=subprocess.DEVNULL)
        return 'monitor' in subprocess.check_output(['iw', 'phy', 'phy0', 'info'], text=True, stderr=subprocess.DEVNULL)
    except:
        return False

def set_monitor_mode(iface, enable):
    try:
        subprocess.run(['ip', 'link', 'set', iface, 'down'], check=True)
        mode = 'monitor' if enable else 'managed'
        subprocess.run(['iw', iface, 'set', 'type', mode], check=True)
        subprocess.run(['ip', 'link', 'set', iface, 'up'], check=True)
        return True
    except Exception as e:
        return False

def is_noise(line):
    for n in NOISE_FILTERS:
        if n in line:
            return True
    return False

def parse_packet(line, filters):
    line = line.strip()
    if not line or is_noise(line):
        return None

    proto = 'OTHER'
    if 'HTTP' in line or '.80 ' in line or '.443 ' in line or ' 80 ' in line:
        proto = 'HTTP'
        if '.443' in line:
            proto = 'HTTPS'
    elif '.53 ' in line or ' 53 ' in line or 'DNS' in line:
        proto = 'DNS'
    elif 'ARP' in line.upper():
        proto = 'ARP'
    elif 'ICMP' in line.upper():
        proto = 'ICMP'
    elif '.22 ' in line or ' 22 ' in line:
        proto = 'SSH'
    elif '.67 ' in line or '.68 ' in line:
        proto = 'DHCP'
    elif 'UDP' in line.upper():
        proto = 'UDP'
    elif 'TCP' in line.upper() or '>' in line:
        proto = 'TCP'

    if filters and proto not in filters and proto != 'OTHER':
        return None
    if filters and 'OTHER' not in filters and proto == 'OTHER':
        return None

    # Extract src > dst
    src, dst = '', ''
    m = re.search(r'(\d+\.\d+\.\d+\.\d+[\.\d]*)\s*>\s*(\d+\.\d+\.\d+\.\d+[\.\d]*)', line)
    if m:
        src, dst = m.group(1), m.group(2)

    length = ''
    lm = re.search(r'length (\d+)', line)
    if lm:
        length = lm.group(1)

    return {
        'time': time.strftime('%H:%M:%S'),
        'proto': proto,
        'src': src,
        'dst': dst,
        'length': length,
        'raw': line[:120]
    }

def capture(iface, filters):
    global packets
    packets.clear()
    cmd = ['tcpdump', '-l', '-n', '-i', iface, '-tt']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    while not stop_event.is_set():
        line = proc.stdout.readline()
        if not line:
            break
        pkt = parse_packet(line, filters)
        if pkt:
            packets.append(pkt)
    proc.terminate()

def start_capture(iface, filters):
    global capture_thread, current_iface
    stop_event.set()
    if capture_thread and capture_thread.is_alive():
        capture_thread.join(timeout=2)
    stop_event.clear()
    current_iface = iface
    capture_thread = threading.Thread(target=capture, args=(iface, filters), daemon=True)
    capture_thread.start()

@app.route('/')
def index():
    ifaces = get_interfaces()
    return render_template('index.html', interfaces=ifaces)

@app.route('/api/interfaces')
def api_interfaces():
    ifaces = get_interfaces()
    result = []
    for i in ifaces:
        result.append({'name': i, 'monitor_capable': supports_monitor(i)})
    return jsonify(result)

@app.route('/api/start', methods=['POST'])
def api_start():
    data = request.json
    iface = data.get('interface', 'eth0')
    filters = data.get('filters', ['HTTP', 'HTTPS', 'DNS', 'TCP', 'UDP'])
    start_capture(iface, filters)
    return jsonify({'status': 'started', 'interface': iface})

@app.route('/api/stop', methods=['POST'])
def api_stop():
    stop_event.set()
    return jsonify({'status': 'stopped'})

@app.route('/api/packets')
def api_packets():
    since = int(request.args.get('since', 0))
    all_pkts = list(packets)
    return jsonify(all_pkts[since:])

@app.route('/api/monitor', methods=['POST'])
def api_monitor():
    data = request.json
    iface = data.get('interface')
    enable = data.get('enable', False)
    ok = set_monitor_mode(iface, enable)
    return jsonify({'status': 'ok' if ok else 'error', 'monitor': enable})

@app.route('/api/clear', methods=['POST'])
def api_clear():
    packets.clear()
    return jsonify({'status': 'cleared'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8099, debug=False)
