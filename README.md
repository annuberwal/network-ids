# Network Intrusion Detection System

A beginner-friendly, offline network traffic analyzer built with Python and Scapy. It reads packet capture files (`.pcap`) and reports patterns that may be suspicious.

## Features

- Detects TCP SYN packets sent to several different ports on the same target.
- Detects a high number of TCP SYN packets from one source within a 10-second window.
- Flags TCP packets with no flags set.
- Prints alerts in the terminal and saves them to `alerts.txt`.
- Offers an optional verbose mode to show packet-by-packet details.
- Summarizes packet counts by protocol.
- Adds an analysis timestamp and severity to saved alerts.
- Flags high packet bursts from one source within the 10-second window.
- Monitors live traffic and prints alerts as packets arrive.

## Requirements

- Python 3
- Scapy

## Setup on Kali Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install scapy
```

## Run

Analyze a capture file:

```bash
python main.py scan-sample.pcap
```

Other practice captures:

```bash
python main.py normal-sample.pcap
python main.py unusual-sample.pcap
```

Show details for every packet:

```bash
python main.py scan-sample.pcap --verbose
```

The analyzer uses `scan-sample.pcap` by default if no filename is provided:

```bash
python main.py
```

## Create the practice captures

```bash
python make_sample.py
```

This creates the practice `.pcap` files locally. It does not send packets over the network.

## Configuration

Detection settings are stored in `config.json` and used by both the PCAP analyzer and live monitor:

- `port_scan_threshold`: distinct destination ports needed for a port-scan alert.
- `syn_attempt_threshold`: TCP SYN packets needed for a connection-attempt alert.
- `packet_rate_threshold`: packets needed for a packet-rate alert.
- `window_seconds`: time window used by burst checks.

## Safety and scope

Use these tools only on your own system or on traffic you are authorized to inspect.

`main.py` captures on the selected interface until Ctrl+C or 5,000 packets, then analyzes the captured packets. It does not save a new PCAP file.

~~~bash
sudo .venv/bin/python main.py --interface lo
~~~

`live_monitor.py` checks packets as they arrive and prints alerts immediately. Press Ctrl+C to stop it.

~~~bash
sudo .venv/bin/python live_monitor.py --interface lo
~~~

# Limitations

The rules are simple learning examples. They can produce false positives or miss patterns that need more advanced detection. An alert is a reason to investigate, not proof of an attack.
