# Network Intrusion Detection System

A beginner-friendly, offline network traffic analyzer built with Python and Scapy. It reads packet capture files (`.pcap`) and reports patterns that may be suspicious.

## Features

- Detects TCP SYN packets sent to several different ports on the same target.
- Detects a high number of TCP SYN packets from one source within a 10-second window.
- Flags TCP packets with no flags set.
- Prints alerts in the terminal and saves them to `alerts.txt`.
- Offers an optional verbose mode to show packet-by-packet details.

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

Detection thresholds are set near the top of `main.py`:

- `PORT_SCAN_THRESHOLD`: number of distinct destination ports that triggers a possible port-scan alert.
- `SYN_ATTEMPT_THRESHOLD`: number of TCP SYN packets that triggers a high-attempt alert.
- `ATTEMPT_WINDOW_SECONDS`: time period used for the SYN-attempt check.

## Safety and scope

This project analyzes saved packet captures. Use captures from your own lab or other traffic you are authorized to inspect. The current version does not perform live network capture.

## Limitations

The rules are simple learning examples. They can produce false positives or miss patterns that need more advanced detection. An alert is a reason to investigate, not proof of an attack.
