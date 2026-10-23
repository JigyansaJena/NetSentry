# NetSentry — PCAP Network Traffic Analyzer

NetSentry is a Python-based network traffic analysis tool that parses PCAP files, visualizes network activity, and detects potentially suspicious port-scanning behavior using a rule-based heuristic.

The project combines packet analysis, an interactive dashboard, and automated tests to demonstrate practical network security concepts.

## Features

- **PCAP Parsing:** Extract packet metadata using Scapy.
- **Protocol Analysis:** Classify TCP, UDP, ARP, and other traffic.
- **Interactive Dashboard:** Explore network traffic through Streamlit and Plotly visualizations.
- **Port Scan Detection:** Flag source–destination IP pairs contacting many distinct destination ports within a configurable time window.
- **Traffic Exploration:** Filter traffic and inspect packet-level information.
- **Exportable Results:** Export supported analysis results for further investigation.
- **Automated Testing:** Test packet extraction and port-scan detection behavior.

## Tech Stack

- **Language:** Python
- **Packet Analysis:** Scapy
- **Data Processing:** pandas
- **Dashboard:** Streamlit
- **Visualization:** Plotly
- **Testing:** pytest

## Project Structure

```text
NetSentry/
├── app.py
├── analyzer.py
├── detector.py
├── requirements.txt
├── README.md
├── .gitignore
├── sample_test/
│   └── dns1.pcap
└── test/
    ├── test_analyzer.py
    └── test_detector.py
```

## Getting Started

### Prerequisites

- Python installed on your system
- pip package manager

### 1. Clone the repository

After publishing the project to GitHub, clone it using:

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd NetSentry
```

Replace the placeholder with your repository's actual URL.

### 2. Create a virtual environment

On Windows:

```cmd
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

```cmd
python -m pip install -r requirements.txt
```

### 4. Launch the dashboard

```cmd
streamlit run app.py
```

Open the local URL printed in the terminal.

### 5. Run the tests

```cmd
python -m pytest -v
```

## Port Scan Detection

NetSentry uses a configurable heuristic to identify possible port scans.

The detector:

1. Filters traffic to TCP and UDP packets with the required IP and port metadata.
2. Groups traffic by source IP and destination IP.
3. Examines packets within a sliding time window.
4. Counts distinct destination ports.
5. Generates an alert when the configured threshold is reached.

### Default detection settings

| Parameter | Default |
|---|---|
| Time window | 10 seconds |
| Minimum distinct destination ports | 15 |
| Medium severity | 15–29 distinct ports |
| High severity | 30 or more distinct ports |

The initial implementation generates at most one alert per source–destination IP pair.

**Important:** These thresholds are heuristic rules, not proof of malicious activity. Legitimate network behavior may also trigger an alert.

## Testing

The current automated test suite contains four tests covering:

- TCP packet extraction
- Empty capture handling
- Detection of simulated port-scanning traffic
- Ignoring traffic that contacts too few distinct destination ports

**Latest test result:** 4 passed.

## Limitations

- Detection uses a rule-based heuristic rather than a trained machine-learning model.
- Accuracy depends on the supplied PCAP data and configured thresholds.
- The initial implementation produces at most one alert per source–destination pair.
- Performance may need optimization for very large captures.
- Alerts require investigation before being classified as actual security incidents.

## Future Improvements

- Add more detection rules for suspicious network behavior.
- Improve performance for large PCAP files.
- Add richer packet and alert summaries.
- Expand the test suite with additional traffic patterns.

## Disclaimer

NetSentry is an educational project intended for learning and authorized network traffic analysis. It is not a replacement for a production-grade intrusion detection or prevention system.