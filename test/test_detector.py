
import pandas as pd
from detector import detect_port_scans


def test_detects_possible_port_scan():
    timestamps = pd.date_range(
        "2026-01-01",
        periods=15,
        freq="500ms",
        tz="UTC",
    )

    df = pd.DataFrame({
        "timestamp": timestamps,
        "src_ip": ["10.0.0.1"] * 15,
        "dst_ip": ["10.0.0.2"] * 15,
        "dst_port": list(range(20, 35)),
        "protocol": ["TCP"] * 15,
    })

    alerts = detect_port_scans(df)

    assert len(alerts) >= 1
    assert alerts.iloc[0]["alert_type"] == "Possible Port Scan"


def test_ignores_traffic_to_few_ports():
    df = pd.DataFrame({
        "timestamp": pd.date_range(
            "2026-01-01", periods=3, freq="1s", tz="UTC"
        ),
        "src_ip": ["10.0.0.1"] * 3,
        "dst_ip": ["10.0.0.2"] * 3,
        "dst_port": [80, 80, 443],
        "protocol": ["TCP"] * 3,
    })

    alerts = detect_port_scans(df)

    assert alerts.empty
