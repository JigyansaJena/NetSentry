
import pandas as pd


def detect_port_scans(
    df,
    window_seconds=10,
    min_unique_ports=15,
):
    """Flag possible port scans using a sliding time window."""

    required = {
        "timestamp", "src_ip", "dst_ip", "dst_port", "protocol"
    }

    missing = required - set(df.columns)
    if missing:
        raise ValueError(
            f"Missing required columns: {sorted(missing)}"
        )

    if window_seconds <= 0 or min_unique_ports < 1:
        raise ValueError("Window and port threshold must be positive.")

    traffic = df.dropna(
        subset=["timestamp", "src_ip", "dst_ip", "dst_port"]
    ).copy()

    traffic = traffic[
        traffic["protocol"].isin(["TCP", "UDP"])
    ].copy()

    traffic["dst_port"] = traffic["dst_port"].astype(int)
    traffic = traffic.sort_values("timestamp")

    alerts = []

    for (src_ip, dst_ip), group in traffic.groupby(
        ["src_ip", "dst_ip"]
    ):
        group = group.reset_index(drop=True)

        for end in range(len(group)):
            end_time = group.loc[end, "timestamp"]
            start_time = end_time - pd.Timedelta(
                seconds=window_seconds
            )

            window = group[
                (group["timestamp"] > start_time)
                & (group["timestamp"] <= end_time)
            ]

            unique_ports = sorted(
                window["dst_port"].unique().tolist()
            )

            if len(unique_ports) >= min_unique_ports:
                alerts.append({
                    "alert_type": "Possible Port Scan",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "start_time": window["timestamp"].min(),
                    "end_time": end_time,
                    "unique_ports": len(unique_ports),
                    "ports": unique_ports,
                    "severity": (
                        "High" if len(unique_ports) >= 30
                        else "Medium"
                    ),
                    "description": (
                        f"{src_ip} contacted {len(unique_ports)} "
                        f"distinct destination ports on {dst_ip} "
                        f"within {window_seconds} seconds."
                    ),
                })

                # One alert per source-target pair for this
                # initial implementation.
                break

    return pd.DataFrame(alerts)
