from io import BytesIO
from shutil import which
from subprocess import check_output, run

from pandas import read_fwf
from prompt_toolkit import choice
from prompt_toolkit.shortcuts import checkboxlist_dialog
from rich import print

DEPENDENCIES = ["nmcli", "airmon-ng", "airodump-ng"]

for dependency in DEPENDENCIES:
    if which(dependency) is None:
        print(f"[red][i]{dependency}[/i] not found. Script cannot continue.")
        exit(1)


def enable_monitor_mode(wlan_interface: str) -> bool:
    print(f"[blue]Enabling monitor mode for [i]{wlan_interface}[/i]...")

    if not run(("sudo", "airmon-ng", "start", wlan_interface)):
        print("[red]Failed to enable monitor mode.")
        return False

    return True


def disable_monitor_mode(wlan_interface: str) -> bool:
    print(f"[blue]Disabling monitor mode for [i]{wlan_interface}[/i]...")

    if not run(("sudo", "airmon-ng", "stop", wlan_interface)):
        print("[red]Failed to disable monitor mode.")
        return False

    return True


device_list = check_output(("nmcli", "device", "status"))

if len(device_list) == 0:
    print("[red]No device status from [i]NetworkManager[/i]. Exiting.")
    exit(1)

device_df = read_fwf(BytesIO(device_list))
device_wifi = device_df.query("TYPE == 'wifi'")

if len(device_wifi) == 0:
    print("[red]No [i]wifi[/i] device found. Exiting.")
    exit(1)

elif len(device_wifi) == 1:
    wlan_interface = device_wifi["DEVICE"].iloc[0]

else:
    wlan_interface = choice(
        message="Choose WLAN interface:",
        options=[(dev, dev) for dev in device_wifi["DEVICE"]],
    )

wifi_df = read_fwf(BytesIO(check_output(("nmcli", "device", "wifi", "list"))))


options: list[tuple[str, str]] = []
for _, row in wifi_df.iterrows():
    options.append(
        (
            row["SSID"],
            f"{row['BSSID']} {row['SECURITY'].split()[0]} {row['SIGNAL']:03} {row['SSID']}",
        )
    )


networks = set(checkboxlist_dialog("Select Wi-Fi networks:", values=options).run())
networks.discard("--")

if len(networks) == 0:
    print("[red]No networks selected. Exiting.")
    exit(1)

if not enable_monitor_mode(wlan_interface):
    exit(1)

command = "sudo airodump-ng "
_ = run(
    (
        "sudo",
        "airodump-ng",
        f"{wlan_interface}mon",
        "--essid-regex",
        "|".join(networks),
        "--output-format",
        "pcap",
    )
)

_ = disable_monitor_mode(f"{wlan_interface}mon")
