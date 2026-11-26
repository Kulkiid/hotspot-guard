# 🔥 Hotspot Guard

**See exactly who is connected to your phone hotspot, with real device names, intruder alerts and a live watch mode. One Bash script, no installs.**

Mobile data is expensive. If your hotspot password leaks, strangers can drain your data without you noticing. Hotspot Guard scans your hotspot, names every device it finds, and alerts you when something you don't recognise joins.

```text
   IP              NAME                   MANUFACTURER       MAC               STATUS
-----------------------------------------------------------------------------------------
💻 192.168.43.2    BLESSING-PC            -                  -                 You
📱 192.168.43.1    Hotspot phone          -                  3a:11:22:33:44:55 (your phone)
📱 192.168.43.5    Mum's phone            Samsung Electronics aa:bb:cc:00:11:22 ✅ trusted
📱 192.168.43.12   TECNO MOBILE device    TECNO MOBILE       00:11:22:aa:bb:cc ❓ UNKNOWN 🆕 NEW
-----------------------------------------------------------------------------------------
Devices connected (besides you): 2   Unknown: 1   New: 1
```

*(Example output with made-up devices.)*

## ✨ Features

- **Real device names:** hostname lookup (NetBIOS, reverse DNS, mDNS), manufacturer lookup from the MAC address, and a type icon guess (📱 💻 📺 🎮).
- **Trusted device list:** name your own devices once; everything else shows as ❓ UNKNOWN.
- **Live watch mode:** rescans on an interval and prints `➕ JOINED` / `➖ LEFT` with a beep and optional desktop popup.
- **Only counts devices that really answer:** devices that left but are still in the ARP table are listed separately, not counted.
- **Device limit alert:** warns you if more than N devices are connected.
- **Device history:** first seen, last seen and scan count for every device ever seen.
- **Password strength checker:** local only, never saved or sent.
- **Speed test + link quality:** ping time and packet loss to your phone, plus download speed.
- **Export:** save any scan as CSV or JSON.
- **Auto-detects your network:** works with Android (`192.168.43.x`) and iPhone (`172.20.10.x`) hotspots.

## 📋 Requirements

- Bash 3.2 or newer
- Standard tools: `ping`, `arp` (or `ip`), `awk`, `sed`, `grep`, `curl` (for manufacturer lookup and speed test)
- Your computer connected to the hotspot you want to scan

**Platforms:** built and tested mainly on **Windows with Git Bash**. Linux and macOS are supported but have had less testing; please open an issue if something breaks.

## 🚀 Quick start

```bash
git clone https://github.com/<your-username>/hotspot-guard.git
cd hotspot-guard
chmod +x hotspot-guard.sh

# 1. Connect your computer to your phone's hotspot, then scan:
./hotspot-guard.sh

# 2. Save your own devices as trusted (only while ONLY your devices are connected):
./hotspot-guard.sh --trust-all

# 3. Guard mode:
./hotspot-guard.sh --watch --notify --max 4
```

## 🧰 Options

| Option | What it does |
|---|---|
| `-w`, `--watch` | Live mode: rescan repeatedly and alert on changes |
| `-i`, `--interval N` | Seconds between scans in watch mode (default 30, minimum 5) |
| `-d`, `--deep` | Scan twice, which helps find sleepy phones |
| `--include-silent` | Also count devices that don't answer ping (may include stale entries) |
| `--subnet A.B.C` | Scan a specific /24 instead of auto-detecting, e.g. `192.168.43` |
| `-t`, `--trust` | Name your devices one by one (saved as trusted) |
| `-T`, `--trust-all` | Trust everything connected right now (auto-named) |
| `--rename` | Menu to rename, trust or remove devices (no scan) |
| `--devices` | Show every device ever seen (no scan) |
| `--refresh` | Forget cached names and look them up again |
| `--no-vendor` | Skip online manufacturer lookup |
| `-n`, `--notify` | Desktop popup when an unknown device joins or the limit is passed |
| `--max N` | Warn if more than N devices are connected |
| `-e`, `--export csv\|json` | Save the scan to a file |
| `-s`, `--speed` | Speed test and link quality to your phone |
| `--no-pass` | Skip the password strength check |
| `--no-color` | Plain output |
| `-h`, `--help` | Show help |

## 🔍 How it works

1. **Find your network:** reads your IP and default gateway (your phone).
2. **Ping sweep:** pings all 254 addresses in the subnet, 60 at a time.
3. **Read the ARP table:** matches IP addresses to MAC addresses.
4. **Confirm devices:** keeps only devices that reply to ping (retrying silent ones). Old ARP entries stay in a separate "not answering" list.
5. **Name devices:** tries hostname lookups, then manufacturer lookup from the MAC prefix. Results are cached.
6. **Compare:** checks against your trusted list and your device history to flag ❓ UNKNOWN and 🆕 NEW devices.

## 📁 Files it creates

These are created next to the script (or in `$HOTSPOT_GUARD_DIR`):

| File | Purpose |
|---|---|
| `hotspot-known.txt` | Your trusted devices (`mac  name`), safe to edit by hand |
| `hotspot-seen.tsv` | Every device ever seen, with first/last seen times |
| `hotspot-history.txt` | One log line per scan |
| `hotspot-report.txt` | The last scan as plain text |
| `hotspot-export-*.csv/json` | Exports, only when you ask |
| `.hotspot-*.cache` | Name and manufacturer caches |

These files contain MAC addresses and device names, so they are listed in `.gitignore` and **should not be committed or shared**.

## ⚠️ Limitations

- **Phones with private MACs** (the default on modern Android and iOS) often hide their name, so they show as "Unknown device". Name them once with `--rename` and the name sticks.
- **Devices that ignore ping** (for example a Windows laptop with the firewall on) appear in the "not answering ping" list instead of the main table. Use `--include-silent` to count them.
- **Sleeping phones** may miss a ping and briefly appear as left. `--deep` reduces this.
- **Icons and types are guesses** from the name and manufacturer, not facts.
- **Detection only.** Hotspot Guard can't kick anyone off. If you find a stranger, change your hotspot password.
- It scans a `/24` network. Very unusual network setups may need `--subnet`.

## 🛡️ Responsible use

Only scan networks you own or have permission to scan, such as your own phone hotspot. Scanning other people's networks may be illegal.

## 🩺 Troubleshooting

| Problem | Try |
|---|---|
| "Not connected to a network" | Connect your computer to the phone hotspot first |
| Wrong network picked on Windows | Choose from the list it shows, or use `--subnet 192.168.43` |
| Everyone is "Unknown device" | Run `--rename` to name them; lookups can't see hidden names |
| A connected device is missing | Try `--deep`, or `--include-silent` |
| No popup alerts | The beep and printed alerts still work; popups need PowerShell (Windows), `notify-send` (Linux) or `osascript` (macOS) |
| Manufacturer shows "-" | You may be offline or rate-limited; run `--refresh` later |

## 🗺️ Ideas for the future

- Alert history viewer
- Optional Telegram / WhatsApp notifications
- Scheduled background scanning
- Offline manufacturer database

Contributions and bug reports are welcome. Open an issue or pull request.

## 📄 License

MIT. See `LICENSE`.

---

Built by **<your-name>** while learning Bash and cybersecurity. If it helped you, give it a ⭐.
