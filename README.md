# WPA2-HalfHandshake-Crack
This is a POC to show it is possible to capture enough of a handshake with a user from a fake AP to crack a WPA2 network without an AP

## Sample use

```
$ python halfHandshake.py -r sampleHalfHandshake.cap -m 48d224f0d128 -s "no place like 127.0.0.1"
```

* **-r** Where to read input pcap file with half handshake (works with full handshakes too)
* **-m** AP mac address
* **-s** AP SSID
* **-d** (optional) Where to read dictionary from
