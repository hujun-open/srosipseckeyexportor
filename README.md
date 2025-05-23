# Overview
This a script to dump [Nokia SROS](https://documentation.nokia.com/sr/) IPsec keys into a wireshark IKEv2 key file, a regular expression could be specified to match target IPsec tunnel's IDi.

The wireshark IKEv2 key file(ikev2_decryption_table) is loaded by wireshark upon startup to decrypt IKEv2 packets, the location of ikev2_decryption_table could be found in bottom of wireshark "Preferences->Protocols>ISAKMP>"IKEv2 Decryption Table" editor GUI window.
    
- on windows, the default location is at `C:\Users\<username>\AppData\Roaming\Wireshark\ikev2_decryption_table`

notes:
- This script is intended to be run on host OS like windows/linux, typically where wireshark is running
- only ipsec-gateway terminated tunnels are supported
- only IKEv2 key are supported




## Pre-requisites - Software Depandancy
Install following software/library:
- OS: should work on any OS that supports following software
- python 3.10 or later
- [pySROS](https://pypi.org/project/pysros/)
- [ConfigArgParse](https://pypi.org/project/ConfigArgParse/)

## Pre-requisites - SROS Router

- SROS 21.7.R1 or later
- SROS system need to run in model-driven management interface configuration mode
- netconf enabled and accessible from the system running this script 
- enable IKE key history feautre via following configuraitons:
    - `config ipsec show-ipsec-keys true`
    - `... ipsec-gateway/max-history-key-records ike <num>`

## How does it work?
the script use netconf/pySROS API to search for existing tunnels whose IDi matches the specified pattern, get the remote tunnel endpoint, then execute command `admin ipsec show key gateway <gw-name> type ike peer-tunnel-ip-address <tunnel-ip> peer-tunnel-port <tunnel-port>` to get cached IKE keys, dump these key information into wireshark format.

# usage
```
python .\keyexport.py -h
usage: keyexport.py [-h] -t ROUTER [--port PORT] -u USER -p PASSWD -s SVC -g GW -i IDI [-o OUTPUT]

options:
  -h, --help            show this help message and exit
  -t ROUTER, --router ROUTER
                        router's IP
  --port PORT           router's netconf port
  -u USER, --user USER  netconf username
  -p PASSWD, --passwd PASSWD
                        netconf password
  -s SVC, --svc SVC     name of service where ipsec-gateway is in
  -g GW, --gw GW        ipsec-gateway name
  -i IDI, --idi IDI     IDi RE match pattern
  -o OUTPUT, --output OUTPUT
                        output path of wireshark IKEv2 keyfile, use stdout if not specified

Args that start with '--' can also be set in a config file (~/.srosipseckeyexportor.conf). Config file syntax allows: key=value,
flag=true, stuff=[a,b,c] (for details, see syntax at https://goo.gl/R74nmi). In general, command-line values override config file
values which override defaults.
```

## Default config file
Commonly used argument could be read from a config file `~/.srosipseckeyexportor.conf`, following is an example:
```
router = 192.168.1.100
port = 830
user = admin
passwd = admin
```
## Example CLI usage
Assume `~/.srosipseckeyexportor.conf` exists and with above content:

1. dump keys of tunnel whose IDi matching RE pattern `.+@nokia.com`, terminated on ipsec-gateway name `rw300` in IES service `300`:
```
python keyexport.py -s 300 -g rw300 -i ".+@nokia.com"
ikev2_decryption_table:
682ffbd9534525b7,b6fa52aceb65e221,8a6c983e7ab2e4a3b0bb4019c20e99fb134686c0,24db145fc32cda417d48a43691f9d3a60a471585,"AES-GCM-128 with 16 octet ICV [RFC5282]",,,"NONE [RFC4306]"
682ff9b4dd5fb0f4,0b13557553a35c90,63d8443b1b5b3862ac5a1db204461cd94dac45b9,9cd58801c3b32c84cae9b764838caa371864aa8c,"AES-GCM-128 with 16 octet ICV [RFC5282]",,,"NONE [RFC4306]"
682ff78b9b38ebe9,cf4d47ee0d7f9faf,1864283d8be02f39c0f58aaa056ef10a3a52dfa4,be90b04ef123799b12b43c6257cb7a3193990640,"AES-GCM-128 with 16 octet ICV [RFC5282]",,,"NONE [RFC4306]"

wireshark display filter:
isakmp.ispi in {682ffbd9534525b7,682ff9b4dd5fb0f4,682ff78b9b38ebe9}
```
The output contains two parts, first part is the content should be added in wireshark ikev2_decryption_table file, 2nd part is the wireshark display filter string the filters IKEv2 packets that contains the initiator SPI that matches one of target tunnels. 


2. variant of #1, write the keys directly to the ikev2_decryption_table file
```
python keyexport.py -s 300 -g rw300 -i ".+@nokia.com" -o C:\Users\junhu\AppData\Roaming\Wireshark\ikev2_decryption_table
keys are written to C:\Users\junhu\AppData\Roaming\Wireshark\ikev2_decryption_table

wireshark display filter:
isakmp.ispi in {682ffe06b92ae142,682ffbd9534525b7,682ff9b4dd5fb0f4}
```

## Match on IDi
the `-i <re_pattern>` is used to specify a regular expression pattern to match on tunnel's IDi, it uses python [`re.search` method](https://docs.python.org/3/library/re.html#re.search)