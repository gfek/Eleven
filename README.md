# Eleven

`Eleven` is a python utility for fetching free intel feeds, using the [python cabby taxii client](https://github.com/eclecticiq/cabby) implemented by [EclecticIQ](https://www.eclecticiq.com/), from the Limo service provided by the [Anomali](https://www.anomali.com/) company. Limo is an out-of-the-box TAXII service for users who want to get started with threat intelligence.

Free Intel Feeds provided by Limo TAXII service:

* Abuse\_ch\_Ransomware\_IPs\_F135
* Abuse\_ch\_Ransomware\_Domains\_F136
* DShield\_Scanning\_IPs\_F150
* Lehigh_Malwaredomains\_F33
* CyberCrime_F41
* Emerging\_Threats\_C\_C\_Server\_F31
* Malware\_Domain\_List\_\_\_Hotlist\_F200
* Phish_Tank\_F107
* Emerging\_Threats\_\_\_Compromised\_F68
* Blutmagie\_TOR\_Nodes\_F209
* Anomali\_Weekly\_Threat\_Briefing\_S1 

The eleven python utility connects to the limo collection and downloads all the available public intel feeds. The downloaded data are stored in an [ElasticSearch](https://www.elastic.co/downloads/elasticsearch) index. [Kibana](https://www.elastic.co/downloads/kibana) can be used to visualise the available data.

## Requirements
```
cabby==0.1.20
certifi==2018.8.24
chardet==3.0.4
colorlog==3.1.4
cybox==2.1.0.17
elasticsearch==6.3.1
furl==1.2.1
idna==2.7
libtaxii==1.1.111
lxml==4.2.4
mixbox==1.0.3
ordered-set==3.0.1
orderedmultidict==1.0
python-dateutil==2.7.3
pytz==2018.5
requests==2.19.1
six==1.11.0
stix==1.2.0.6
urllib3==1.23
weakrefmethod==1.0.3
```

## Help

``` 
usage: eleven.py [-h] [-d DAYS] [-u USERNAME] [-p PASSWORD] [-e ES]
                     [-l PORT] [-i INDEX]

A tool for fetching `ANOMALI` limo threat intel feed collection and store them to an ElasticSearch.

optional arguments:
  -h, --help            show this help message and exit
  -d DAYS, --days DAYS  Define the timedelta in days.
  -u USERNAME, --username USERNAME
                        Define the username.
  -p PASSWORD, --password PASSWORD
                        Define the password.
  -e ES, --es ES        Define the elasticsearch host.
  -l PORT, --port PORT  Define the elasticsearch port.
  -i INDEX, --index INDEX
                        Define the elsticsearch index.
```

## Example

`python eleven.py -d 30`

```
[*]-Fetching collection name: Abuse_ch_Ransomware_IPs_F135
[*]-Fetching collection name: Abuse_ch_Ransomware_Domains_F136
[*]-Fetching collection name: DShield_Scanning_IPs_F150
[*]-Fetching collection name: Lehigh_Malwaredomains_F33
[*]-Fetching collection name: CyberCrime_F41
[*]-Fetching collection name: Emerging_Threats_C_C_Server_F31
[*]-Fetching collection name: Malware_Domain_List___Hotlist_F200
[*]-Fetching collection name: Phish_Tank_F107
[*]-Fetching collection name: Emerging_Threats___Compromised_F68
[*]-Fetching collection name: Blutmagie_TOR_Nodes_F209
[*]-Fetching collection name: Anomali_Weekly_Threat_Briefing_S1

[*]-Connection with ES was successful.
[*]-Deleting taxii_anomali index... Status: True
[*]-Creating taxii_anomali index...
[*]-Index taxii_anomali created successully... Status: True
[*]-10,309 documents have been saved.
```

## Kibana

![](https://raw.githubusercontent.com/gfek/Eleven/master/kibana_vis.png)