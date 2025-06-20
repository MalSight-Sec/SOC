# Description:

These tools and command-line utilities are part of my day-to-day workflow in a Security Operations Center (SOC) environment. I rely on them for comprehensive analysis across multiple threat vectors, including phishing emails, malware-infected documents, suspicious PDFs, and abnormal network activity. They assist in extracting and decoding malicious attachments, inspecting embedded macros or scripts, parsing email headers, and validating IOCs from both host and network sources. I also use them to correlate data from logs, PCAPs, and endpoint artifacts to detect and confirm malicious behavior. This curated toolkit allows for quick triage, in-depth investigation, and manual verification, making it an essential reference for efficient incident response, threat hunting, and malware analysis.




## -----Tools and Commands-------- 


## Phishing Analysis Tools:

### 1.)EIOC
---------------------------------
 $ python3 eioc.py sample.eml 

### 2.)EMLDUMP
---------------------------------
$ python3 emldump.py   sample.eml 

#### Dump and extract embedded files or attachments from an email file

$ python3 emldump.py  sample.eml  -s [index number of  flie place ex:5]  -d > sample.docm


### 3.)HASH EXTRACTOR
---------------------------------
$ python3 hash.py  sample.txt 


### 4.)OLEID
---------------------------------
#### The troubleshooting case follows the commands below

$ python3 -m venv myenv

$source myenv/bin/activate

#### Then try the below command:

$ python3 oleid.py sample.docm   



### 5.)OLEDUMP
---------------------------------

#### oledump.py is a tool used to analyze OLE files, which are mostly older Microsoft Office documents. It works with file types like .doc, .xls, .ppt, .docm, .xlsm, and .msg. These files often contain embedded macros or objects, which can be used in phishing or malware attacks. oledump.py helps extract and view these hidden or suspicious components for further analysis.

$python3  oledump.py  sample.docm 

### Viewing Macros or Shellcode from a Document Using oledump.py

$ python3  oledump.py  sample.docm -s A3 -S

$ python3  oledump.py  sample.docm -s A3 -v


### 6.)PDFID
---------------------------------

✅ **Main Indicators of Malicious Activity in the PDF**

| Keyword        | Count | Meaning                                                                 |
|----------------|-------|------------------------------------------------------------------------ |
| /OpenAction    | 1     | 🚨 Automatically executes an action when the PDF is opened. Suspicious. |
| /Launch        | 1     | 🚨 Can be used to execute external files or commands. Very dangerous.  |
| /EmbeddedFile  | 1     | ⚠️ Indicates a file is embedded (e.g., EXE, script). Possible dropper. |
| /JS, /JavaScript | 0   | ✅ No JavaScript — that's good, but not enough to rule out malware.    |
 
$ python3  pdfid.py  pdf-doc-vba-eicar-dropper.pdf 


### 7.)PDF_PARSER
---------------------------------

#### Basic Command ###

 $ python3  pdf-parser.py  samle.pdf | more 

#### Dump and extract embedded files from a PDF file ###

 $ python3  pdf-parser.py  sample-vba-eicar-dropper.pdf  --object 8 --filter --raw  --dump  test.doc 



# PCAP Analysis Methods with tcpdump tool



## 📦 Method 1: Real PCAP Analysis (HTTP Focus)
----------------------------------------------------


##### Note: Avoid using "-n" when analyzing HTTP traffic, so domain names are visible.

##### → Count HTTP packets (no output, just number):

$ tcpdump -r 2024-04-18.pcap -tt port 80 --count

##### → Extract HTTP GET/POST traffic to/from host 10.xx.xx.xx:

$ tcpdump -r 2021-09-14.pcap -tt port http and host 10.xx.xx.xx | grep -E "GET|POST"

##### → Search for specific file names in raw payloads:

$ tcpdump -r 2021-09-14.pcap -tt | grep "audiodg.exe"

##### → Display file-related data in ASCII (500 lines after match):

$ tcpdump -r 2021-09-14.pcap -tt -A | grep "audiodg.exe" -A 500 | less


## 📊 Method 2: Advanced PCAP Analysis (All Protocols)
-----------------------------------------------------------


→ Basic packet count:

$ tcpdump -r file.pcap --count

→ List all TCP packets with timestamps:

$ tcpdump -tt -r file.pcap -n tcp


## 🎯 Find Most Active IPs (Talkers)
----------------------------------

➤ Extract source IPs:

$ tcpdump -tt -r file.pcap -n tcp | cut -d " " -f 3 | cut -d "." -f 1-4 | sort | uniq -c | sort -nr

➤ Extract destination IPs:

$tcpdump -tt -r file.pcap -n tcp | cut -d " " -f 5 | cut -d "." -f 1-4 | sort | uniq -c | sort -nr


## 🔁 Analyze Communication Between Two IPs
-----------------------------------------

➤ Count packets between the suspected source and destination:

$ tcpdump -r file.pcap src host 10.xx.xx.xx and dst host 85.xx.xx.xx --count


## 🔎 Identify Common Ports Used
------------------------------
➤ From 10.xx.xx.xx to 85.xx.xx.xx:

$ tcpdump -r file.pcap -n tcp and src host 10.xx.xx.xx and dst host 85.xx.xx.xx | cut -d " " -f 3 | cut -d "." -f 5 | sort | uniq -c | sort -nr

➤ Reverse (from 85.xx.xx.xx to 10.xx.xx.xx):

$tcpdump -r file.pcap -n tcp and dst host 10.xx.xx.xx and src host 85.xx.xx.xx | cut -d " " -f 3 | cut -d "." -f 5 | sort | uniq -c | sort -nr


## 🌐 Detect HTTP Requests (if unencrypted)
-----------------------------------------

➤ Look for GET or POST requests:

$ tcpdump -r file.pcap src host 10.xx.xx.xx and dst host 85.xx.xx.xx -A | grep -E "GET|POST"


## 🔤 Read Payloads in ASCII
--------------------------

$ tcpdump -r file.pcap host 10.xx.xx.xx and host 85.xx.xx.xx -A


## 🔐 Search for Sensitive Data (e.g., credentials)
------------------------------------------------

➤ Basic credential search:

$ tcpdump -r file.pcap host 85.xx.xx.xx -A | grep -i "pass\|user\|login"

or

$ tcpdump -r tcpdump_challenge.pcap -A port 80 | grep -iE "pass|password|user|login"

➤ Exclude common headers (like User-Agent):

$ tcpdump -r file.pcap host 85.xx.xx.xx -A | grep -i "pass\|user\|login" | grep -v "User-Agent"


## 📁 Search for File Transfers or Names

--------------------------------------

$ tcpdump -r file.pcap host 85.xx.xx.xx -A | grep -i "filename"


## 🌍 Find Domains (via DNS Queries)
----------------------------------

➤ Look for suspicious domains (e.g., t.me):

$ tcpdump -r file.pcap | grep "t.me"

➤ Resolve domains to IPs:

$ tcpdump -r file.pcap host t.me -n


## 🧩 Detect Suspicious File Types (DLLs, EXEs)
--------------------------------------------

$ tcpdump -r file.pcap | grep dll

➤ Read content near DLL references:

$ tcpdump -r file.pcap -A | grep dll -A 50 | less

## Snort Important commands
--------------------------------------------

Snort basic commands:


| Command                 | Description                                    |
| ---                     | -----           |
| `snort -i enp0s3`       | Basic sniffing on interface `enp0s3`           |
| `snort -i enp0s3 -e`    | Shows Ethernet headers                         |
| `snort -i enp0s3 -d`    | Shows application layer data (payload)         |
| `snort -i enp0s3 -x`    | Shows packet data in **hex + ASCII**           |
|  snort -i enp0s3 -l .   | Logs packets into the current directory (.)    |
|  snort -r snort.log     | Reads packet capture file generated by Snort   |


Snort-capable reads logs and pcap files:

$ sudo snort -r  /var/log/snort/snort.log.1750260124 -q  ( Snort save  log file to read )

$ sudo snort -r 1. pcap  -q   -d    ( Common save pcap read  run commands )

🛠️ Alert Modes in Snort:

$ sudo  snort  -i enp0s3  -A fast, console  -c /ect/snort/snort.conf

| Mode                  | Description |
| ---                   | --- |
| fast                  | One-line alerts (default, good for performance). |
| full                  | Detailed multi-line alerts (more info, slower). |
| console               | Alerts shown in terminal (for testing/debugging). |
| unsock                | Alerts sent to a UNIX socket (for advanced setups). |



Snort Intrusion  Commands:

$ sudo snort -A console -l /var/log/snort -i enp0s3 -c /etc/snort/snort.conf -q


$ sudo snort -A fast -l /var/log/snort -i enp0s3 -c /etc/snort/snort.conf -q


Snort prevention commands:

$  sudo snort -q -A console --daq afpacket -i enp0s3:enp0s8 -c /etc/snort/snort.conf -Q

Snort reads the file to detect and prevent commands:

$  sudo snort -q -A console -c /etc/snort/snort.conf  -r snort.pcap
