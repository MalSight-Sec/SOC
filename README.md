# Description:

These tools and command-line utilities are part of my day-to-day workflow in a Security Operations Center (SOC) environment. I rely on them for comprehensive analysis across multiple threat vectors, including phishing emails, malware-infected documents, suspicious PDFs, and abnormal network activity. They assist in extracting and decoding malicious attachments, inspecting embedded macros or scripts, parsing email headers, and validating IOCs from both host and network sources. I also use them to correlate data from logs, PCAPs, and endpoint artifacts to detect and confirm malicious behavior. This curated toolkit allows for quick triage, in-depth investigation, and manual verification, making it an essential reference for efficient incident response, threat hunting, and malware analysis.




## -----Tools and Commands-------- 


## Phishing Analysis Tools:

### 1.)EIOC  
---------------------------------

###### => This tools automatically extract IOC headers, data, time, subject, attachment files, etc, and attachment file hash 

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

#### Change the virtual ( myenv )  directory to the bin directory AND  this way to access any place that tools or file

$ (myenv) ms@SOC:~$ which floss
/home/ms17/myenv/bin/floss

File change  directory cmd

$ sudo cp -rf  /home/ms17/myenv/bin/filename /usr/bin/ 


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

➤ Resolve domains

$ tcpdump -r file.pcap port 53 -nn

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


# Endpoint analysis Important commands:

## Tools:

Autoruns

Process Explorer

Resitry panel

services Pnael

Task Manager panel

TCP View

Task scheduler panel

Autorun PowerShell module 

Commandline and PowerShell Commands

### Basic Blue team cmds

$ net view
$ net share
$ net session
$ net use

### 1.) Network analysis:

$netstat -anob 

### 2.) Process analysis

$ tasklist /FI "PID eq 3624"
$ tasklist /FI "PID eq 3624" /M ⇒ dll find
$ tasklist /FI “IMAGENAME eq notmalware.exe”


### 3.) Registry analysis

#### Command Line:

⇒ Main paths ( HKCU, HKLM )

HKCU:
$ reg query “HKCU\Software\Microsoft\Windows\CurrentVersion\Run”
$ reg query “HKCU\Software\Microsoft\Windows\CurrentVersion\Runonce”


HKLM:
$ reg query “HKLM\Software\Microsoft\Windows\CurrentVersion\Run”
$reg query “HKLM\Software\Microsoft\Windows\CurrentVersion\Runonce”

#### Powershell:
$ Get-ItemProperty -Path "Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run”

### 4.) Services analysis:

#### Commandline:

1.) $ net start ⇒ ( show all services )

2.) $sc query ⇒ ( show all services extend )

3.) $sc query state=all ( this only shows running services )

4.) $sc query “BackupService” ⇒ ( specific service show )

5.) sc qc BackupService ⇒ (specific service execution binary and path show )



#### Powershell:

1.) $ Get-service ⇒ ( show all services )

2.) $ Get-Service | Where-Object { $_.status -eq "Running" } ⇒ ( Only running services )

3.) $Get-Service -Name "BackupService” ⇒  ( specific service show )

4.) $ Get-Service -Name "B*” ⇒  ( Only extract “B” letter service )

5.) $ Get-Service -Name “BackupService” | Select-Object “ ⇒ ( Only extend version ) 

6.) $ Get-WmiObject -Class Win32_Service -Filter "Name = 'BackupService'" | Select-Object * ⇒ ( wmi Advanced Command and this wmi but a new version of PowerShell supports and an  old version supports)

7.) $ Get-CimInstance -Class Win32_Service -Filter "Name = 'BackupService'" | Select-Object * ⇒ ( same but this ciminstance new version PowerShell support not old version support )

###  5.) Task analysis:

#### ⇒ Command Line:

CMD.exe Run as admin

1.) $ schtasks /query /fo LIST ⇒ ( List all services )

2.) $ schtasks /query /tn “SystemCleanup” ⇒ ( show specific services details)

3.) $ schtasks /query /tn “SystemCleanup” /v ⇒ ( more details get )

4.) $ schtasks /query /tn “SystemCleanup” /v /fo LIST ⇒ ( much better output )

##### General methodology: look for any scheduled tasks

1 admin

2 privileged users

3 system users account

4 No user's name set

5 Task runs suspicious location

6 anything outside of the typical system folders

7 task abnormal execution frequencies ( if tasks are running every minute or every 30 seconds)

### 4.) Autoruns PowerShell for all analysis like Registry, Services, Task

#### Let Practical:

⇒ Shortly, this process explains create two Snapchats one create without malware
execute, and another one is created after the malware executes

⇒ If the changes case shows that is process runs ok, let's see 

#### Install the autoruns module in PowerShell

$  Set-ExecutionPolicy  Unrestricted

$ Import-Module  .\AutoRuns.psm1

$ Get-Module => ( Check autoruns available or not available )



#### Process  to run the autoruns  baseline module in PowerShell



1.) Create directory ( mkdir baseline )


2.) Create Snapchat without malware execution 

##### New-AutoRunsBaseLine - Baseline:

$ Get-PSAutorun -VerifyDigitalSignature |

Where { -not($_.isOSbinary)} |

New-AutoRunsBaseLine -Verbose -FilePath .\Baseline.ps1

3.)Create another Snapchat  after malware execution 

##### New-AutoRunsBaseLine - CurrentState:

$ Get-PSAutorun -VerifyDigitalSignature |

Where { -not($_.isOSbinary)} |

New-AutoRunsBaseLine -Verbose -FilePath .\CurrentState.ps1

4.) Finally, compare the two results:

$ Compare-AutoRunsBaseLine -ReferenceBaseLineFile .\Baseline.ps1 DifferenceBaseLineFile .\CurrentState.ps1 -Verbose


# Events Logs Analysis Commands:

## Important Cmds:

### CMD.exe

#### Live Security Event analysis cmd  via cmd.exe:

#####  Security Event Cmd.exe

$  powershell -NoProfile -Command "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4720,4722,4723,4724,4738,4725,4726,4732,4688,1102} | Format-List *"

$ powershell -NoProfile -Command "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4720,4722,4723,4724,4738,4725,4726,4732,4688,1102} | Format-List * | Out-File -Encoding utf8 'C:\\Users\\soc\\Desktop\\SecurityEvents.txt'"

#####  Security Logs output file analysis cmd via cmd.exe:

#####  Security logs Event Cmd.exe


$  powershell -NoProfile -Command "Get-WinEvent -Path 'C:\\Users\\soc\\Desktop\\03_Endpoint_Security\\Windows\\Challenges\\challenge.evtx' | Where-Object { $_.Id -in 4720,4722,4723,4724,4738,4725,4726,4732,4688,1102 } | Format-List *"

$ powershell -NoProfile -Command "Get-WinEvent -Path 'C:\\Users\\soc\\Desktop\\03_Endpoint_Security\\Windows\\Challenges\\challenge.evtx' | Where-Object { $_.Id -in 4720,4722,4723,4724,4738,4725,4726,4732,4688,1102 } | Format-List * | Out-File -Encoding utf8 'C:\\Users\\soc\\Desktop\\FilteredEvents.txt'"

###  Live system event analysis cmd  via cmd.exe :

###### System Event  Cmd.exe

$  powershell -NoProfile -Command "Get-WinEvent -FilterHashtable @{LogName='Security'; ID= 7045,7030,7035,7036 } | Format-List *"

$ powershell -NoProfile -Command "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=7045,7030,7035,7036} | Format-List * | Out-File -Encoding utf8 'C:\\Users\\soc\\Desktop\\SecurityEvents.txt'"

###  Systems Log output file analysis cmd via cmd.exe:

$  powershell -NoProfile -Command "Get-WinEvent -Path 'C:\\Users\\soc\\Desktop\\03_Endpoint_Security\\Windows\\Challenges\\challenge.evtx' | Where-Object { $_.Id -in  7045,7030,7035,7036  } | Format-List *"

$ powershell -NoProfile -Command "Get-WinEvent -Path 'C:\\Users\\soc\\Desktop\\03_Endpoint_Security\\Windows\\Challenges\\challenge.evtx' | Where-Object { $_.Id -in  7045,7030,7035,7036 } | Format-List * | Out-File -Encoding utf8 'C:\\Users\\soc\\Desktop\\FilteredEvents.txt'"

## Powershell.exe

### Live security event analysis cmd via powershell:

#####  security event PowerShell

$  Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4720,4722,4723,4724,4738,4725,4726,4732,4688,1102} | Format-List  *

$ Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4720,4722,4723,4724,4738,4725,4726,4732,4688,1102} | Format-List  * | Out-File -Encoding utf8 "C:\Users\soc\Desktop\SecurityEvents.txt"   ⇒ ( Use real analysis case )

###  Live system event analysis cmd via powershell:

#####   System event PowerShell

$ Get-WinEvent -FilterHashtable @{LogName="System"; ID=7045,7030,7035,7036} | Format-List *

$ Get-WinEvent -FilterHashtable @{LogName="System"; ID=7045,7030,7035,7036} | Format-List * | Out-File -Encoding utf8 "C:\Users\soc\Desktop\SecurityEvents.txt"

###  Security event Log output file analysis cmd via powershell:

#####  Security   event PowerShell

$Get-WinEvent -Path "C:\Users\soc\Desktop\03_Endpoint_Security\Windows\Challenges\challenge.evtx" | Where-Object { $_.Id -in 4720,4722,4723,4724,4738,4725,4726,4732,4688,1102 } | Format-List * 

$ Get-WinEvent -Path "C:\Users\soc\Desktop\03_Endpoint_Security\Windows\Challenges\challenge.evtx" | Where-Object { $_.Id -in 4720,4722,4723,4724,4738,4725,4726,4732,4688,1102 } | Format-List * | Out-File "C:\Users\soc\Desktop\FilteredEvents.txt" -Encoding utf8

###  System  Log output file analysis command via PowerShell:

#####  System  event PowerShell

$ Get-WinEvent -Path "C:\Users\soc\Desktop\03_Endpoint_Security\Windows\Challenges\challenge.evtx" | Where-Object { $_.Id -in 7045,7030,7035,7036 } | Format-List *

$ Get-WinEvent -Path "C:\Users\soc\Desktop\03_Endpoint_Security\Windows\Challenges\challenge.evtx" | Where-Object { $_.Id -in 7045,7030,7035,7036 } | Format-List * | Out-File "C:\Users\soc\Desktop\FilteredEvents.txt" -Encoding utf8




