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



### Windows Hash EXTRACT

---------------------------------

$ get-filehash .\test.iso

$ get-filehash  .\test.iso  -algorithm md5

$ get-filehash  .\test.iso  -algorithm sha1

 #### Compain commands for hash extraction

$ get-filehash .\test.iso get-filehash  .\test.iso  -algorithm md5; get-filehash  .\test.iso  -algorithm sha1



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


## Wireshark

##### 📘 Wireshark Display Filter – Important Rules

| 📌 Purpose                                 | 🧪 Display Filter                                 |
|-------------------------------------------|--------------------------------------------------|
| All HTTP requests                          | `http.request`                                   |
| Only POST requests                         | `http.request.method == "POST"`                  |
| Only GET requests                          | `http.request.method == "GET"`                   |
| URI contains suspicious file (e.g. .exe)   | `http.request.uri contains "audiodg.exe"`        |
| DNS query to specific domain               | `dns.qry.name == "example.com"`                  |
| HTTP traffic on port 80                    | `tcp.port == 80`                                 |
| Match specific IP address (src or dst)     | `ip.addr == 192.168.0.1`                         |
| HTTP payload contains "login" keyword      | `http contains "login"`                          |
| HTTP payload contains "audiodg.exe"        | `http contains "audiodg.exe"`                    |
| User-Agent contains "sqlmap"               | `http.user_agent contains "sqlmap"`              |
| User-Agent contains "Mozilla"             | `http.user_agent contains "Mozilla"`             |
| User-Agent contains "python-requests"      | `http.user_agent contains "python-requests"`     |
| Referrer contains "example.com"            | `http.referer contains "example.com"`            |
| HTTP requests from specific source IP      | `ip.src == 10.0.0.5 and http.request`            |
| Filter by TCP stream number                | `tcp.stream eq 3`                                |
| Detect executable download attempt         | `http.request.uri contains ".exe"`               |
| Filter for Specific Status Codes           | `http.response.code == 200 or http.response.code >= 400`               |
| Filter for Full http request               | `http.request.full_uri `               |




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
|  sudo snort -T -c /etc/snort.conf    | Once snort config rules,  then check broken or come  |


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

## Windows Endpoint analysis commands:

## Tools:

Autoruns

Process Explorer

Resitry panel

services Pnael

Task Manager panel

TCP View

Task scheduler panel

Autorun PowerShell module 

Sysmon

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

### WMIC

$ wmic  process where processid=6036 get name, parentprocessid , processid  ⇒ 📌  Get process name, PID, and its parent PID.

$ wmic  process  get name, parentprocessid , processid  | find “192”  ⇒  📌  Find all processes with “192” in output (e.g., PIDs, names).

$ wmic process where processid=2832 get commandline ⇒   📌 Get the command line that started the process.

##### Note ⇒  📌 Normally, you run notmalware.exe  execute  case, use    cmd.exe,   so the  first  parent process is cmd.exe and the child process is notmalware.exe


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

⇒ Shortly, this process explains create two Snapchats, one created without malware
execute, and another one is created after the malware executes

⇒ If the changes case shows that the process runs ok, let's see 

#### Install the autoruns module in PowerShell

$  Set-ExecutionPolicy  Unrestricted

$ Import-Module  .\AutoRuns.psm1

$ Get-Module => ( Check autoruns available or not available )



#### Process  to run the autoruns  baseline module in PowerShell



1.) Create a directory ( mkdir baseline )


2.) Create Snapchat without malware execution, which means fresh

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

# Important logs:

### Security Logs

| ID   | Event Description                                         |
|------|-----------------------------------------------------------|
| 4624 | An account was successfully logged on                     |
| 4720 | A user account was created                                |
| 4722 | A user account was enabled                                |
| 4723 | An attempt was made to change an account's password       |
| 4724 | An attempt was made to reset an account's password        |
| 4738 | A user account was changed                                |
| 4725 | A user account was disabled                               |
| 4726 | A user account was deleted                                |
| 4732 | A member was added to a security-enabled local group      |
| 4688 | A new process has been created                            |
| 1102 | The audit log was cleared                                 |


### System Logs

| ID   | Event Description                                         |
|------|-----------------------------------------------------------|
| 7045 | A service was installed in the system                     |
| 7030 | The Service Control Manager tried to take a corrective action (Restart the service) |
| 7035 | The Service Control Manager is transitioning services to a running state |
| 7036 | The Service Control Manager has reported that a service has entered the running state |


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


## Sysmon XML query via Event Viewer:

### Event Viewer: Process ID XML Query

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

<QueryList>
<Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
<Select Path="Microsoft-Windows-Sysmon/Operational"> *[System[Provider[@Name='Microsoft-Windows-Sysmon']]] and *[EventData[Data[@Name='ProcessId'] and (Data='<ENTER YOUR PID HERE>')]] </Select>
</Query>
</QueryList>

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Event Viewer: Process ID XML Query - Process Creation Events

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


<QueryList>
<Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
<Select Path="Microsoft-Windows-Sysmon/Operational">
*[System[Provider[@Name='Microsoft-Windows-Sysmon'] and (EventID=1)]]
and
*[EventData[Data[@Name='ProcessId'] and (Data='<ENTER YOUR PID HERE>')]]
</Select>
</Query>
</QueryList>

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


## Sysmon via powershell:


$ Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational"

$ Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational"; id=1}

$ Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational"; id=3} -MaxEvents 1 | Format-List *

$ Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System/EventID=3 and EventData[Data[@Name='DestinationPort']='4444']]" | Format-List *

$ Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System/EventID=1]"

$ Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System/EventID=1 and EventData[Data[@Name='ProcessId']='<ENTER YOUR PID HERE>']]" | Format-List *


# Important Commands for Linux Endpoint Analysis:

## Network analysis:

$  sudo netstat -tnp  ( or )  netstat -atnp 

$  sudo netstat -tulnp

$ sudo ss  -tnp

$ sudo lsof -i -P

$ sudo lsof -p <PID>

## Process analysis:

#### What process runs the system?:

$ sudo ps

$ sudo ps -u <username>

$ sudo ps -AFH | less

$ sudo ps -p < parent or child process_id > -F

$ sudo ps --ppid <parent id 3764 >  -F

#### Find the parent-child process using pstree:

$pstree => show hierarchical view

$pstree -p -s <process_id> => more suitable specific process


#### The dynamic update running process uses top:

$sudo top => show all processes and dynamically update all new processes

$sudo top -u  ms17 => extract specific uses

$sudo top -u  ms17 -c => show command of execute

$sudo top -u ms17 -c -o -TIME+ => Capture recently process



## proc directory find all processes:

$cd /proc/3894  =>  show all processes and dynamically update all new processes ( this is very important because even delete a file during running, it runs background the proc directory)  

##### some import file to proc reverse shell directory:

$ cat cmdline => cmd execute file name

$ cwd => malware execution location or malware name  

$cat environ  | tr '\0' '\n'  =>  It contains the environment variables of the running process (in string format).

Example: PATH, USER, HOME, LANG, SHELL, SECRET_KEY, etc.

but our case important  username=tcm , and  home=/home/tcm

$exe => ls -al exe  ( show what file and malware execute location )

##  Delete the file but run background  in proc dir analysis:

#### Note that even malware delete case process runs background because that runs a virtual file ( proc directory), which means it runs in memory.

$ps -AHF | gerp "notmalware"

⇒ Create a backup malware file

⇒  and DELETE the malware file

$ps -AHF | grep "notmalware" | grep -v grep

$ lsof -p <malware process id>  = (in that case, malware runs background, even malware file is deleted)

$ lsof +L1 => This command views all deleted files, even those running in the  background

I you check go proc directory and see that still available

## Crontab analysis:

$ cat /etc/crontab => we can see malicious commands or files

$  ls -al /var/spool/cron/crontabs/  => which users use crontab

$ sudo  cat   /var/spool/cron/crontabs/<user_name> => Read user file

##### Instead, another analysis  cmds:

$  sudo crontab -u tcm -l

### Analysis crontab main directory

$ ls -al /etc | grep cron

### ⇒ Check all the directories, like copy hash  and  paste virustotal

cron.d

cron.daily

cron.hourly

cron.yearly

cron.weakly

cron.monthly

# Log analysis:

#### Manual  Logs analysis:

#### Key Linux Log Files to Analyze (Security-Relevant)


| 📁 Log File                                         | 🔎 Purpose |
| ---                                                 | --- |
| `/var/log/auth.log` (Debian)                        | Authentication events (login, sudo, SSH, failures, etc.) |
| `/var/log/secure` (RHEL/CentOS)                     | Same as `auth.log` (for RedHat-based systems) |
| `/var/log/syslog`                                   | System-wide logs, including services |
| `/var/log/messages`                                 | Kernel + system logs (RHEL-based) |
| `/var/log/cron`                                     | Cron job execution logs |
| `/var/log/wtmp`                                     | Binary log of user logins/logouts – use `last` |
| `/var/log/btmp`                                     | Failed login attempts – use `lastb` |
| `/var/log/dmesg`                                    | Kernel ring buffer (boot, hardware, drivers) |
| `/var/log/bash_history`                             | Shell command history (if not cleared by attacker) |
| `/var/log/audit/audit.log                         ` | SELinux/auditd logs (if auditd is enabled) |
| `/var/log/httpd/access_log`                         | Web server logs (Apache/Nginx) – good for web attack tracing |


### 🛠️ Manual Log Analysis Techniques:

###### View SSH login attempts
$ grep 'sshd' /var/log/auth.log

###### View failed login attempts
$ grep 'Failed password' /var/log/auth.log

###### View successful logins
$ grep 'Accepted password' /var/log/auth.log

###### Check for new user creation
$ grep 'useradd' /var/log/auth.log

###### Review Command Execution (if bash history available)

$ cat ~/.bash_history


## Auto Logs analysis:

$ sudo logwatch --detail High --service All --range today --format text

$ sudo logwatch --detail High --range today > /tmp/log_report.txt


# Logs analysis: Important methodology 

### Important Commands:

$ file test.log

$ head -n 1 test.log

### Most IP talks:

$ cut test.log -d “ “ -f 1  |  sort |  uniq -c  | grep -v “ 1 “ | sort -nr 

### Found suspicious User agent:

$ cut challenge.log  -d " \ ""  -f 6  |  sort |  uniq -c

### Find the extract value:

$ grep "Nmap Scripting Engine" access.log

$ grep "Nmap Scripting Engine" access.log   | awk '{print $1}' | sort  | uniq -c

### Brute force trace:

=> site redirect 302 301 and most modern web 200 use

$ grep "Mozilla/5.0 (Hydra)"  access.log  | awk  '{print $9}'

$ grep "Mozilla/5.0 (Hydra)"  access.log  | awk  '$9 > 200'

$ grep "Mozilla/5.0 (Hydra)"  access.log  | grep  -v "/login.php"

## Grep:

$ grep -c "404" access.log

$ grep -n "404" access.log

$ grep -E '%3C|%3E|<|>' access.log

$ grep -E '\.\./|%2E%2E%2F|%2E%2E%2E%2E%2F%2F' access.log


## 🔍 Use `grep` Patterns for Web Attack Detection:

### 1. SQL Injection (SQLi)




$ grep -Ei "(\%27)|(\')|(\-\-)|(\%23)|(#)|(\bUNION\b)|(\bSELECT\b)|(\bINSERT\b)|(\bUPDATE\b)|(\bDELETE\b)" access.log



### 2. Cross-Site Scripting (XSS)



$ grep -Ei "(\<script\>)|(%3Cscript%3E)|(\bon\w+=)|(\balert\b)|(\bconfirm\b)|(\bdocument\.cookie\b)" access.log


### 3. Command Injection



$ grep -Ei "(;|\&\&|\|\||\`|\$\(.*\)|\bcat\b|\bwget\b|\bcurl\b|\bnc\b|\bping\b|\bpython\b|\bbash\b)" access.log



### 4. Local File Inclusion (LFI)



$ grep -Ei "(\.\./)|(%2e%2e%2f)|(/etc/passwd)|(/proc/self/environ)" access.log



### 5. Remote File Inclusion (RFI)



$ grep -Ei "(http[s]?:\/\/.*\.(php|txt|jpg|gif|png))" access.log



### 6. Path Traversal



$ grep -Ei "(\.\./|\.\.\\)" access.log



### 7. PHP Injection or Execution



$ grep -Ei "(\bphpinfo\b)|(\beval\b)|(\bsystem\b)|(\bexec\b)|(\bpopen\b)|(\bpassthru\b)" access.log



### 8. User-Agent Based Attacks (like scanners or bots)



$ grep -Ei "(nikto|acunetix|sqlmap|nessus|nmap|curl|wget)" access.log



### 🔁 Combine With Other Filters

#### To find only  suspicious GET requests:



$ grep -Ei "GET .*((\.\./)|(\<script\>)|(\bUNION\b))" access.log



#### To find requests by a specific IP:



$ grep "192.168.1.10" access.log | grep -Ei "(select|union|<script>)"




## Jq uses:

$ jq . access.log

$ jq 'length' events.json

$ jq 'map(.event)' event.json

#### child:

$ jq '.[] | select(.event.PROCESS_ID == 3532)' event.json

$ jq '.[] | select(.event.PROCESS_ID == 3532) | .event.HASH' event.json

#### Parent:

$ jq '.[] | select(.event.PROCESS_ID == 3532) | .event.PARENT' event.json

$ jq '.[] | select(.event.PROCESS_ID == 3532) | .event.PARENT.PROCESS_ID' event.json

#### 🔐 SOC-Worthy Fields to Hunt Malware in JSON Logs

|     No. |  Field Name          |
| ------: | --------------------- |
|       1 | `PROCESS_ID`          |
|       2 | `PARENT_PROCESS_ID`   |
|       3 | `FILE_PATH`           |
|       4 | `FILE_IS_SIGNED`      |
|       5 | `SIGNER_NAME`         |
|       6 | `COMMAND_LINE`        |
|       7 | `USER_NAME`           |
|       8 | `THREADS`             |
|       9 | `MEMORY_USAGE`        |
|      10 | `BASE_ADDRESS`        |
|      11 | `CHILD_PROCESSES`     |
|      12 | `NETWORK_CONNECTIONS` |
|      13 | `HASH`                |
|      14 | `INJECTED_INTO`       |
|      15 | `CREATION_TIME`       |
|      16 | `WORKING_DIRECTORY`   |


### Automation Code:

json_alert.sh ⇒ Use this script for automation

