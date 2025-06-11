# -----Tools and Commands-------- 

## Phishing Analysis Tools:

### 1.)EIOC

 $ python3 eioc.py sample.eml 

### 2.)EMLDUMP

$ python3 emldump.py   sample.eml 

#### Dump and extract embedded files or attachments from an email file

$ python3 emldump.py  sample.eml  -s [index number of  flie place ex:5]  -d > sample.docm


### 3.)HASH EXTRACTOR

$ python3 hash.py  sample.txt 


### 4.)OLEID

#### The troubleshooting case follows the commands below

$ python3 -m venv myenv

$source myenv/bin/activate

#### Then try the below command:

$ python3 oleid.py AR_Wedding_RSVP.docm   



### 5.)OLEDUMP

#### oledump.py is a tool used to analyze OLE files, which are mostly older Microsoft Office documents. It works with file types like .doc, .xls, .ppt, .docm, .xlsm, and .msg. These files often contain embedded macros or objects, which can be used in phishing or malware attacks. oledump.py helps extract and view these hidden or suspicious components for further analysis.

$python3  oledump.py  sample.docm 

### Viewing Macros or Shellcode from a Document Using oledump.py

$ python3  oledump.py  sample.docm -s A3 -S

$ python3  oledump.py  sample.docm -s A3 -v


### 6.)PDFID

✅ **Main Indicators of Malicious Activity in the PDF**

| Keyword        | Count | Meaning                                                                 |
|----------------|-------|------------------------------------------------------------------------ |
| /OpenAction    | 1     | 🚨 Automatically executes an action when the PDF is opened. Suspicious. |
| /Launch        | 1     | 🚨 Can be used to execute external files or commands. Very dangerous.  |
| /EmbeddedFile  | 1     | ⚠️ Indicates a file is embedded (e.g., EXE, script). Possible dropper. |
| /JS, /JavaScript | 0   | ✅ No JavaScript — that's good, but not enough to rule out malware.    |
 
$ python3  pdfid.py  pdf-doc-vba-eicar-dropper.pdf 


### 7.)PDF_PARSER

#### Basic Command ###

 $ python3  pdf-parser.py  samle.pdf | more 

#### Dump and extract embedded files from a PDF file ###

 python3  pdf-parser.py  sample-vba-eicar-dropper.pdf  --object 8 --filter --raw  --dump  test.doc 
