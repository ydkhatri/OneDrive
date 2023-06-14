# OneDrive

A parser for OneDrive .odl files.

## License
MIT

## Requirements & Installation
Python 3.7+ and the following modules
- construct
- pycryptodome

## Usage
OneDrive logs are stored as binary files with extensions .odl,
.odlgz, .odlsent and .aold usually found in the profile folder of 
a user under the following paths on Windows :
- \AppData\Local\Microsoft\OneDrive\logs\Business1
- \AppData\Local\Microsoft\OneDrive\logs\Personal

On macOS, they are under:
- /Users/\<USER>/Library/Logs/OneDrive/Business1
- /Users/\<USER>/Library/Logs/OneDrive/Personal
- /Users/\<USER>/Library/Logs/OneDrive/Common  
  
On some macOS, they may be here:
- /Users/\<USER>/Library/Containers/com.microsoft.OneDrive-mac/Data/Library/Logs

  
In addition to odl logs, there should be a file named `ObfuscationStringMap.txt`. This file is needed to unobfuscate strings. There is usually only one of these files per OneDrive installation, either in the Personal or Business1 folder, but it is used by all odl logs. You will need to provide the path of this file to the script too (if it is not in the same folder as .odl files).

In newer versions since April 2022, there might not be an ObfuscationStringMap.txt file. Instead you now need the `general.keystore` (in the same location) to unobfuscate strings.

```
% python3 odl.py -h                                                   
usage: odl.py [-h] [-o OUTPUT_PATH] [-s OBFUSCATIONSTRINGMAP_PATH] [-k] [-d]
              odl_folder

OneDrive Log (ODL) reader

positional arguments:
  odl_folder            Path to folder with .odl files

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT_PATH, --output_path OUTPUT_PATH
                        Output file name and path
  -s OBFUSCATIONSTRINGMAP_PATH, --obfuscationstringmap_path OBFUSCATIONSTRINGMAP_PATH
                        Path to ObfuscationStringMap.txt (if not in odl_folder)
  -k, --all_key_values  For repeated keys in ObfuscationMap, get all values | delimited (off by default)
  -d, --all_data        Show all data (off by default)

(c) 2022 Yogesh Khatri,  @swiftforensics
This script will read OneDrive sync logs. These logs are produced by 
OneDrive, and are stored in a binary format having the extensions 
.odl .odlgz .oldsent .aold

Sometimes the ObfuscationMap stores old and new values of Keys. By 
default, only the latest value is fetched. Use -k option to get all 
possible values (values will be | delimited). 

Newer versions of OneDrive since at least April 2022 do not use the
ObfuscationStringMap file. Data to be obfuscated is now AES encrypted
with the key stored in the file general.keystore

By default, irrelevant functions and/or those with empty parameters 
are not displayed. This can be toggled with the -d option.
```

### Example
```
% python3 odl.py -o ~/Desktop/odl_output.csv ~/Desktop/testing
WARNING: Multiple instances of some keys were found in the ObfuscationMap.
Recovered Unobfuscation key Mfv+fea23ca234VpoEc63Vawq+dae82uUKc=, version=1, utf_type=utf16
Read 26401 items from map
Searching  /Users/ykhatri/Desktop/testing/SyncEngine-2022-02-13.0355.840.786.odlgz
Wrote 1 rows
Searching  /Users/ykhatri/Desktop/testing/SyncEngine-2022-02-13.0354.840.775.odlgz
Wrote 40 rows

  ... output snipped ...

Searching  /Users/ykhatri/Desktop/testing/SyncEngine-2022-02-13.0355.840.787.aodl
Wrote 772 rows
Finished processing files, output is at /Users/ykhatri/Desktop/odl_output.csv
```
#### Output Snippet from odl_output.csv
<img width="1275" alt="image" src="https://user-images.githubusercontent.com/13247440/153752356-a513e9c9-7ae8-481a-9d96-d146f8914e68.png">
