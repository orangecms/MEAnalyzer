# ME Analyzer
Intel Engine Firmware Analysis Tool

[ME Analyzer News Feed](https://twitter.com/platomaniac)

[ME Analyzer Discussion Topic](https://www.win-raid.com/t840f39-ME-Analyzer-Intel-Engine-Firmware-Analysis-Tool-Discussion.html)

[Intel Engine Firmware Repositories](https://www.win-raid.com/t832f39-Intel-Engine-Firmware-Repositories.html)

[![ME Analyzer Donation](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=DJDZD3PRGCSCL)

![](https://i.imgur.com/XWRRPEq.png)

## **A. About ME Analyzer**

ME Analyzer is a tool which parses Intel Engine & PMC firmware images from the (Converged Security) Management Engine, (Converged Security) Trusted Execution Engine, (Converged Security) Server Platform Services & Power Management Controller families. It can be used by end-users who are looking for all relevant firmware information such as Family, Version, Release, Type, Date, SKU, Platform etc. It is capable of detecting new/unknown firmware, checking firmware health, Updated/Outdated status and many more. ME Analyzer is also a powerful Engine firmware research analysis tool with multiple structures which allow, among others, full parsing and unpacking of Converged Security Engine (CSE) code & file system, Flash Partition Table (FPT), Boot Partition Descriptor Table (BPDT/IFWI), CSE Layout Table (LT), advanced Size detection etc. Moreover, with the help of its extensive database, ME Analyzer is capable of uniquely categorizing all supported Engine firmware as well as check for any firmware which have not been stored at the Intel Engine Firmware Repositories yet.

#### **A1. ME Analyzer Features**

- Supports all Engine firmware Families (CS)ME 2-14, (CS)TXE 0-4, (CS)SPS 1-5
- Supports all types of firmware images (Engine Regions, SPI/BIOS etc)
- Detection of Family, Version, SKU, Date, Revision, Platform etc info
- Detection of Production, Pre-Production, ROM-Bypass etc Releases
- Detection of Region (Stock/clean or Extracted/dirty), Update etc Types
- Detection of Security Version Numbers (SVN), Version Control Number (VCN)
- Detection of Power Management Controller (PMC) firmware Version, SKU etc
- Detection of whether the imported Engine firmware is updated or not
- Detection of unusual Engine firmware (Corrupted, Compressed, OEM etc)
- Ability to fully unpack CSE firmware CSME 11+, CSTXE 3+ and CSSPS 4+
- Ability to validate Engine RSA Signature and Region table checksums
- Advanced detection & validation of Engine region's firmware Size
- Ability to detect & analyze Integrated Firmware Images (IFWI/BPDT)
- Ability to analyze multiple files by drag & drop or by input path
- Detection of unique Apple Macintosh Engine firmware "Slim" SKUs
- Detection of multiple Engine regions in input file, number only
- Ability to detect & categorize firmware which require attention
- Reports all firmware which are not found at the Engine Firmware Repositories
- Reports any new, unknown, problematic, incomplete etc Engine firmware images
- Features command line parameters to enhance functionality & assist research
- Features user friendly messages & proper handling of unexpected code errors
- Shows colored text to signify the importance of notes, warnings & errors
- Open Source project under permissive license, comment assisted code

#### **A2. Engine Firmware Repository Database**

ME Analyzer allows end-users and/or researchers to quickly analyze and/or report new firmware versions without the use of special Intel tools (FIT/FITC, FWUpdate) or Hex Editors. To do that effectively, a database had to be built. The [Intel Engine Firmware Repositories](http://www.win-raid.com/t832f39-Intel-Management-amp-Trusted-Execution-Engine-Firmware-Repository.html) is a collection of every (CS)ME, (CS)TXE & (CS)SPS firmware we have found. Its existence is very important for ME Analyzer as it allows us to continue doing research, find new types of firmware, compare same major version releases for similarities, check for updated firmware etc. Bundled with ME Analyzer is a file called MEA.dat which is required for the program to run. It includes entries for all Engine firmware that are available to us. This accommodates primarily three actions: a) Detect each firmware's Family via unique identifier keys, b) Check whether the imported firmware is up to date and c) Help find new Engine firmware sooner by reporting them at the [Intel Management Engine: Drivers, Firmware & System Tools](http://www.win-raid.com/t596f39-Intel-Management-Engine-Drivers-Firmware-amp-System-Tools.html) or [Intel Trusted Execution Engine: Drivers, Firmware & System Tools](http://www.win-raid.com/t624f39-Intel-Trusted-Execution-Engine-Drivers-Firmware-amp-System-Tools.html) threads respectively.

#### **A2. Development**

ME Analyzer uses [Python conversions for C structs](https://docs.python.org/3/library/struct.html).


## **B. How to use ME Analyzer**

There are two ways to use ME Analyzer, MEA executable & Command Prompt. The MEA executable allows you to drag & drop one or more firmware and analyze them one by one or recursively scan entire directories. To manually call ME Analyzer, a Command Prompt can be used with -skip as parameter.

#### **B1. ME Analyzer Executable**

To use ME Analyzer, select one or multiple files and Drag & Drop them to its executable. You can also input certain optional parameters either by running MEA directly or by first dropping one or more files to it. Keep in mind that, due to operating system limitations, there is a limit on how many files can be dropped at once. If the latter is a problem, you can always use the -mass parameter to recursively scan entire directories as explained below.

#### **B2. ME Analyzer Parameters**

There are various parameters which enhance or modify the default behavior of ME Analyzer:

* -?      : Displays help & usage screen
* -skip   : Skips welcome & options screen
* -exit   : Skips Press enter to exit prompt
* -mass   : Scans all files of a given directory
* -pdb    : Writes input file DB entry to text file
* -dbname : Renames input file based on unique DB name
* -dfpt   : Shows $FPT, BPDT and/or CSE Layout Table headers
* -unp86  : Unpacks all CSE Converged Security Engine firmware
* -bug86  : Enables pausing on error during CSE unpacking
* -ver86  : Enables full verbose output during CSE unpacking
* -html   : Writes parsable HTML files during MEA operation
* -json   : Writes parsable JSON files during MEA operation

#### **B3. ME Analyzer Error Control**

During operation, ME Analyzer may encounter issues that can trigger Notes, Warnings and/or Errors. Notes (yellow/green color) provide useful information about a characteristic of this particular firmware. Warnings (purple color) notify the user of possible problems that can cause system instability. Errors (red color) are shown when something unexpected or problematic is encountered.

## **C. Download ME Analyzer**

ME Analyzer consists of three files, the executable (MEA.exe or MEA) and the databases (MEA.dat & Huffman.dat). An already built/frozen/compiled binary is provided by me for Windows only (icon designed by [Those Icons](https://thoseicons.com/)). Thus, **you don't need to manually build/freeze/compile ME Analyzer under Windows**. Instead, download the latest version from the [Releases](https://github.com/platomav/MEAnalyzer/releases) tab, title should be "ME Analyzer v1.X.X". You may need to scroll down a bit if there are DB releases at the top. The latter can be used to update the outdated DB which was bundled with the latest executable release, title should be "DB rXX". To extract the already built/frozen/compiled archive, you need to use programs which support RAR5 compression.

#### **C1. Compatibility**

ME Analyzer should work at all Windows, Linux or macOS operating systems which have Python >= 3.7 support. Windows users who plan to use the already built/frozen/compiled binary must make sure that they have the latest Windows Updates installed which include all required "Universal C Runtime (CRT)" libraries.

#### **C2. Code Prerequisites**

To run ME Analyzer's python script, you need to have the following 3rd party Python modules installed:

* [Colorama](https://pypi.org/project/colorama/)

> pip3 install colorama

* [CRCCheck](https://pypi.org/project/crccheck/)

> pip3 install crccheck

* [PLTable](https://github.com/platomav/PLTable/)

> pip3 install pltable

#### **C3. Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile ME Analyzer at all three supported platforms, it is simple to run and gets updated often.

1. Make sure Python 3.7.0 or newer is installed:

> python --version

2. Use pip to install PyInstaller:

> pip3 install pyinstaller

3. Use pip to install colorama:

> pip3 install colorama

4. Use pip to install crccheck:

> pip3 install crccheck

5. Use pip to install PLTable:

> pip3 install pltable

6. Build/Freeze/Compile ME Analyzer:

> pyinstaller --noupx --onefile MEA.py

At dist folder you should find the final MEA executable

#### **C4. Anti-Virus False Positives**

Some Anti-Virus software may claim that the built/frozen/compiled MEA executable contains viruses. Any such detections are false positives, usually of PyInstaller. You can switch to a better Anti-Virus software, report the false positive to their support, add the MEA executable to the exclusions, build/freeze/compile MEA yourself or use the Python script directly.

## **D. Pictures**

**Note:** Some pictures are outdated and depict older ME Analyzer versions.

![](https://i.imgur.com/XWRRPEq.png)

![](https://i.imgur.com/6UNqSe8.png)

![](https://i.imgur.com/9tnZ7lA.png)

![](https://i.imgur.com/v46gBmR.png)

![](https://i.imgur.com/WIATngh.png)

![](https://i.imgur.com/OEBpie6.png)

![](https://i.imgur.com/CYNWoiS.png)

![](https://i.imgur.com/dLVMFlg.png)

![](https://i.imgur.com/3ofDnwl.png)

![](https://i.imgur.com/febB1yM.png)

![](https://i.imgur.com/JGljfRQ.png)

![](https://i.imgur.com/LdYLZrg.png)

![](https://i.imgur.com/XCY7eY6.png)

![](https://i.imgur.com/D012Cpt.png)

![](https://i.imgur.com/cvHhCO2.png)

![](https://i.imgur.com/U4jLUPS.png)

![](https://i.imgur.com/crUf9f9.png)

![](https://i.imgur.com/YEd7frw.png)

![](https://i.imgur.com/QiyR9n8.png)

![](https://i.imgur.com/kSKcpb0.png)

![](https://i.imgur.com/mszfNno.png)
