<p align="center">
<img src="https://user-images.githubusercontent.com/5906222/133528855-0e73fb1e-e77d-4f50-ab10-7efbe8586d01.gif" height="400">
</p>

# HexCopy
IDA plugin for quickly copying disassembly as encoded hex bytes. This whole plugin just saves you two extra clicks... but if you are frequently copying data from IDA into external tools and scripts this is a must have! 

## Using HexCopy
Highlight the data that you want to copy in the disassembly window then right click and select `Copy Hex`. You can also use the `Ctrl+H` hotkey to copy selected data without any clicks! 

The data will be automatically copied to your clipboard as a hex-encoded string. The hex-encoded string is also printed to the console for quick reference. 

## Installing HexCopy
Simply copy the latest release of [`hexcopy.py`](https://github.com/OALabs/hexcopy-ida/releases) into your IDA plugins directory and you are ready to start copying in hex!

## ❗Compatibility Issues
HexCopy has been developed for use with the __IDA 7+__ and __Python 3__. 

I know many of you are still using Python 2.7 for compatibility with older plugins. We will attempt to continue to support Python 2.7 on IDA 7+ but there are no guarantees. 



