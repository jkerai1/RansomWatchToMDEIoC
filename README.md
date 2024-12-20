[![GitHub stars](https://img.shields.io/github/stars/jkerai1/RansomWatchToMDEIoC?style=flat-square)](https://github.com/jkerai1/RansomWatchToMDEIoC/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/jkerai1/RansomWatchToMDEIoC?style=flat-square)](https://github.com/jkerai1/RansomWatchToMDEIoC/network)
[![GitHub issues](https://img.shields.io/github/issues/jkerai1/RansomWatchToMDEIoC?style=flat-square)](https://github.com/jkerai1/RansomWatchToMDEIoC/issues)
[![GitHub pulls](https://img.shields.io/github/issues-pr/jkerai1/RansomWatchToMDEIoC?style=flat-square)](https://github.com/jkerai1/RansomWatchToMDEIoC/pulls)
# RansomWatchToMDEIoC
Parse Ransomwatch results in python and create MDE IOC lists as you search. 

https://ransomwatch.telemetry.ltd/    

There is a limit of 500 IOCs per CSV in MDE, if you need to split out the IOCs, please see: https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/Scripts/MDE-IOC-Batch-Separator.py  

## Required Libraries for validating domains:  
```
pip install validators
pip install tldextract
```
# Example Usage

![image](https://github.com/jkerai1/RansomWatchToMDEIoC/assets/55988027/e1b568e6-add6-4ad8-a3bf-bb05f27af5d1)

# How to Bulk Import IOCs

![image](https://github.com/jkerai1/RansomWatchToMDEIoC/assets/55988027/a90d7f32-0a9b-451f-953f-e9c6fac6b151)

# See also MDE IOC/TenantAllowBockList Repos for   
DNSTwist: https://github.com/jkerai1/DNSTwistToMDEIOC  
JoeSandBox: https://github.com/jkerai1/JoeSandBoxToMDEBlockList   
TLD: https://github.com/jkerai1/TLD-TABL-Block  

# Map
![image](https://github.com/jkerai1/RansomWatchToMDEIoC/assets/55988027/f31e288a-5bb4-437b-a8f0-a9a2729e5bbd)

# Ransomwatch Repo  

https://github.com/joshhighet/ransomwatch
