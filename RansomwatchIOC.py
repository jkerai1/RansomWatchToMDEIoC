import requests
import datetime
import os
import validators
import csv
from pathlib import Path

whitelist =["example.com"] #domains to exclude from blocking

userchoice = input("Searching for posts or groups? ").lower().replace("s","")
if userchoice == "": userchoice = "group"
url = "https://ransomwhat.telemetry.ltd/" 

if userchoice == "pot":
    searchterm = input("search term? ").replace(" ","")
    url = url + "posts"
    print()
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        posts = [post["post_title"] for post in data if post.get("group_name") == searchterm]

        for post_title in posts:
            print(post_title.replace('.','[.]'))
    
    
if userchoice == "group":
    url = url + "groups"
    searchterm = "group search"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        posts = [location["slug"] for group in data for location in group.get("locations", []) if location.get("available") == True]
        #titles = [location["title"] for group in data for location in group.get("locations", []) if location.get("available") == True]
        for slug in posts:
            print(slug.replace('.','[.]'))

    
IOC_Columns = ["IndicatorType","IndicatorValue","ExpirationTime","Action","Severity","Title","Description","RecommendedActions","RbacGroups","Category","MitreTechniques","GenerateAlert"]
stamp = datetime.datetime.now().strftime("%x").replace("/","-")
filename = "Ransomwatch+" + stamp + ".csv"
fopen = Path(filename)
    
if os.path.exists(filename)== False:
    with open(filename, 'a+',newline='') as file:
        writer = csv.writer(file)
        writer.writerow(IOC_Columns)    
    
with open(filename, 'a',newline='') as file:
    writer = csv.writer(file)
    for i in posts: 
        i = i.replace('http://','').replace('https://','')
        if i not in whitelist and i.find('.') and validators.domain(i):
            try:
                writer.writerow(["DomainName",i,"","Block","","Ransomwatch " + searchterm,"https://www.virustotal.com/gui/domain/"+i+"\nTool written by jkerai1","","","","","FALSE"])#Create MDE BlockList
            except: #fallback
                print("   Error")    
    
