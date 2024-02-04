import requests
import datetime
import os
import validators
import csv
import tldextract
from pathlib import Path

whitelist =["example.com"] #domains to exclude from blocking

userchoice = input("Searching for posts or groups? ").lower().replace("s","") #Normalize user input to some extent
if userchoice == "": userchoice = "group" 
url = "https://ransomwhat.telemetry.ltd/" 

if userchoice == "pot": #stripping s makes it "pot" not "post"
    searchterm = input("search term? ").replace(" ","")
    url = url + "posts"
    print()
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        posts = [post["post_title"] for post in data if post.get("group_name") == searchterm] #As per example on Ransomwatch Github

        for post_title in posts:
            print(post_title.replace('.','[.]'))
        
if userchoice == "group":
    url = url + "groups"
    searchterm = "group search"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        posts = [location["slug"] for group in data for location in group.get("locations", []) if location.get("available") == True] #As per example on Ransomwatch Github
        #titles = [location["title"] for group in data for location in group.get("locations", []) if location.get("available") == True]
        for slug in posts:
            print(slug.replace('.','[.]'))

    
IOC_Columns = ["IndicatorType","IndicatorValue","ExpirationTime","Action","Severity","Title","Description","RecommendedActions","RbacGroups","Category","MitreTechniques","GenerateAlert"]
stamp = datetime.datetime.now().strftime("%x").replace("/","-") 
filename = "Ransomwatch+" + stamp + ".csv"
fopen = Path(filename) 
    
if os.path.exists(filename)== False:
    with open(filename, 'a+',newline='') as file: #Build File
        writer = csv.writer(file)
        writer.writerow(IOC_Columns)    
    
with open(filename, 'a',newline='') as file:
    writer = csv.writer(file)
    for i in posts: 
        i = i.replace('http://','').replace('https://','') #Remove protocol
        i = tldextract.extract(i) #tld extraction could be modified to ignore TLDs that are already blocked (perhaps using windows firewall)
        i = i.domain + "." + i.suffix #Block at highest level where possible
        if i not in whitelist and i.find('.') and validators.domain(i):
            try: #Create Record
                writer.writerow(["DomainName",i,"","Block","","Ransomwatch " + searchterm,"https://www.virustotal.com/gui/domain/"+i+"\nTool written by jkerai1","","","","","FALSE"])
            except: #fallback
                print("   Error")    
    
