#For Alexa Rank
import urllib.request, sys, re
import xmltodict, json
#for num_of subdomain and prefix-suffix
from tldextract import extract
#for whois
from datetime import date
from bs4 import BeautifulSoup
import bs4
import requests
#for SSL
import ssl
import regex
import socket
#for whois
import pandas as pd
import whois 
#import time


def url_length(url):
	return len(url)

def having_at(url):
	if '@' in url:
		return 1#'Yes'
	else:
		return 0#'No'

def is_ip(url):
    index = 0
    if url[:5] == 'http:':
        index = 7
    elif url[:5] == 'https':
        index = 8
    ips = url[index:index+15].split('.')
    if len(ips) == 4:
        if '/' in ips[3]:
            temp = ips[3].split('/')
            ips[3] = temp[0] 
        if ips[0].isdigit() and ips[1].isdigit() and ips[2].isdigit() and ips[3].isdigit():
            return 1#'Yes'
        else:
            return 0#'No'
    else:
        return 0#'No'

def alexa_rank(url):
    index = 0
    if url[:5] == 'http:':
        index = 7
    elif url[:5] == 'https':
        index = 8
    url = url[index:]
    rank = 2147483647
    try:
        xml = urllib.request.urlopen('http://data.alexa.com/data?cli=10&dat=s&url={}'.format(url)).read() 
        result= xmltodict.parse(xml)
        data = json.dumps(result).replace("@","")
        data_tojson = json.loads(data)
        url = data_tojson["ALEXA"]["SD"][1]["POPULARITY"]["URL"]
        rank= data_tojson["ALEXA"]["SD"][1]["POPULARITY"]["TEXT"]
    except:
        rank = 2147483647
    return rank


def no_of_subdomain(url):
    subDomain, domain, suffix = extract(url)        
    result = subDomain.count('.')+1
    return result

def prefix_suffix(url):
    subDomain, domain, suffix = extract(url)        
    if domain.find('-') == -1:
        return 0#'No'
    else:
        return 1#'Yes'

def url_anchor(url,soup,domain):
    percentage = 0
    i = 0
    unsafe=0
    if soup == -999:
        return 0
    else:
        for a in soup.find_all('a', href=True):
            if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (url in a['href'] or domain in a['href']):
                unsafe = unsafe + 1
            i = i + 1
        try:
            percentage = unsafe / float(i) * 100
            return int(percentage)

        except Exception:
            return 0

def links_in_tags(url,soup,domain):
    i=0
    success =0
    if soup == -999:
        return 0
    else:
        for link in soup.find_all('link', href= True):
           dots=[x.start(0) for x in re.finditer('\.',link['href'])]
           if url in link['href'] or domain in link['href'] or len(dots)==1:
              success = success + 1
           i=i+1

        for script in soup.find_all('script', src= True):
           dots=[x.start(0) for x in re.finditer('\.',script['src'])]
           if url in script['src'] or domain in script['src'] or len(dots)==1 :
              success = success + 1
           i=i+1
        try:
            percentage = success / float(i) * 100
            return int(percentage)
        except:
            return 100

def url_redirect(url,response):
	if response != "" and response.history:
		return 1#'True'
	else:
		return 0#'False'

def SSLfinal_State(url):
    try:
		#check wheather contains https       
        if(regex.search('^https',url)):
            usehttps = 1
        else:
            usehttps = 0
            return 0#-1 phishy
		#getting the certificate issuer to later compare with trusted issuer 
        #getting host name
        subDomain, domain, suffix = extract(url)
        host_name = domain + "." + suffix
        context = ssl.create_default_context()
        sct = context.wrap_socket(socket.socket(), server_hostname = host_name)
        sct.connect((host_name, 443))
        certificate = sct.getpeercert()
        issuer = dict(x[0] for x in certificate['issuer'])
        certificate_Auth = str(issuer['commonName'])
        certificate_Auth = certificate_Auth.split()
        if(certificate_Auth[0] == "Network" or certificate_Auth == "Deutsche"):
            certificate_Auth = certificate_Auth[0] + " " + certificate_Auth[1]
        else:
            certificate_Auth = certificate_Auth[0] 
        trusted_Auth = ['Comodo','Symantec','GoDaddy','GlobalSign','DigiCert','StartCom','Entrust','Verizon','Trustwave','Unizeto','Buypass','QuoVadis','Deutsche Telekom','Network Solutions','SwissSign','IdenTrust','Secom','TWCA','GeoTrust','Thawte','Doster','VeriSign']        
		#getting age of certificate
        startingDate = str(certificate['notBefore'])
        endingDate = str(certificate['notAfter'])
        startingYear = int(startingDate.split()[3])
        endingYear = int(endingDate.split()[3])
        Age_of_certificate = endingYear-startingYear
        
		#checking final conditions
        if((usehttps==1) and (certificate_Auth in trusted_Auth) and (Age_of_certificate>=1) ):
            return 2#1 legitimate
        elif((usehttps==1) and (certificate_Auth not in trusted_Auth)):
            return 1#0 suspicious
        else:
            return 0#-1 phishing
        
    except Exception:
        return 0#-1 phishy


def sfh(url, soup, domain):
	if soup != -999:
	    for form in soup.find_all('form', action=True):
	        if form['action'] == "" or form['action'] == "about:blank":
	            return 0#-1
	        elif url not in form['action'] and domain not in form['action']:
	            return 1#0
	        else:
	            return 2#1
	    return 2#1
	else:
		return 0#-1


def submitting_to_email(soup):
	if soup != -999:
	    for form in soup.find_all('form', action=True):
	        if "mailto:" in form['action']:
	            return 0#-1
	        else:
	            return 1
	    return 1
	else:
		return 0#-1


def links_pointing(url,response):
    if response == "":
        return -1
    else:
        number_of_links = len(re.findall(r"<a href=", response.text))
        if number_of_links == 0:
            return -1
        elif number_of_links <= 2:
            return 0
        else:
            return 1


def calculate_age(a,b):
    if a == 'before Aug-1996':
        a = '1996-07-01'
        if b == '0000-00-00':
            b = '2025-07-07'
    a1 = a.split('-')
    b1 = b.split('-')
    d0 = date(int(a1[0]),int(a1[1]),int(a1[2]))
    d1 = date(2019,2,28)
    d2 = date(int(b1[0]),int(b1[1]),int(b1[2]))
    age = d1-d0
    r_age = d2-d1
    return age.days,r_age.days


def whois_age(url):
    c_date,e_date = '0','0'
    try:
        subDomain, domain, suffix = extract(url)
        res = requests.get("https://www.whois.com/whois/" + domain+'.'+suffix)
        soup = bs4.BeautifulSoup(res.text,'lxml')
        content = soup.select('.df-block')
        if len(content) > 0:
            rows = content[0].select('.df-row')
            for row in rows:
                if row.select('.df-label')[0].text == 'Registered On:':
                    c_date = row.select('.df-value')[0].text
                    c = 1
                elif row.select('.df-label')[0].text == 'Expires On:':
                    e_date = row.select('.df-value')[0].text
                    e = 1
                #elif row.select('.df-label')[0].text == 'Updated On:':
                    #updation_date.append(row.select('.df-value')[0].text)
            if c == 0:
                c_date = '0'
            if e == 0:
                e_date = '0'
        else:
            c_date = '0'
            e_date = '0'

    except Exception:
        c_date = '0'
        e_date = '0'
    if c_date != '0' and e_date != '0':
    	return calculate_age(c_date,e_date)
    else:
        return 0,0


def whois_age2(url):
    try:
        subDomain, domain, suffix = extract(url)
        w = whois.whois(domain+'.'+suffix)
        res1,res2 = 0,0
        if type(w['creation_date']) not in [list,type(None)]:
            res1 = (pd.to_datetime('today')-w['creation_date']).days
        elif type(w['creation_date']) == list:
            res1 = (pd.to_datetime('today')-w['creation_date'][0]).days
        else:
            res1 = 0
        if type(w['expiration_date']) not in [list,type(None)]:
            res2 = (w['expiration_date']-pd.to_datetime('today')).days
        elif type(w['expiration_date']) == list:
            res2 = (w['expiration_date'][0]-pd.to_datetime('today')).days
        else:
            res2 = 0
        return res1,res2
    except Exception:
        return 0,0

def calculate_features(url):
    features = []
    response = ''
    soup = 0
    try:
        response = requests.get(url,timeout=20)
        soup = BeautifulSoup(response.text, 'html.parser')
    except:
        response = ''
        soup = -999

    subDomain, domain, suffix = extract(url)
    features.append(url_length(url))
    features.append(having_at(url))
    features.append(is_ip(url))
    features.append(alexa_rank(url))
    features.append(no_of_subdomain(url))
    features.append(prefix_suffix(url))
    features.append(url_anchor(url,soup,domain))
    features.append(links_in_tags(url,soup,domain))
    features.append(url_redirect(url,response))
    features.append(SSLfinal_State(url))
    features.append(sfh(url, soup, domain))
    features.append(submitting_to_email(soup))
    features.append(links_pointing(url,response))
    a,b = whois_age(url)
    if a == 0:
        a,b = whois_age2(url)
    features.append(a)
    features.append(b)
    return features
'''
start_time = time.time()
print(calculate_features(r"https://mail.google.com/mail/u/0/?tab=rm#inbox"))
print("--- %s seconds ---" % (time.time() - start_time))
'''
