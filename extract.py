import whois
import requests
import tldextract
from datetime import datetime
from collections import Counter
import numpy as np
import ipaddress
import pandas as pd
from urllib.parse import urlparse, urlunparse

# Function to extract features from URLs
def extract_features(url):

    url = normalize_url(url)
    """if not isinstance(url, str):  # Ensure URL is a string
        url = "" # If not, set URL to empty string
    if not url.startswith("http"):
        url = "http://" + url
        """
    
    # Parse the URL
    try:
        parsed_url = urlparse(url)
    except Exception as e:
        return [0] * 20  # Return a list of zeros if URL parsing fails
    
    # Extract the domain and subdomain information
    ext = tldextract.extract(url)

    features = {
        #1
        "url_length": len(url),
        #2
        "num_dots": url.count("."),
        #3
        "num_hyphens": url.count("-"),
        #4
        "num_slash": url.count("/") - 2,
        #5
        "num_digits": sum(c.isdigit() for c in url),
        #6
        "has_ip_address": contains_valid_ip(parsed_url.netloc),
        #7
        "presence_of_@": "@" in url,
        #8
        "uses_https": url.startswith("https://"),
        #9
        "num_subdomains": count_subdomains(url),
        #10
        "path_length": len(parsed_url.path),
        #11
        "presence_of_www": "www." in parsed_url.netloc,
        #12
        "length_of_domain": len(ext.domain),
        #13
        "has_sensitive_keyword": int(any(word in url.lower() for word in ["secure", "bank", "update", "verify"])),
        #14
        "suspicious_tld": sus_tld(url),
        #15
        "is_shortened": is_shortened(parsed_url.netloc),
        #16
        "digit_to_char_ratio": sum(c.isdigit() for c in url) / len(url),
        #17
        "suspicious_extension": int(any(ext in url for ext in [".exe ", ".zip ", ".apk ", ".scr ", ".php ", "jpg ", 
                                                               ".png ", ".gif ", ".js ", ".css ", ".pdf ", ".doc ", 
                                                               ".docx ", ".xls ", ".xlsx ", ".ppt ", ".pptx "])),
        #18
        "domain_entropy": calc_entropy(ext.domain),
        #19
        "num_query_params": len(parsed_url.query.split("&")) if parsed_url.query else 0,
        #20
        "has_double_slash": url.count("//") > 1
    }
    return list(features.values())

def normalize_url(url):
        parsed = urlparse(url)
        # Remove trailing slash ONLY if it's the only path
        path = '' if parsed.path == '/' else parsed.path
        normalized = urlunparse(parsed._replace(path=path))
        return normalized

def count_subdomains(url):
    ext = tldextract.extract(url)
    return len(ext.subdomain.split('.')) if ext.subdomain else 0

def sus_tld(url):
    ext = tldextract.extract(url)
    tld_list = ['ml', 'mk', 'cf', 'go.gov.br', 'website', 'ga', 'xyz', 'top', 'co.tz', 'do', '', 'com.pl', 'edu.in', 'go.th', 'hosting',
                'site', 'edu.bd', 'social', 'gen.tr', 'nf', 'men', 'gq', 'expert', 'link', 'in.rs', 'gm', 'fm.br', 'gd', 'xxx', 'sch.id'
                'gov.bd', 'srv.br', 'co.rs', 'florist', 'business', 'net.br', 'domains', 'or.kr', 'ci', 'tax', 'xn--p1ai', 'bydgoszcz.pl',
                'pn', 'lc', 'net.in', 'tr', 'bo', 'life', 'or.at', 'eng.br', 'report', 'org.my', 'tj', 'directory', 'cloud',
                'com.na', 'sn', 'med.br', 'ac.ke', 'ac.th', 'org.ar', 'click', 'net.tr', 'or.ke', 'services', 'org.sa', 'sch.sa',
                'com.tn', 'net.ua', 'ne.kr', 'edu.ec', 'com.mk', 'rj.gov.br', 'bio.br', 'ce.gov.br', 'COM', 'siracusa.it', 'com.gr',
                'edu.pe', 'or.cr', 'mg.gov.br', 'parma.it', 'legal', 'com.bo', 'work', 'edu.mx', 'ac.ug', 'org.tr', 'or.tz',
                'media', 'gov.ng', 'space', 'fin.ec', 'org.pk', 'i.ng', 'co.cr', 'co.ug', 'gov.it', 'sy', 'uy', 'gov.vn', 'photo',
                'edu.br', 'org.pe', 'church', 'care', 'gov.co', 'szczecin.pl', 'lviv.ua', 'mw', 'live', 'faith', 'kr', 'review', 'buzz',
                'org.sv', 'equipment', 'edu.rs', 'or.id', 'rec.br', 'com.fj', 'ng', 'adm.br', 'com.ge', 'org.mk', 'today', 'dp.ua', 'tv.br',
                'bs', 'gov.mz', 'pl.ua', 'biz.id', 'edu.ar', 'ink', 'ind.br', 'gob.do', 'university', 'com.hr', 'org.ng', 'builders',
                'konin.pl', 'gob.ve', 'download', 'in.ua', 'one', 'net.cn', 'ms', 'edu.vn', 'or.th', 'edu.pt', 'gov.ly', 'run', 'cab',
                'stargard.pl', 'bb', 'tools', 'radio.br', 'co.mz', 'blog.br', 'date', 'ind.in', 'info.ve', 'ac.cn', 'clinic', 'market',
                'world', 'co.at', 'gov.ve', 'net.ve', 'zp.ua', 'org.mx', 'gov.pg', 'edu.sv', 'pr.gov.br', 'gob.pe', 'bucks.sch.uk', 'kr.ua',
                'global', 'edu.jm', 'com.ro', 'uz', 'casa', 'org.np', 'computer', 're', 'edu.ba', 'vacations', 'gov.al', 'sc.gov.br',
                'cv.ua', 'info.pl', 'wang', 'elblag.pl', 'waw.pl', 'wodzislaw.pl', 'pf', 'ra.it', 'je', 'kh.ua', 'catering', 'av.tr',
                'kg', 'properties', 'sd', 'prato.it', 'om', 'org.ph', 'net.ma', 'as', 'CO.ZA', 'gob.bo', 'org.sz', 'biz.tr', 'arts.ro',
                'edu.ng', 'ac.zm', 'bh', 'com.bb', 'institute', 'so', 'onion', 'gov.af', 'bf', 'gov.sy', 'bialystok.pl', 'coop.br', 'gov.mm',
                'biz.pl', 'party', 'info.tr', 'edu.kh', 'support', 'km.ua', 'go.ke', 'pm', 'edu.ve', 'inf.br', 've.it', 'restaurant', 'science',
                'etc.br', 'systems', 'club.tw', 'lol', 'host', 'web.tr', 'yt', 'od.ua', 'gob.ec', 'xn--80aswg', 'Data', 'city', 'com.ba', 'qa',
                'gift', 'agency', 'london', 'co.cl', 'gen.in', 'messina.it', 'NET', 'rocks', 've', 'net.vn', 'webcam', 'odessa.ua', 'ORG',
                'INFO', 'com.mo', 'tf', 'loan', 'racing', 'CO', 'slask.pl', 'RU', 'help', 'net.my', 'coffee', 'rip', 'tips', 'alsace', 'bel.tr',
                'xn--80asehdb', 'accountant', 'red', 'moe', 'CO.UK', 'US', 'gdn', 'eus', 'net.bd', 'net.pk', 'capital', 'sl', 'zgora.pl', 'edu.py',
                'ac.fj', 'com.qa', 'edu.uy', 'com.pa', 'com.jo', 'go.tz', 'bradesco', 'psc.br', 'dn.ua', 'gob.ar', 'gold', 'land', 'idv.tw',
                'africa', 'icu', 'cash', 'org.co', 'app', 'ug', 'center', 'xn--p1acf', 'net.ec', 'vet', 'mr', 'wf', 'gov.zm', 'com.ni',
                'nagoya', 'com.sb', 'company', 'gop', 'milano.it', 'ovh', 'kiwi', 'gp', 'ao', 'events', 'gov.np', 'camp', 'ai', 'store',
                'email', 'xn--tckwe', 'mazowsze.pl', 'network', 'fun', 'info.hu', 'gov.ps', 'cool', 'xn--c1avg', 'goog', 'kharkov.ua',
                'solutions', 'gt', 'audio', 'ac.tz', 'desa.id', 'video', 'pics', 'sydney', 'net.gy', 'or.ug', 'place', 'education', 'org.dz',
                'credit', 'edu.gh', 'tokyo', 'shop', 'org.gt', 'edu.sd', 'arq.br', 'gallery', 'digital', 'bio', 'wtf', 'cng.br']
    ext_list = tld_list + ["xyz", "info", "top", "tk", "buzz", "ga", "ml", "cf", "gq"]
    return ext.suffix in ext_list
  
def calc_entropy(s):
    prob = [freq / len(s) for freq in Counter(s).values()]
    return -sum(p * np.log2(p) for p in prob)

def is_shortened(domain):
    list = ["tinyurl.com", "bit.ly", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly"]
    return any(item in domain for item in list)

def contains_valid_ip(domain):
    for part in domain.split():
        try:
            ipaddress.IPv4Address(part)
            return True
        except ValueError:
            continue
    return False

"""def get_domain_age(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]  # Handle multiple dates
        if creation_date:
            age = (datetime.now() - creation_date).days
            return age
    except:
        return 0  # Return 0 if WHOIS fails

    return 0"""

"""def check_redirects(url):
    try:
        session = requests.Session()
        response = session.get(url, allow_redirects=True)
        return len(response.history)
    except:
        return 0"""