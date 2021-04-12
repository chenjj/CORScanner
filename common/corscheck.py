import gevent.monkey
gevent.monkey.patch_all()

import requests, json, os, inspect, tldextract

from future.utils import iteritems
try:
    from urllib.parse import urlparse
except Exception as e:
    from urlparse import urlparse

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from threading import Thread

class CORSCheck:
    """docstring for CORSCheck"""
    url = None
    cfg = None
    headers = None
    timeout = None
    result = {}

    def __init__(self, url, cfg):
        self.url = url
        self.cfg = cfg
        self.timeout = cfg["timeout"]
        self.all_results = []
        if cfg["headers"] != None:
            self.headers = cfg["headers"]
        self.proxies = {}
        if cfg.get("proxy") != None:
            self.proxies = {
                "http": cfg["proxy"],
                "https": cfg["proxy"],
            }
        
    def send_req(self, url, origin):
        try:

            headers = {
                'Origin':
                origin,
                'Cache-Control':
                'no-cache',
                'User-Agent':
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36'
            }
            if self.headers != None:
                headers.update(self.headers)

            # self-signed cert OK, follow redirections
            resp = requests.get(self.url, timeout=self.timeout, headers=headers,
                verify=False, allow_redirects=True, proxies=self.proxies)

            # remove cross-domain redirections, which may cause false results
            first_domain =tldextract.extract(url).registered_domain
            last_domain = tldextract.extract(resp.url).registered_domain

            if(first_domain.lower() != last_domain.lower()):
                resp = None

        except Exception as e:
            resp = None
        return resp

    def get_resp_headers(self, resp):
        if resp == None:
            return None
        resp_headers = dict(
            (k.lower(), v) for k, v in iteritems(resp.headers))
        return resp_headers

    def check_cors_policy(self, test_module_name,test_origin,test_url):
        resp = self.send_req(self.url, test_origin)
        resp_headers = self.get_resp_headers(resp)
        status_code = resp.status_code if resp is not None else None

        if resp_headers == None:
            return None
        
        parsed = urlparse(str(resp_headers.get("access-control-allow-origin")))
        if test_origin != "null":
            resp_origin = parsed.scheme + "://" + parsed.netloc.split(':')[0]
        else:
            resp_origin = str(resp_headers.get("access-control-allow-origin"))

        msg = None

        # test_origin does not have to be case sensitive
        if test_origin.lower() == resp_origin.lower():
            credentials = "false"

            if resp_headers.get("access-control-allow-credentials") == "true":
                credentials = "true"
            
            # Set the msg
            msg = {
                "url": test_url,
                "type": test_module_name,
                "credentials": credentials,
                "origin": test_origin,
                "status_code" : status_code
            }
        return msg

    def is_cors_permissive(self,test_module_name,test_origin,test_url):
        msg = self.check_cors_policy(test_module_name,test_origin,test_url)

        if msg != None:
            self.cfg["logger"].warning(msg)
            self.result = msg
            self.all_results.append(msg)
            return True

        self.cfg["logger"].info("nothing found for {url: %s, origin: %s, type: %s}" % (test_url, test_origin, test_module_name))
        return False

    def test_reflect_origin(self):
        module_name = inspect.stack()[0][3].replace('test_','');
        test_url = self.url
        parsed = urlparse(test_url)
        test_origin = parsed.scheme + "://" + "evil.com"

        self.cfg["logger"].info(
            "Start checking %s for %s" % (module_name,test_url))

        return self.is_cors_permissive(module_name,test_origin,test_url)

    def test_prefix_match(self):
        module_name = inspect.stack()[0][3].replace('test_','');
        test_url = self.url
        parsed = urlparse(test_url)
        test_origin = parsed.scheme + "://" + parsed.netloc.split(':')[0] + ".evil.com"

        self.cfg["logger"].info(
            "Start checking %s for %s" % (module_name,test_url))

        return self.is_cors_permissive(module_name,test_origin,test_url)


    def test_suffix_match(self):
        module_name = inspect.stack()[0][3].replace('test_','');
        test_url = self.url
        parsed = urlparse(test_url)
        sld = tldextract.extract(test_url.strip()).registered_domain
        test_origin = parsed.scheme + "://" + "evil" + sld

        self.cfg["logger"].info(
            "Start checking %s for %s" % (module_name,test_url))

        return self.is_cors_permissive(module_name,test_origin,test_url)


    def test_trust_null(self):
        module_name = inspect.stack()[0][3].replace('test_','');
        test_url = self.url
        test_origin = "null"

        self.cfg["logger"].info(
            "Start checking %s for %s" % (module_name,test_url))

        return self.is_cors_permissive(module_name,test_origin,test_url)


    def test_include_match(self):
        module_name = inspect.stack()[0][3].replace('test_','');
        test_url = self.url
        parsed = urlparse(test_url)
        sld = tldextract.extract(test_url.strip()).registered_domain
        test_origin = parsed.scheme + "://" + sld[1:]

        self.cfg["logger"].info(
            "Start checking %s for %s" % (module_name,test_url))

        return self.is_cors_permissive(module_name,test_origin,test_url)


    def test_not_escape_dot(self):
        module_name = inspect.stack()[0][3].replace('test_','');
        test_url = self.url
        parsed = urlparse(test_url)
        sld = tldextract.extract(test_url.strip()).registered_domain
        domain = parsed.netloc.split(':')[0]
        test_origin = parsed.scheme + "://" + domain[::-1].replace(
            '.', 'a', 1)[::-1]

        self.cfg["logger"].info(
            "Start checking %s for %s" % (module_name,test_url))

        return self.is_cors_permissive(module_name,test_origin,test_url)


    def test_trust_any_subdomain(self):
        module_name = inspect.stack()[0][3].replace('test_','');
        test_url = self.url
        parsed = urlparse(test_url)
        test_origin = parsed.scheme + "://" + "evil." + parsed.netloc.split(':')[0]

        self.cfg["logger"].info(
            "Start checking %s for %s" % (module_name,test_url))

        return self.is_cors_permissive(module_name,test_origin,test_url)


    def test_https_trust_http(self):
        module_name = inspect.stack()[0][3].replace('test_','');
        test_url = self.url
        parsed = urlparse(test_url)
        if parsed.scheme != "https":
            return
        test_origin = "http://" + parsed.netloc.split(':')[0]

        self.cfg["logger"].info(
            "Start checking %s for %s" % (module_name,test_url))

        return self.is_cors_permissive(module_name,test_origin,test_url)


    def test_custom_third_parties(self):
        module_name = inspect.stack()[0][3].replace('test_','');
        test_url = self.url
        parsed = urlparse(test_url)
        sld = tldextract.extract(test_url.strip()).registered_domain
        domain = parsed.netloc.split(':')[0]
        
        self.cfg["logger"].info(
            "Start checking %s for %s" % (module_name,test_url))

        is_cors_perm = False

        # Opening origins file
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),'..%sorigins.json' % os.sep)) as origins_file:  
            origins = json.load(origins_file)['origins']

            for test_origin in origins:

                is_cors_perm = self.is_cors_permissive(module_name,test_origin,test_url)
                if is_cors_perm: break

        return is_cors_perm
    
    def test_special_characters_bypass(self):
        module_name = inspect.stack()[0][3].replace('test_','');
        test_url = self.url
        parsed = urlparse(test_url)
        special_characters = ['_','-','"','{','}','+','^','%60','!','~','`',';','|','&',"'",'(',')','*',',','$','=','+',"%0b"]

        origins = []

        for char in special_characters:
            attempt = parsed.scheme + "://" + parsed.netloc.split(':')[0] + char + ".evil.com"
            origins.append(attempt)
            
        is_cors_perm = False

        self.cfg["logger"].info(
            "Start checking %s for %s" % (module_name,test_url))

        for test_origin in origins:
            is_cors_perm = self.is_cors_permissive(module_name,test_origin,test_url)
            if is_cors_perm: break

        return is_cors_perm

    def check_one_by_one(self):
        functions = [
            'test_reflect_origin',
            'test_prefix_match',
            'test_suffix_match',
            'test_trust_null',
            'test_include_match',
            'test_not_escape_dot',
            'test_custom_third_parties',
            'test_special_characters_bypass',
            'test_trust_any_subdomain',
            'test_https_trust_http',
        ]

        for fname in functions:
            func = getattr(self,fname)
            # Stop if we found a exploit case.
            if(func()): break 

        return self.result

    def check_all_in_parallel(self):
        functions = [
            'test_reflect_origin',
            'test_prefix_match',
            'test_suffix_match',
            'test_trust_null',
            'test_include_match',
            'test_not_escape_dot',
            'test_custom_third_parties',
            'test_special_characters_bypass',
            'test_trust_any_subdomain',
            'test_https_trust_http',
        ]

        threads = []
        for fname in functions:
            func = getattr(self,fname)
            t = Thread(target=func)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        return self.all_results