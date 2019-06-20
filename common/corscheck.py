import requests, json, os, inspect, tldextract
from urlparse import urlparse

class CORSCheck:
    """docstring for CORSCheck"""
    url = None
    cfg = None
    headers = None
    result = {}

    def __init__(self, url, cfg):
        self.url = url
        self.cfg = cfg
        if cfg["headers"] != None:
            self.headers = cfg["headers"]
        
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
            # self-signed cert OK
            resp = requests.get(self.url, timeout=5, headers=headers, verify=True, allow_redirects=True)

            # It could be interesting to keep redirects if requesting/requested origins domains are matching
            # (means that a vulnerable origin has been found on the targeted domain/subdomain)
            first_domain = '%s.%s' % (tldextract.extract(url).domain,tldextract.extract(url).suffix)
            last_domain = '%s.%s' % (tldextract.extract(resp.url).domain,tldextract.extract(resp.url).suffix)

            if(first_domain.lower() != last_domain.lower()):
                resp = None

        except Exception, e:
            resp = None
        return resp

    def get_resp_headers(self, resp):
        if resp == None:
            return None
        resp_headers = dict(
            (k.lower(), v) for k, v in resp.headers.iteritems())
        return resp_headers

    def check_cors_policy(self, vul_origin):
        resp = self.send_req(self.url, vul_origin)
        resp_headers = self.get_resp_headers(resp)

        if resp_headers == None:
            return -1
        # vul_origin does not have to be case sensitive
        if vul_origin.lower() in str(resp_headers.get("access-control-allow-origin")):
            if resp_headers.get("access-control-allow-credentials") == "true":
                return 1
            return 0
        return -1

    def is_cors_permissive(self,test_module_name,test_origin,test_url):
        ret = self.check_cors_policy(test_origin)

        msg = None
        if ret == 1:
            msg = {
                "url": test_url,
                "type": test_module_name,
                "credentials": "true",
                "origin": test_origin
            }
        elif ret == 0:
            msg = {
                "url": test_url,
                "type": test_module_name,
                "credentials": "false",
                "origin": test_origin
            }

        if msg != None:
            self.cfg["logger"].warning(msg)
            self.result = msg
            return True

        self.cfg["logger"].info("%s: nothing found for url %s" % (test_module_name,test_url))
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
        sld = tldextract.extract(test_url.strip()).suffix
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
        sld = tldextract.extract(test_url.strip()).suffix
        test_origin = parsed.scheme + "://" + sld[1:]

        self.cfg["logger"].info(
            "Start checking %s for %s" % (module_name,test_url))

        return self.is_cors_permissive(module_name,test_origin,test_url)


    def test_not_escape_dot(self):
        module_name = inspect.stack()[0][3].replace('test_','');
        test_url = self.url
        parsed = urlparse(test_url)
        sld = tldextract.extract(test_url.strip()).suffix
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
        sld = tldextract.extract(test_url.strip()).suffix
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

    def check_one_by_one(self):
        functions = [
            'test_reflect_origin',
            'test_prefix_match',
            'test_suffix_match',
            'test_trust_null',
            'test_include_match',
            'test_not_escape_dot',
            'test_https_trust_http',
            'test_trust_any_subdomain',
            'test_custom_third_parties'
        ]

        for fname in functions:
            func = getattr(self,fname)
            if(func()): break
        
        return self.result
