import requests
from urlparse import urlparse

from tld import get_tld


class CORSCheck:
    """docstring for CORSCheck"""
    url = None
    cfg = None

    def __init__(self, url, cfg):
        self.url = url
        self.cfg = cfg

    def send_req(self, url, origin):
        try:
            headers = {
                'Origin':
                origin,
                'Cache-Control':
                'no-cache',
                'Cookie':
                'a=b',
                'User-Agent':
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36'
            }
            resp = requests.get(
                self.url, timeout=5, headers=headers, allow_redirects=False)
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
        if resp_headers.get("access-control-allow-origin") == vul_origin:
            if resp_headers.get("access-control-allow-credentials") == "true":
                return 1
            return 0
        return -1

    def test_reflect_origin(self):
        test_url = self.url
        parsed = urlparse(test_url)
        test_origin = parsed.scheme + "://" + "evil.com"

        self.cfg["logger"].info(
            "Start checking reflect_origin for " + test_url)

        ret = self.check_cors_policy(test_origin)

        msg = None
        if ret == 1:
            msg = {
                "url": test_url,
                "type": "reflect_origin",
                "credentials": "true"
            }
        elif ret == 0:
            msg = {
                "url": test_url,
                "type": "reflect_origin",
                "credentials": "false"
            }

        if msg != None:
            self.cfg["logger"].warning(msg)
            return True
        self.cfg["logger"].info("Not found reflect_origin for " + test_url)
        return False

    def test_prefix_match(self):
        test_url = self.url
        parsed = urlparse(test_url)
        test_origin = parsed.scheme + "://" + parsed.netloc + ".evil.com"

        self.cfg["logger"].info("Start checking prefix_match for " + test_url)

        ret = self.check_cors_policy(test_origin)

        msg = None
        if ret == 1:
            msg = {
                "url": test_url,
                "type": "prefix_match",
                "credentials": "true"
            }
        elif ret == 0:
            msg = {
                "url": test_url,
                "type": "prefix_match",
                "credentials": "false"
            }

        if msg != None:
            self.cfg["logger"].warning(msg)
            return True
        self.cfg["logger"].info("Not found prefix_match for " + test_url)
        return False

    def test_suffix_match(self):
        test_url = self.url
        parsed = urlparse(test_url)
        sld = get_tld(test_url.strip())
        test_origin = parsed.scheme + "://" + "evil" + sld

        self.cfg["logger"].info("Start checking suffix_match for " + test_url)

        ret = self.check_cors_policy(test_origin)

        msg = None
        if ret == 1:
            msg = {
                "url": test_url,
                "type": "suffix_match",
                "credentials": "true"
            }
        elif ret == 0:
            msg = {
                "url": test_url,
                "type": "suffix_match",
                "credentials": "false"
            }

        if msg != None:
            self.cfg["logger"].warning(msg)
            return True
        self.cfg["logger"].info("Not found suffix_match for " + test_url)
        return False

    def test_trust_null(self):
        test_url = self.url
        test_origin = "null"
        self.cfg["logger"].info("Start checking trust_null for " + test_url)

        ret = self.check_cors_policy(test_origin)

        msg = None
        if ret == 1:
            msg = {
                "url": test_url,
                "type": "trust_null",
                "credentials": "true"
            }
        elif ret == 0:
            msg = {
                "url": test_url,
                "type": "trust_null",
                "credentials": "false"
            }

        if msg != None:
            self.cfg["logger"].warning(msg)
            return True
        self.cfg["logger"].info("Not found trust_null for " + test_url)
        return False

    def test_include_match(self):
        test_url = self.url
        parsed = urlparse(test_url)
        sld = get_tld(test_url.strip())
        test_origin = parsed.scheme + "://" + sld[1:]

        self.cfg["logger"].info("Start checking include_match for " + test_url)

        ret = self.check_cors_policy(test_origin)

        msg = None
        if ret == 1:
            msg = {
                "url": test_url,
                "type": "include_match",
                "credentials": "true"
            }
        elif ret == 0:
            msg = {
                "url": test_url,
                "type": "include_match",
                "credentials": "false"
            }

        if msg != None:
            self.cfg["logger"].warning(msg)
            return True
        self.cfg["logger"].info("Not found include_match for " + test_url)
        return False

    def test_not_escape_dot(self):
        test_url = self.url
        parsed = urlparse(test_url)
        sld = get_tld(test_url.strip())
        domain = parsed.netloc
        test_origin = parsed.scheme + "://" + domain[::-1].replace(
            '.', 'a', 1)[::-1]
        self.cfg["logger"].info(
            "Start checking not_escape_dot for " + test_url)

        ret = self.check_cors_policy(test_origin)

        msg = None
        if ret == 1:
            msg = {
                "url": test_url,
                "type": "not_escape_dot",
                "credentials": "true"
            }
        elif ret == 0:
            msg = {
                "url": test_url,
                "type": "not_escape_dot",
                "credentials": "false"
            }

        if msg != None:
            self.cfg["logger"].warning(msg)
            return True
        self.cfg["logger"].info("Not found not_escape_dot for " + test_url)
        return False

    def test_trust_any_subdomain(self):
        test_url = self.url
        parsed = urlparse(test_url)
        test_origin = parsed.scheme + "://" + "evil." + parsed.netloc

        self.cfg["logger"].info(
            "Start checking trust_any_subdomain for " + test_url)

        ret = self.check_cors_policy(test_origin)

        msg = None
        if ret == 1:
            msg = {
                "url": test_url,
                "type": "trust_any_subdomain",
                "credentials": "true"
            }
        elif ret == 0:
            msg = {
                "url": test_url,
                "type": "trust_any_subdomain",
                "credentials": "false"
            }

        if msg != None:
            self.cfg["logger"].warning(msg)
            return True
        self.cfg["logger"].info(
            "Not found trust_any_subdomain for " + test_url)
        return False

    def test_https_trust_http(self):
        test_url = self.url
        parsed = urlparse(test_url)
        if parsed.scheme != "https":
            return
        test_origin = "http://" + parsed.netloc

        self.cfg["logger"].info(
            "Start checking https_trust_http for " + test_url)

        ret = self.check_cors_policy(test_origin)

        msg = None
        if ret == 1:
            msg = {
                "url": test_url,
                "type": "https_trust_http",
                "credentials": "true"
            }
        elif ret == 0:
            msg = {
                "url": test_url,
                "type": "https_trust_http",
                "credentials": "false"
            }

        if msg != None:
            self.cfg["logger"].warning(msg)
            return True
        self.cfg["logger"].info("Not found https_trust_http for " + test_url)
        return False

    def check_one_by_one(self):
        if self.test_reflect_origin():
            return
        elif self.test_prefix_match():
            return
        elif self.test_suffix_match():
            return
        elif self.test_trust_null():
            return
        elif self.test_include_match():
            return
        elif self.test_not_escape_dot():
            return
        elif self.test_https_trust_http():
            return
        elif self.test_trust_any_subdomain():
            return
