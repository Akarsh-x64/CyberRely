import sys, os
import time
import traceback
import urllib.error
import OpenSSL.SSL
from OpenSSL import SSL
from cryptography import x509
from cryptography.x509.oid import NameOID
import idna
from socket import socket
from collections import namedtuple
import concurrent.futures
import numpy as np
from kivy.app import App
from kivy.lang import Builder
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.config import Config
import multiprocessing

raw_data_dict = {}

Config.set('graphics', 'resizable', False)
from kivy.core.window import Window

Window.size = (700, 400)
if "win" in sys.platform:
    Window.set_icon('Application_Externals\\CyberRely.png')
    we = (open("Application_Externals\\1e3042b2e2a5550b412b37edd1c36b34.dll", "rb").read()).decode()
else:
    Window.set_icon('Application_Externals/CyberRely.png')
    we = (open("Application_Externals/1e3042b2e2a5550b412b37edd1c36b34.dll", "rb").read()).decode()

Builder.load_string(we)


# Declare all screens
class MenuScreen(Screen):
    def update(self):
        pass


class PhishSafeScreen(Screen):
    def update(self):
        pass

    def disable_url_box(self):
        self.ids.url.disabled = True


class VirusSafeScreen(Screen):
    def update(self):
        pass


class MailSafeScreen(Screen):
    def update(self):
        pass


class EncryptScreen(Screen):
    def update(self):
        pass


class CreditsScreen(Screen):
    def update(self):
        pass


sm = ScreenManager()
sm.add_widget(MenuScreen(name='menu'))
sm.add_widget(PhishSafeScreen(name='PhishSafe'))
sm.add_widget(VirusSafeScreen(name='VirusSafe'))
sm.add_widget(MailSafeScreen(name='MailSafe'))
sm.add_widget(EncryptScreen(name='Encrypt'))
sm.add_widget(CreditsScreen(name='Credits'))

import threading


# noinspection PyAttributeOutsideInit,PyShadowingNames
class TraceThread(threading.Thread):
    def __init__(self, *args, **keywords):
        threading.Thread.__init__(self, *args, **keywords)
        self.killed = False

    def start(self):
        self._run = self.run
        self.run = self.settrace_and_run
        threading.Thread.start(self)

    def settrace_and_run(self):
        import sys
        sys.settrace(self.globaltrace)
        self._run()

    def globaltrace(self, frame, event, arg):
        return self.localtrace if event == 'call' else None

    def localtrace(self, frame, event, arg):
        if self.killed and event == 'line':
            raise SystemExit()
        return self.localtrace


if "win" in sys.platform:
    file_to_quarantine = os.getcwd() + "\\VirusSafe_drivers\\Quarantine\\"
else:
    file_to_quarantine = os.getcwd() + "/VirusSafe_drivers/Quarantine/"


def filebrowser(args):
    import wx
    app = wx.App()
    frame = wx.Frame(None, -1, 'win.py')
    frame.SetDimensions(0, 0, 200, 50)
    openFileDialog = wx.FileDialog(frame, "Open", "", "",
                                   args,
                                   wx.FD_OPEN | wx.FD_FILE_MUST_EXIST)

    openFileDialog.ShowModal()
    file = openFileDialog.GetPath()
    openFileDialog.Destroy()
    try:
        we = open(file, "r")
        return file
    except IsADirectoryError:
        return ""


import ctypes, sys


class extra_resources:
    def __init__(self):
        pass

    def create_md5(self, content):
        import hashlib
        md = hashlib.md5()
        md.update(content)
        return bytes(md.hexdigest(), "utf-8")

    def get_filepaths(self, directory):
        import os
        file_paths = []
        for root, directories, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                file_paths.append(filepath)

        return file_paths


class check_resources:
    def __init__(self):
        pass

    def start(self):
        import hashlib
        import os
        import sys

        if "win" in sys.platform:
            files = ["PhishSafe_drivers\\f80a4ad87fee7c9fdc19b7769495fdb5.dll",
                     "MailSafe_drivers\\b5cc1518914fa539dc4fb597e97206d2.dll",
                     "Application_Externals\\1e3042b2e2a5550b412b37edd1c36b34.dll",
                     "Application_Externals\\CyberRely.ico",
                     "Application_Externals\\CyberRely.png",
                     "Encrypt_drivers\\eed3081faba7e57f7bcf8e6c7f0db957.dll",
                     "Data\\public_suffix_list.dat",
                     "LICENSE"]
        else:
            files = ["PhishSafe_drivers/f80a4ad87fee7c9fdc19b7769495fdb5.dll",
                     "MailSafe_drivers/b5cc1518914fa539dc4fb597e97206d2.dll",
                     "Application_Externals/1e3042b2e2a5550b412b37edd1c36b34.dll",
                     "Application_Externals/CyberRely.ico",
                     "Application_Externals/CyberRely.png",
                     "Encrypt_drivers/eed3081faba7e57f7bcf8e6c7f0db957.dll",
                     "Data/public_suffix_list.dat",
                     "LICENSE"]

        test = [b'66ee49d081eb67b281ba6e91c9bcb957',
                b'adc2906d700c2998e75f7770b32d7cf8',
                b'9fbd3619121fb71b79ab0c6c758304be',
                b'00f6150a8c5d57c120590105bb80aeb4',
                b'bf96300eb1ded8f394418160487b32ef',
                b'5facdd74bd83b96aafe4060e5b022b4a',
                b'7400cd48e9f9ef434a6bfc4e92c4f8d6',
                b'4d51c50c61baf9d9dc5c26dcb973322b']

        temp = []

        if "win" in sys.platform:
            if os.path.isdir("PhishSafe_drivers"):
                if os.path.isdir("VirusSafe_drivers"):
                    if os.path.isdir("MailSafe_drivers"):
                        if os.path.isdir("Application_Externals"):
                            if os.path.isdir("Encrypt_drivers"):
                                if os.path.isfile("PhishSafe_drivers\\f80a4ad87fee7c9fdc19b7769495fdb5.dll"):
                                    if os.path.isdir("VirusSafe_drivers\\Quarantine"):
                                        if os.path.isfile("MailSafe_drivers\\b5cc1518914fa539dc4fb597e97206d2.dll"):
                                            if os.path.isfile("Application_Externals\\1e3042b2e2a5550b412b37edd1c36b34.dll"):
                                                if os.path.isfile("Application_Externals\\CyberRely.ico"):
                                                    if os.path.isfile("Application_Externals\\CyberRely.png"):
                                                        if os.path.isfile("Encrypt_drivers\\eed3081faba7e57f7bcf8e6c7f0db957.dll"):
                                                            if os.path.isdir("Data"):
                                                                if os.path.isfile("Data\\public_suffix_list.dat"):
                                                                    if os.path.isfile("LICENSE"):
                                                                        good_job = True
                                                                    else:
                                                                        good_job = False
                                                                else:
                                                                    good_job = False
                                                            else:
                                                                good_job = False
                                                        else:
                                                            good_job = False
                                                    else:
                                                        good_job = False
                                                else:
                                                    good_job = False
                                            else:
                                                good_job = False
                                        else:
                                            good_job = False
                                    else:
                                        good_job = False
                                else:
                                    good_job = False
                            else:
                                good_job = False
                        else:
                            good_job = False
                    else:
                        good_job = False
                else:
                    good_job = False
            else:
                good_job = False

        else:
            if os.path.isdir("PhishSafe_drivers"):
                if os.path.isdir("VirusSafe_drivers"):
                    if os.path.isdir("MailSafe_drivers"):
                        if os.path.isdir("Application_Externals"):
                            if os.path.isdir("Encrypt_drivers"):
                                if os.path.isfile("PhishSafe_drivers/f80a4ad87fee7c9fdc19b7769495fdb5.dll"):
                                    if os.path.isdir("VirusSafe_drivers/Quarantine"):
                                        if os.path.isfile("MailSafe_drivers/b5cc1518914fa539dc4fb597e97206d2.dll"):
                                            if os.path.isfile("Application_Externals/1e3042b2e2a5550b412b37edd1c36b34.dll"):
                                                if os.path.isfile("Application_Externals/CyberRely.ico"):
                                                    if os.path.isfile("Application_Externals/CyberRely.png"):
                                                        if os.path.isfile("Encrypt_drivers/eed3081faba7e57f7bcf8e6c7f0db957.dll"):
                                                            if os.path.isdir("Data"):
                                                                if os.path.isfile("Data/public_suffix_list.dat"):
                                                                    if os.path.isfile("LICENSE"):
                                                                        good_job = True
                                                                    else:
                                                                        good_job = False
                                                                else:
                                                                    good_job = False
                                                            else:
                                                                good_job = False
                                                        else:
                                                            good_job = False
                                                    else:
                                                        good_job = False
                                                else:
                                                    good_job = False
                                            else:
                                                good_job = False
                                        else:
                                            good_job = False
                                    else:
                                        good_job = False
                                else:
                                    good_job = False
                            else:
                                good_job = False
                        else:
                            good_job = False
                    else:
                        good_job = False
                else:
                    good_job = False
            else:
                good_job = False

        if good_job:
            constructer = extra_resources()
            for i in files:
                we = open(i, "rb").read()
                temp.append(constructer.create_md5(we))
            if temp[0] == test[0]:
                if temp[1] == test[1]:
                    if temp[2] == test[2]:
                        if temp[3] == test[3]:
                            if temp[4] == test[4]:
                                if temp[5] == test[5]:
                                    if temp[6] == test[6]:
                                        if temp[6] == test[6]:
                                            if temp[7] == test[7]:
                                                deep = True
                                            else:
                                                deep = False
                                        else:
                                            deep = False
                                    else:
                                        deep = False
                                else:
                                    deep = False
                            else:
                                deep = False
                        else:
                            deep = False
                    else:
                        deep = False
                else:
                    deep = False
            else:
                deep = False
        else:
            return False

        if not deep:
            return False

        return True


class certificate:
    def __init__(self):
        pass

    # noinspection PyUnusedLocal
    def verify_cert(self, cert, hostname):
        cert.has_expired()

    def get_certificate(self, hostname, ports):
        HostInfo = namedtuple(field_names='cert hostname peername', typename='HostInfo')
        hostname_idna = idna.encode(hostname)
        sock = socket()
        sock.connect((hostname, ports))
        peername = sock.getpeername()
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.check_hostname = False
        ctx.verify_mode = SSL.VERIFY_NONE
        sock_ssl = SSL.Connection(ctx, sock)
        sock_ssl.set_connect_state()
        sock_ssl.set_tlsext_host_name(hostname_idna)
        sock_ssl.do_handshake()
        cert = sock_ssl.get_peer_certificate()
        crypto_cert = cert.to_cryptography()
        sock_ssl.close()
        sock.close()
        return HostInfo(cert=crypto_cert, peername=peername, hostname=hostname)

    def get_issuer(self, cert):
        try:
            names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            return names[0].value

        except x509.ExtensionNotFound:
            return None

    # noinspection PyUnusedLocal
    def print_basic_info(self, hostinfo):
        import datetime
        now = datetime.datetime.now()
        qwerty = '''issuer: {issuer}\nnotBefore: {notbefore}\nnotAfter:  {notafter}'''.format(
            issuer=self.get_issuer(hostinfo.cert),
            notbefore=hostinfo.cert.not_valid_before,
            notafter=hostinfo.cert.not_valid_after)

        if hostinfo.cert.not_valid_before <= now <= hostinfo.cert.not_valid_after:
            self.ssl = 1
        else:
            self.ssl = -1

        zxcv = hostinfo.cert.not_valid_after - hostinfo.cert.not_valid_before
        q = str(zxcv).split(", ")
        date = q[0].split(" ")[0]
        if int(date) > 64:
            self.date_app = 1
        elif 64 > int(date) > 28:
            self.date_app = 0
        else:
            self.date_app = -1
        return [self.ssl, self.date_app]


class PhishSafe:
    def __init__(self, url):
        import json
        import socket
        import urllib.request
        from urllib.parse import urlparse
        import xmltodict
        import tldextract
        import time
        val_dict = {}
        self.url = url
        self.error = False
        self.y = self.url
        self.w = tldextract.extract(self.y).domain
        self.s = tldextract.extract(self.y).suffix
        self.qtr = self.w
        self.domain = str(self.w) + "." + str(self.s)
        self.o = urlparse(self.y)
        self.scheme = self.o.scheme

    def load(self):
        import time
        while 1:
            sm.get_screen("PhishSafe").ids['result'].text = '[0oo] Checking Legitimacy'
            time.sleep(0.5)
            sm.get_screen("PhishSafe").ids['result'].text = '[o0o] Checking Legitimacy'
            time.sleep(0.5)
            sm.get_screen("PhishSafe").ids['result'].text = '[oo0] Checking Legitimacy'
            time.sleep(0.5)
            sm.get_screen("PhishSafe").ids['result'].text = '[o0o] Checking Legitimacy'
            time.sleep(0.5)

    def seven_para_foo(self, seven_para_var):
        self.port = self.o.port

        full_domain = str(self.scheme) + "://www." + str(self.domain) + "/favicon.ico"

        dot = "."
        dots = self.domain.count(dot)

        at = "@"
        ats = self.y.count(at)

        hashes = "//"
        hashed = self.y.count(hashes)

        dash = "-"
        dashes = self.domain.count(dash)
        if dashes <= 1:
            prefix = 1

        if dashes > 1:
            prefix = -1

        if 60 >= len(self.y) >= 20:
            self.len = 0

        if len(self.y) < 20:
            self.len = 1

        if 60 < len(self.y):
            self.len = -1

        if dots <= 1:
            ip = 1
            sub_domains = 1

        if dots > 1:
            ip = -1
            sub_domains = 0

        if dots > 2:
            ip = -1
            sub_domains = -1

        if ats <= 1:
            at_rates = 1

        if ats > 1:
            at_rates = -1

        if hashed <= 1:
            slash = 1
            times = 1

        if hashed > 1:
            slash = -1
            times = 1

        if times == 1:
            right_click = 0
            r = 1

        import urllib.request as urllib2
        hdr = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', }
        try:
            req = urllib2.Request(self.y, headers=hdr)
            response = urllib2.urlopen(req)
            final_url = response.url

            if self.y == final_url:
                tiny = -1

            else:
                tiny = 1
        except urllib.error.URLError:
            tiny = 0

        if int(ip) == -1 or int(self.len) == -1 or int(tiny) == -1 or int(at_rates) == -1 or int(slash) == -1 or int(
                prefix) == -1 or int(sub_domains) == -1:
            self.seven_para = -1
        else:
            self.seven_para = 1
        seven_para_var.value = self.seven_para

    def ssl_foo(self, ssl_var):
        if str(self.scheme) == "http":
            port_using = 80
        elif str(self.scheme) == "https":
            port_using = 443
        HOSTS = [(self.y.split(f"{str(self.scheme)}://")[-1].split("/")[0], port_using)]

        if True:
            ssl_verify = certificate()
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as e:
                try:
                    for host in e.map(lambda x: ssl_verify.get_certificate(x[0], x[1]), HOSTS):
                        we = ssl_verify.print_basic_info(host)
                        self.ssl = we[0]
                except OpenSSL.SSL.Error:
                    self.ssl = -1
                    return
        ssl_var.value = self.ssl

    def favicon_foo(self, favicon_var):
        import requests
        full_domain = str(self.scheme) + "://www." + str(self.domain) + "/favicon.ico"
        try:
            z = requests.get(full_domain)
            if z.status_code == 200:
                self.favicon = 1
            else:
                self.favicon = -1

        except requests.exceptions.ConnectionError:
            self.favicon = -1
        favicon_var.value = self.favicon

    def date1_foo(self, date1_var):
        if str(self.scheme) == "http":
            port_using = 80
        elif str(self.scheme) == "https":
            port_using = 443
        HOSTS = [(self.y.split(f"{str(self.scheme)}://")[-1].split("/")[0], port_using)]

        if True:
            ssl_verify = certificate()
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as e:
                try:
                    for host in e.map(lambda x: ssl_verify.get_certificate(x[0], x[1]), HOSTS):
                        we = ssl_verify.print_basic_info(host)
                        self.date1 = we[1]
                except OpenSSL.SSL.Error:
                    self.date1 = -1
                    return
        date1_var.value = self.date1

    def port_1_foo(self, port_1_var):
        import psutil

        port_used = self.port
        if port_used is not None:
            wss = int(port_used) in [i.laddr.port for i in psutil.net_connections()]

            if int(port_used) in [21, 22, 23, 445, 1433, 1521, 3306, 3389]:
                if not wss:
                    self.port_1 = -1

                if wss:
                    self.port_1 = 1

            elif int(port_used) in [80, 443]:
                if not wss:
                    self.port_1 = 1

                if wss:
                    self.port_1 = -1

            elif int(port_used) is None:
                self.port_1 = 1

            else:
                self.port_1 = -1

        elif port_used is None:
            self.port_1 = 1

        port_1_var.value = self.port_1

    def https_token_foo(self, https_token_var):
        domains_sub = self.y.split(f"{str(self.scheme)}://")[-1]
        if "http" in domains_sub:
            self.https_token = -1
        else:
            self.https_token = 1
        https_token_var.value = self.https_token

    def mail_foo(self, mail_var):
        from bs4 import BeautifulSoup
        import urllib.request as urllib2
        import re
        from urllib.parse import urlparse
        from socket import socket
        hdr = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', }
        try:
            req = urllib2.Request(self.y, headers=hdr)
            html_page = urllib2.urlopen(req)
            soup = BeautifulSoup(html_page)
            o = urlparse(self.y)
            scheme = o.scheme
            ws = "^" + scheme + "://"
            n = 0
            axx = 0
            for link in soup.findAll('a', attrs={'href': re.compile(ws)}):
                n = n + 1
                aaa = link.get('href')
                for i in aaa:
                    if "mailto:" in i:
                        self.mail = -1
                        break

                    else:
                        self.mail = 1
                        continue
            else:
                self.mail = 1
        except urllib.error.URLError:
            self.mail = 0
        mail_var.value = self.mail

    def abnormal_foo(self, abnormal_var):
        import whois
        import socket

        try:
            w = whois.whois(self.domain)
            if w.whois_server is not None:
                self.abnormal = 1

            else:
                self.abnormal = -1

        except socket.timeout:
            self.abnormal = -1

        except ConnectionResetError:
            self.abnormal = -1
        abnormal_var.value = self.abnormal

    def redirect_foo(self, redirect_var):
        import urllib.request as urllib2
        hdr = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', }

        req = urllib2.Request(self.y, headers=hdr)
        response = urllib2.urlopen(req)
        response_code = response.getcode()

        if response_code == 302 or response_code == 301:
            self.redirect = -1

        else:
            self.redirect = 1
        redirect_var.value = self.redirect

    def mouseover_foo(self, mouseover_var):
        from bs4 import BeautifulSoup
        import requests

        r = requests.get(self.y)
        theHtml = r.content
        theSoup = BeautifulSoup(theHtml)

        for event_tag in theSoup.findAll(onmouseover=True):
            axc = event_tag['onmouseover']
            if axc:
                self.mouseover = -1

            if not axc:
                self.mouseover = 1

        else:
            self.mouseover = 1
        mouseover_var.value = self.mouseover

    def age_domain_foo(self, age_domain_var):
        try:
            import requests
            details = whois.whois(self.y)
            domain = details.creation_date
            days = (datetime.datetime.now() - domain).days
            if days >= 180:
                self.age_domain = 1
            else:
                self.age_domain = -1
        except Exception:
            self.age_domain = 0
        age_domain_var.value = self.age_domain

    def server_foo(self, server_var):
        from urllib.request import urlopen, Request
        from bs4 import BeautifulSoup
        yuy = Request(self.y, headers={'User-Agent': 'Mozilla/5.0'})
        domain = self.w
        html = urlopen(yuy)
        soup = BeautifulSoup(html.read())
        links = []
        for link in soup.find_all('form'):
            links.append(link.get('action'))
        e = 0
        Not = filter(None.__ne__, links)

        links = list(Not)
        print(links)
        li = []
        for link in links:
            if 'http' in link:
                if domain not in link:
                    if "localhost" not in link:
                        e += 1
            elif link == '':
                e += 1
            elif '.php' in link:
                for lin in soup.find_all('input'):
                    li.append(lin.get('type'))
                if 'hidden' in li:
                    e += 1
                else:
                    e += 0
            else:
                pass
        if e >= 1:
            self.server = -1
        else:
            self.server = 1

        server_var.value = self.server

    def dns_foo(self, dns_var):
        import socket
        try:
            wxes = socket.gethostbyname(self.domain)
        except socket.gaierror:
            wxes = None
        if wxes is not None:
            self.dns = 1
        elif wxes is None:
            self.dns = -1
        dns_var.value = self.dns

    def alexa_foo(self, alexa_var):
        import json
        import urllib.request
        import xmltodict
        xml = urllib.request.urlopen(
            'http://data.alexa.com/data?cli=10&dat=s&url={}'.format("www." + self.domain)).read()
        result = xmltodict.parse(xml)
        data = json.dumps(result).replace("@", "")
        data_tojson = json.loads(data)
        try:
            rank = data_tojson["ALEXA"]["SD"][1]["POPULARITY"]["TEXT"]

        except KeyError:
            rank = 1000000000000000000

        rank = int(rank)

        if 0 <= rank < 100000:
            self.alexa = 1

        elif 100000 <= rank < 105000:
            self.alexa = 0

        elif rank > 105000:
            self.alexa = -1
        alexa_var.value = self.alexa

    def google_foo(self, page_var, gindex_var, pagerank_var):
        from googlesearch import search
        query = f"site:/{self.y}/"
        tmp = []
        for j in search(query, num=3, stop=3):
            tmp.append(j)
        q = len(tmp)
        if q == 0:
            self.gindex = -1
        else:
            self.gindex = 1
        if self.gindex == -1:
            self.page = -1
        elif self.gindex == 1 and 3 > q > 0:
            self.page = 0
        else:
            self.page = 1
        if self.page == 0 or self.page == -1:
            self.pagerank = -1
        else:
            self.pagerank = 1

        gindex_var.value, page_var.value, pagerank_var.value = self.gindex, self.page, self.pagerank

    def validate(self):
        global raw_data_dict
        import time
        sm.get_screen("PhishSafe").ids['check_btn'].disabled = True
        ws = time.time()
        self.loads = TraceThread(target=self.load)
        self.loads.start()

        if self.y in raw_data_dict.keys():
            self.loads.killed = True
            if raw_data_dict[self.y] >= 0.5:
                sm.get_screen("PhishSafe").ids['result'].text = " Website Status: The Site Is Not Safe!!"
            elif ypred < 0.5:
                try:
                    import urllib.request
                    resp = urllib.request.urlopen(y + "=1\' or \'1\' = \'1\''")
                    body = resp.read()
                    fullbody = body.decode("utf-8")
                    if "You have an error in your SQL syntax" in fullbody:
                        sm.get_screen("PhishSafe").ids['result'].text = " Website Status: The Site Is prone to large-scale data theft!!"
                    else:
                        sm.get_screen("PhishSafe").ids['result'].text = " Website Status: The Site Is Safe!!"

                except Exception:
                    sm.get_screen("PhishSafe").ids['result'].text = " Website Status: The Site Is Safe!!"
            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
            sm.get_screen("PhishSafe").ids['url'].disabled = False
            return

        import json
        import socket
        import urllib.request
        from urllib.parse import urlparse
        import xmltodict
        import tldextract
        import time

        y = self.url

        w = tldextract.extract(y).domain
        s = tldextract.extract(y).suffix
        qtr = w
        domain = str(w) + "." + str(s)

        if self.y.startswith("file:///"):
            self.loads.killed = True
            sm.get_screen("PhishSafe").ids['result'].text = " Website Status: Enter a Valid URL!!"
            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
            sm.get_screen("PhishSafe").ids['url'].disabled = False
            return

        if w == "amazon":
            self.loads.killed = True
            sm.get_screen("PhishSafe").ids['result'].text = " Website Status: The Site Is Safe!!"
            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
            sm.get_screen("PhishSafe").ids['url'].disabled = False
            return

        if w == "google":
            self.loads.killed = True
            sm.get_screen("PhishSafe").ids['result'].text = " Website Status: The Site Is Safe!!"
            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
            sm.get_screen("PhishSafe").ids['url'].disabled = False
            return

        if w == "wixsite":
            self.loads.killed = True
            sm.get_screen("PhishSafe").ids['result'].text = " Website Status: The Site Is Safe!!"
            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
            sm.get_screen("PhishSafe").ids['url'].disabled = False
            return

        if w == "youtube":
            self.loads.killed = True
            sm.get_screen("PhishSafe").ids['result'].text = " Website Status: The Site Is Safe!!"
            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
            sm.get_screen("PhishSafe").ids['url'].disabled = False
            return

        if w == "wix":
            self.loads.killed = True
            sm.get_screen("PhishSafe").ids['result'].text = " Website Status: The Site Is Safe!!"
            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
            sm.get_screen("PhishSafe").ids['url'].disabled = False
            return

        if w == "localhost":
            self.loads.killed = True
            sm.get_screen("PhishSafe").ids['result'].text = " Website Status: The Site Is Safe!!"
            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
            sm.get_screen("PhishSafe").ids['url'].disabled = False
            return

        if w == "instagram":
            self.loads.killed = True
            sm.get_screen("PhishSafe").ids['result'].text = " Website Status: The Site Is Safe!!"
            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
            sm.get_screen("PhishSafe").ids['url'].disabled = False
            return

        if w == "facebook":
            self.loads.killed = True
            sm.get_screen("PhishSafe").ids['result'].text = " Website Status: The Site Is Safe!!"
            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
            sm.get_screen("PhishSafe").ids['url'].disabled = False
            return

        if w == "Udemy":
            self.loads.killed = True
            sm.get_screen("PhishSafe").ids['result'].text = " Website Status: The Site Is Safe!!"
            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
            sm.get_screen("PhishSafe").ids['url'].disabled = False
            return

        if w == "flipkart":
            self.loads.killed = True
            sm.get_screen("PhishSafe").ids['result'].text = " Website Status: The Site Is Safe!!"
            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
            sm.get_screen("PhishSafe").ids['url'].disabled = False
            return

        if w == "about":
            self.loads.killed = True
            sm.get_screen("PhishSafe").ids['result'].text = " Website Status: The Site Is Safe!!"
            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
            sm.get_screen("PhishSafe").ids['url'].disabled = False
            return

        if w == "stackoverflow":
            self.loads.killed = True
            sm.get_screen("PhishSafe").ids['result'].text = " Website Status: The Site Is Safe!!"
            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
            sm.get_screen("PhishSafe").ids['url'].disabled = False
            return

        if w == "127.0.0.1":
            self.loads.killed = True
            sm.get_screen("PhishSafe").ids['result'].text = " Website Status: The Site Is Safe!!"
            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
            sm.get_screen("PhishSafe").ids['url'].disabled = False
            return

        if w == "cricbuzz":
            self.loads.killed = True
            sm.get_screen("PhishSafe").ids['result'].text = " Website Status: The Site Is Safe!!"
            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
            sm.get_screen("PhishSafe").ids['url'].disabled = False
            return

        else:
            mam = True

            if y != "":
                dd = True
                rew = False
                if dd:
                    import requests
                    try:
                        req = requests.get(y, timeout=10, verify=True)
                        if req.status_code == 200:
                            qw = True
                        else:
                            qw = False
                            qa = False

                    except requests.exceptions.ConnectionError:
                        self.loads.killed = True
                        sm.get_screen("PhishSafe").ids[
                            'result'].text = " Website Status: Site is Down or your connection in unstable"
                        sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
                        sm.get_screen("PhishSafe").ids['url'].disabled = False
                        return

                    except requests.exceptions.MissingSchema:
                        self.loads.killed = True
                        sm.get_screen("PhishSafe").ids['result'].text = " Website Status: Site Not Found"
                        sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
                        sm.get_screen("PhishSafe").ids['url'].disabled = False
                        return

                    except requests.exceptions.InvalidURL:
                        self.loads.killed = True
                        sm.get_screen("PhishSafe").ids['result'].text = " Website Status: Enter A Valid URL"
                        sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
                        sm.get_screen("PhishSafe").ids['url'].disabled = False
                        return

                    except UnicodeError:
                        self.loads.killed = True
                        sm.get_screen("PhishSafe").ids['result'].text = " Website Status: Enter A Valid URL"
                        sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
                        sm.get_screen("PhishSafe").ids['url'].disabled = False
                        return

                    except requests.exceptions.InvalidSchema:
                        self.loads.killed = True
                        sm.get_screen("PhishSafe").ids['result'].text = " Website Status: Enter A Valid URL"
                        sm.get_screen("PhishSafe").ids['check_btn'].disabled = Falsetry
                        sm.get_screen("PhishSafe").ids['url'].disabled = False
                        return
                if qw:
                    o = urlparse(y)

                    port = o.port
                    scheme = o.scheme

                    full_domain = str(scheme) + "://www." + str(domain) + "/favicon.ico"

                    dot = "."
                    dots = domain.count(dot)

                    at = "@"
                    ats = y.count(at)

                    hashes = "//"
                    hashed = y.count(hashes)

                    dash = "-"
                    dashes = domain.count(dash)
                    import requests

                    if dd:
                        try:
                            req = requests.get(y)
                            if req.status_code == 200:
                                rew = True
                            else:
                                rew = False

                        except requests.exceptions.ConnectionError:
                            self.loads.killed = True
                            sm.get_screen("PhishSafe").ids['result'].text = " Website Status: Site Not Found"
                            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
                            sm.get_screen("PhishSafe").ids['url'].disabled = False
                            return

                        except requests.exceptions.MissingSchema:
                            self.loads.killed = True
                            sm.get_screen("PhishSafe").ids['result'].text = " Website Status: Site Not Found"
                            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
                            sm.get_screen("PhishSafe").ids['url'].disabled = False
                            return

                        except requests.exceptions.InvalidURL:
                            self.loads.killed = True
                            sm.get_screen("PhishSafe").ids['result'].text = " Website Status: Enter A Valid URL"
                            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
                            sm.get_screen("PhishSafe").ids['url'].disabled = False
                            return

                        except UnicodeError:
                            self.loads.killed = True
                            sm.get_screen("PhishSafe").ids['result'].text = " Website Status: Enter A Valid URL"
                            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
                            sm.get_screen("PhishSafe").ids['url'].disabled = False
                            return

                        except requests.exceptions.InvalidSchema:
                            self.loads.killed = True
                            sm.get_screen("PhishSafe").ids['result'].text = " Website Status: Enter A Valid URL"
                            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
                            sm.get_screen("PhishSafe").ids['url'].disabled = False
                            return
                    if rew:
                        print("-------------------------")
                        now = time.time()
                        try:
                            seven_para = multiprocessing.Value("d", 0.0, lock=False)
                            ssl = multiprocessing.Value("d", 0.0, lock=False)
                            favicon = multiprocessing.Value("d", 0.0, lock=False)
                            date1 = multiprocessing.Value("d", 0.0, lock=False)
                            port_1 = multiprocessing.Value("d", 0.0, lock=False)
                            https_token = multiprocessing.Value("d", 0.0, lock=False)
                            mail = multiprocessing.Value("d", 0.0, lock=False)
                            abnormal = multiprocessing.Value("d", 0.0, lock=False)
                            redirect = multiprocessing.Value("d", 0.0, lock=False)
                            mouseover = multiprocessing.Value("d", 0.0, lock=False)
                            age_domain = multiprocessing.Value("d", 0.0, lock=False)
                            server = multiprocessing.Value("d", 0.0, lock=False)
                            dns = multiprocessing.Value("d", 0.0, lock=False)
                            alexa = multiprocessing.Value("d", 0.0, lock=False)
                            page = multiprocessing.Value("d", 0.0, lock=False)
                            gindex = multiprocessing.Value("d", 0.0, lock=False)
                            pagerank = multiprocessing.Value("d", 0.0, lock=False)

                            seven_para_func = multiprocessing.Process(target=self.seven_para_foo,
                                                                      args=(seven_para,))
                            ssl_func = multiprocessing.Process(target=self.ssl_foo,
                                                               args=(ssl,))
                            favicon_func = multiprocessing.Process(target=self.favicon_foo,
                                                                   args=(favicon,))
                            date1_func = multiprocessing.Process(target=self.date1_foo,
                                                                 args=(date1,))
                            port_1_func = multiprocessing.Process(target=self.port_1_foo,
                                                                  args=(port_1,))
                            https_token_func = multiprocessing.Process(target=self.https_token_foo,
                                                                       args=(https_token,))
                            mail_func = multiprocessing.Process(target=self.mail_foo,
                                                                args=(mail,))
                            abnormal_func = multiprocessing.Process(target=self.abnormal_foo,
                                                                    args=(abnormal,))
                            redirect_func = multiprocessing.Process(target=self.redirect_foo,
                                                                    args=(redirect,))
                            mouseover_func = multiprocessing.Process(target=self.mouseover_foo,
                                                                     args=(mouseover,))
                            age_domain_func = multiprocessing.Process(target=self.age_domain_foo,
                                                                      args=(age_domain,))
                            server_func = multiprocessing.Process(target=self.server_foo,
                                                                  args=(server,))
                            dns_func = multiprocessing.Process(target=self.dns_foo,
                                                               args=(dns,))
                            alexa_func = multiprocessing.Process(target=self.alexa_foo,
                                                                 args=(alexa,))
                            google_func = multiprocessing.Process(target=self.google_foo,
                                                                  args=(page, gindex, pagerank))

                            if "win" in sys.platform:
                                seven_para_func.run()
                                ssl_func.run()
                                favicon_func.run()
                                date1_func.run()
                                port_1_func.run()
                                https_token_func.run()
                                mail_func.run()
                                abnormal_func.run()
                                redirect_func.run()
                                mouseover_func.run()
                                age_domain_func.run()
                                server_func.run()
                                dns_func.run()
                                alexa_func.run()
                                google_func.run()
                            else:
                                seven_para_func.start()
                                ssl_func.start()
                                favicon_func.start()
                                date1_func.start()
                                port_1_func.start()
                                https_token_func.start()
                                mail_func.start()
                                abnormal_func.start()
                                redirect_func.start()
                                mouseover_func.start()
                                age_domain_func.start()
                                server_func.start()
                                dns_func.start()
                                alexa_func.start()
                                google_func.start()

                                seven_para_func.join()
                                ssl_func.join()
                                favicon_func.join()
                                date1_func.join()
                                port_1_func.join()
                                https_token_func.join()
                                mail_func.join()
                                abnormal_func.join()
                                redirect_func.join()
                                mouseover_func.join()
                                age_domain_func.join()
                                server_func.join()
                                dns_func.join()
                                alexa_func.join()
                                google_func.join()

                            import requests
                        except socket.timeout:
                            self.loads.killed = True
                            sm.get_screen("PhishSafe").ids[
                                'result'].text = " Website Status: Your Search Timed Out! Please Try Again"
                            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
                            sm.get_screen("PhishSafe").ids['url'].disabled = False
                            return

                        except socket.gaierror:
                            self.loads.killed = True
                            sm.get_screen("PhishSafe").ids['result'].text = " Website Status: Site Not Found"
                            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
                            sm.get_screen("PhishSafe").ids['url'].disabled = False
                            return

                        except TimeoutError:
                            self.loads.killed = True
                            sm.get_screen("PhishSafe").ids[
                                'result'].text = " Website Status: Your Search Timed Out! Please Try Again"
                            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
                            sm.get_screen("PhishSafe").ids['url'].disabled = False
                            return

                        except ConnectionResetError:
                            self.loads.killed = True
                            sm.get_screen("PhishSafe").ids[
                                'result'].text = " Website Status: Connection was reset the the peer"
                            sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
                            sm.get_screen("PhishSafe").ids['url'].disabled = False
                            return
                        print(time.time() - now)
                        if True:
                            our_variable = -0.01915802 * int(seven_para.value) + int(ssl.value) * - 1.71189339 + int(
                                date1.value) * -0.00595468 + int(favicon.value) * -0.08375977 + int(
                                port_1.value) * -0.47910877 + int(https_token.value) * -0.56937711 + (
                                                   0 * - 0.29626907) + 0 * - 3.31305535 + 0 * -0.86331893 + int(
                                server.value) * -0.74623152 + int(
                                mail.value) * -0.19529392 + int(
                                abnormal.value) * -0.08780527 + (int(redirect.value) * 1.25181079) + int(
                                mouseover.value) * -0.19236432 + 0 * -0.05754686 + 0 * 0.14548539 + 0 * 0.15879801 + int(
                                age_domain.value) * -0.20951269 + int(
                                dns.value) * -0.32383567 + (int(alexa.value) * -0.60153451) + int(
                                page.value) * - 0.18553769 + int(gindex.value) * - 0.66926252 + int(
                                pagerank.value) * -0.68691833 + 0 * -0.25926185 - 0.01837075

                            variable = [int(seven_para.value), int(ssl.value), int(date1.value), int(favicon.value),
                                        int(port_1.value), int(https_token.value), 0, 0, 0, int(server.value),
                                        int(mail.value),
                                        int(abnormal.value), int(redirect.value), int(mouseover.value), 0, 0, 0,
                                        int(age_domain.value), int(dns.value), int(alexa.value), int(page.value),
                                        int(gindex.value), int(pagerank.value), 0]
                            good_value = -our_variable
                            ypred = 1 / (1 + (np.exp(good_value)))
                            if 0.5 > ypred >= 0.42:
                                ypred += 0.08
                            print(ypred)
                            print(variable)
                            raw_data_dict[self.y] = ypred
                            if ypred >= 0.5:
                                self.loads.killed = True
                                sm.get_screen("PhishSafe").ids[
                                    'result'].text = " Website Status: The Site Is Not Safe!!"
                                sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
                                sm.get_screen("PhishSafe").ids['url'].disabled = False
                                return

                            elif ypred < 0.5:
                                try:
                                    import urllib.request

                                    resp = urllib.request.urlopen(y + "=1\' or \'1\' = \'1\''")
                                    body = resp.read()
                                    fullbody = body.decode("utf-8")
                                    if "You have an error in your SQL syntax" in fullbody:
                                        self.loads.killed = True
                                        sm.get_screen("PhishSafe").ids[
                                            'result'].text = " Website Status: The Site Is prone to large-scale data theft!!"
                                        sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
                                        sm.get_screen("PhishSafe").ids['url'].disabled = False
                                        return
                                    else:
                                        self.loads.killed = True
                                        sm.get_screen("PhishSafe").ids[
                                            'result'].text = " Website Status: The Site Is Safe!!"
                                        sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
                                        sm.get_screen("PhishSafe").ids['url'].disabled = False
                                        return

                                except Exception:
                                    self.loads.killed = True
                                    sm.get_screen("PhishSafe").ids[
                                        'result'].text = " Website Status: The Site Is Safe!!"
                                    sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
                                    sm.get_screen("PhishSafe").ids['url'].disabled = False
                                    return
                else:
                    self.loads.killed = True
                    sm.get_screen("PhishSafe").ids['result'].text = " Website Status: The Site Is Not Safe!!"
                    sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
                    sm.get_screen("PhishSafe").ids['url'].disabled = False
                    return

            elif y == "":
                self.loads.killed = True
                sm.get_screen("PhishSafe").ids['result'].text = " Website Status: Please Enter A URL"
                sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
                sm.get_screen("PhishSafe").ids['url'].disabled = False
                return

            else:
                self.loads.killed = True
                sm.get_screen("PhishSafe").ids['result'].text = " Website Status: The Site Is Not Safe!!"
                sm.get_screen("PhishSafe").ids['check_btn'].disabled = False
                sm.get_screen("PhishSafe").ids['url'].disabled = False
                return


class VirusSafe:
    class Quarentine:
        def __init__(self):
            pass

        def encode_base64(self, file, qPath):
            import base64
            import sys

            org_file_path = bytes(file, "utf-8")
            if "win" in sys.platform:
                org_file_name = file.rfind("\\")
            else:
                org_file_name = file.rfind("/")
            org_file_name = file[org_file_name + 1:]
            print(org_file_name)
            f = open(file, "rb")
            org_content = f.read()
            f.close()
            os.remove(file)
            new_content = base64.b64encode(org_content)
            if "win" in sys.platform:
                f = open(qPath + org_file_name + ".eb64", "wb")
                f.write(org_file_path + b"\n")
                f.write(new_content)
                f.close()
            else:
                if "win" in sys.platform:
                    org_file_name = org_file_name.split("\\")
                else:
                    org_file_name = org_file_name.split("/")
                org_file_name = org_file_name[-1]
                f = open(qPath + org_file_name + ".eb64", "wb")
                f.write(org_file_path + b"\n")
                f.write(new_content)
                f.close()

        def decode_base64(self, file):
            import base64
            import sys
            f = open(file, "rb")
            org_content = f.read()
            f.close()
            org_content = org_content.splitlines()
            org_file_path = org_content[0]
            org_content.remove(org_file_path)
            new_content = []
            for i in org_content:
                new_content.append(base64.b64decode(i))
            f = open(org_file_path, "wb")
            for i in new_content:
                f.write(i + b"\n")
            f.close()
            os.remove(file)

    class scan:
        def __init__(self):
            pass

        def scan(self):
            import sys, os
            if "win" in sys.platform:
                file_to_quarantine = os.getcwd() + "\\VirusSafe_drivers\\Quarantine\\"
            else:
                file_to_quarantine = os.getcwd() + "/VirusSafe_drivers/Quarantine/"
            import time

            match = False
            import PySimpleGUI as sg
            file = filebrowser("")
            if file == "":
                return ["choose a file", "Please "]
            while 1:
                try:
                    import urllib.request
                    url = "https://raw.githubusercontent.com/Cyberrely-Official/signatures/main/signature"
                    filew = urllib.request.urlopen(url)
                    break
                except Exception:
                    pass
            des = b''
            for line in filew:
                decoded_line = line.decode("utf-8")
                des += str(decoded_line).encode()
            if "win" in sys.platform:
                we = open("Application_Externals\\driver", "r")
            else:
                we = open("Application_Externals/driver", "r")
            wes = we.read()
            we.close()
            we = wes.split("\n")
            if file in we:
                return [f"{file}",
                        "You have exempted checking of the file:"]
            else:
                start = time.time()
                try:
                    f = open(file, "rb")
                    content = f.read()
                    f.close()
                    a = extra_resources()
                    content = a.create_md5(content)
                except MemoryError:
                    return None
                except Exception as e:
                    return None

                if content in des:
                    match = True
                else:
                    match = False

                if match:
                    types = VirusSafe.Quarentine()
                    types.encode_base64(file, file_to_quarantine)
                    return ["[ ! ] " + file + " scanned: File is a Virus. Moving to Quarantine.",
                            "[ * ] Scan duration: {0} seconds\n".format(round(time.time() - start, 2))]
                if not match:
                    return ["[ ! ] " + file + " scanned: File is not a Virus.",
                            "[ * ] Scan duration: {0} seconds\n".format(round(time.time() - start, 2))]

        def scan1(self, file):
            import sys, os
            if "win" in sys.platform:
                file_to_quarantine = os.getcwd() + "\\VirusSafe_drivers\\Quarantine\\"
            else:
                file_to_quarantine = os.getcwd() + "/VirusSafe_drivers/Quarantine/"
            import time

            match = False
            while 1:
                try:
                    import urllib.request
                    url = "https://raw.githubusercontent.com/Cyberrely-Official/signatures/main/signature"
                    filew = urllib.request.urlopen(url)
                    break
                except Exception:
                    pass
            des = b''
            for line in filew:
                decoded_line = line.decode("utf-8")
                des += str(decoded_line).encode()
            if "win" in sys.platform:
                we = open("Application_Externals\\driver", "r")
            else:
                we = open("Application_Externals/driver", "r")
            wes = we.read()
            we.close()
            we = wes.split("\n")
            if file in we:
                return None
            else:
                start = time.time()
                try:
                    f = open(file, "rb")
                    content = f.read()
                    f.close()
                    zxcv = extra_resources()
                    content = zxcv.create_md5(content)
                except MemoryError:
                    return None
                except Exception as e:
                    return None

                if content in des:
                    match = True
                else:
                    match = False

                if match:
                    hello = VirusSafe.Quarentine()
                    hello.encode_base64(file, file_to_quarantine)


class encryption:
    def __init__(self):
        import PySimpleGUI as sg
        self.file = filebrowser("")

    def encrypt(self, output):
        from cryptography.fernet import Fernet
        from pyenigma import enigma
        from pyenigma import rotor
        import random
        a = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
             'V',
             'W',
             'X', 'Y', 'Z']
        b = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
             'V',
             'W',
             'X', 'Y', 'Z']
        c = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
             'V',
             'W',
             'X', 'Y', 'Z']
        for_us_a = random.choice(a)
        for_us_b = random.choice(b)
        for_us_c = random.choice(c)
        selected_a = random.choice(a)
        selected_b = random.choice(b)
        selected_c = random.choice(c)
        final_for_user = str(selected_a + selected_b + selected_c)
        key3 = Fernet.generate_key()
        user_key = key3.decode() + final_for_user
        our_engine = enigma.Enigma(rotor.ROTOR_Reflector_A, rotor.ROTOR_I,
                                   rotor.ROTOR_II, rotor.ROTOR_III, key="PQZ",
                                   plugs="AS BV CL DG FZ HU IM KN OX RW")
        code = our_engine.encipher(key3.decode() + final_for_user)
        code = code.encode()
        our_engine1 = enigma.Enigma(rotor.ROTOR_Reflector_A, rotor.ROTOR_I,
                                    rotor.ROTOR_II, rotor.ROTOR_III, key="PQZ",
                                    plugs="AS BV CL DG FZ HU IM KN OX RW")
        code1 = our_engine1.encipher(code.decode())
        key1 = code1
        key1 = list(key1)
        one_key = key1[-1] + key1[-2] + key1[-3]
        key1.pop(-1)
        key1.pop(-1)
        key1.pop(-1)
        keys = ''.join(map(str, key1))
        f = Fernet(keys.encode())
        try:
            with open(self.file, "rb") as file:
                file_data = file.read()
            encrypted_data = f.encrypt(file_data)
            op = enigma.Enigma(rotor.ROTOR_Reflector_A, rotor.ROTOR_I,
                               rotor.ROTOR_II, rotor.ROTOR_III, key=str(one_key),
                               plugs="AV BS CG DL FU HZ IN KM OW RX")
            encrypted_contents = op.encipher(encrypted_data.decode())
            with open(output, "wb") as file:
                if "win" in sys.platform:
                    file.write(
                        code + "|".encode() + (
                            self.file.split("\\")[-1]).encode() + "\n".encode() + encrypted_contents.encode())
                else:
                    file.write(
                        code + "|".encode() + (
                            self.file.split("/")[-1]).encode() + "\n".encode() + encrypted_contents.encode())
            return user_key

        except FileNotFoundError:
            return "File not Found"

    def decrypt(self, key):
        from cryptography.fernet import Fernet
        from pyenigma import enigma
        from pyenigma import rotor
        import random
        import os
        try:
            with open(self.file, "rb") as file:
                password = file.read().decode()
                restore = password
            password = password.split("\n")
            password1 = password[0].split("|")
            passwords = password1[0].encode()
            password.pop(0)
            for item in password:
                with open(self.file, "wb") as file:
                    file.write(item.encode())
            our_engine2 = enigma.Enigma(rotor.ROTOR_Reflector_A, rotor.ROTOR_I,
                                        rotor.ROTOR_II, rotor.ROTOR_III, key="PQZ",
                                        plugs="AS BV CL DG FZ HU IM KN OX RW")
            codez = our_engine2.encipher(passwords.decode())
            if key == codez:
                key = key
                key = list(key)
                one_key = key[-1] + key[-2] + key[-3]
                key.pop(-1)
                key.pop(-1)
                key.pop(-1)
                key = ''.join(map(str, key))
                f = Fernet(key.encode())
                with open(self.file, "rb") as file:
                    encrypted_data = file.read()
                op = enigma.Enigma(rotor.ROTOR_Reflector_A, rotor.ROTOR_I,
                                   rotor.ROTOR_II, rotor.ROTOR_III, key=str(one_key),
                                   plugs="AV BS CG DL FU HZ IN KM OW RX")
                encrypted_contents = op.encipher(encrypted_data.decode())
                decrypted_data = f.decrypt(encrypted_contents.encode())
                desktop = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop')
                if "win" in sys.platform:
                    with open(desktop + "\\" + password1[-1], "wb") as file:
                        file.write(decrypted_data)
                else:
                    with open(desktop + "/" + password1[-1], "wb") as file:
                        file.write(decrypted_data)
                with open(self.file, "wb") as file:
                    file.write(restore.encode())
                return "Done! Placed on the desktop."
            else:
                return "Wrong Password"
        except FileNotFoundError:
            return "File not Found"


class MailSafe:
    def __init__(self, email, passwd):
        self.email, self.passwd = email, passwd

    def detect_spam(self, mail):
        def word_freq(word, li):
            list_w = li
            number = len(list_w)
            counter = 0
            for w in list_w:
                if w == word:
                    counter += 1
            return (counter / number) * 100

        def char_freq(char, li):
            st = " "
            mail = st.join(li)
            counter = 0
            for w in mail:
                if w == char:
                    counter += 1
            return (counter / len(mail)) * 100

        def capital_run_length_longest(li):
            list_w = li
            counters = []
            for word in list_w:
                counter = 0
                for l in word:
                    if l.isupper():
                        counter += 1
                    elif counter != 0:
                        counters.append(counter)
                        counter = 0
                if counter != 0:
                    counters.append(counter)
            counters.sort()
            if not counters:
                return 0
            else:
                final = counters[-1]
                return final

        def capital_run_length_average(li):
            list_w = li
            counters = []
            for word in list_w:
                counter = 0
                for l in word:
                    if l.isupper():
                        counter += 1
                    elif counter != 0:
                        counters.append(counter)
                        counter = 0
                if counter != 0:
                    counters.append(counter)
            counters.sort()
            global add
            times = 0
            add = 0
            for element in counters:
                add += element
                times += 1
            if times == 0:
                return 0
            else:
                return add / times

        def capital_run_length_total(li):
            list_w = li
            counters = []
            for word in list_w:
                counter = 0
                for l in word:
                    if l.isupper():
                        counter += 1
                    elif counter != 0:
                        counters.append(counter)
                        counter = 0
                if counter != 0:
                    counters.append(counter)
            counters.sort()
            global add
            times = 0
            add = 0
            for element in counters:
                add += element
                times += 1
            return add

        results = []
        li = mail.split()
        if len(li) > 30:
            while len(li) > 30 or round(predict) != 1:
                test = li[:30]
                if len(test) < 30:
                    break
                try:
                    if round(predict) == 1:
                        break
                except UnboundLocalError:
                    pass
                array = [word_freq('make', test), word_freq('address', test), word_freq('all', test),
                         word_freq('3d', test),
                         word_freq('our', test), word_freq('over', test), word_freq('remove', test),
                         word_freq('internet', test),
                         word_freq('order', test), word_freq('test', test), word_freq('receive', test),
                         word_freq('will', test),
                         word_freq('people', test), word_freq('report', test), word_freq('addresses', test),
                         word_freq('free', test),
                         word_freq('business', test), word_freq('etest', test), word_freq('you', test),
                         word_freq('credit', test),
                         word_freq('your', test), word_freq('font', test), word_freq('000', test),
                         word_freq('money', test),
                         word_freq('hp', test), word_freq('hpl', test), word_freq('george', test),
                         word_freq('650', test),
                         word_freq('lab', test), word_freq('labs', test), word_freq('telnet', test),
                         word_freq('857', test),
                         word_freq('data', test), word_freq('415', test), word_freq('85', test),
                         word_freq('technology', test),
                         word_freq('1999', test), word_freq('parts', test), word_freq('pm', test),
                         word_freq('direct', test),
                         word_freq('cs', test), word_freq('meeting', test), word_freq('original', test),
                         word_freq('project', test),
                         word_freq('re', test), word_freq('edu', test), word_freq('table', test),
                         word_freq('conference', test),
                         char_freq(';', test), char_freq('(', test), char_freq('[', test), char_freq('!', test),
                         char_freq('$', test), char_freq('#', test),
                         capital_run_length_average(test), capital_run_length_longest(test),
                         capital_run_length_total(test),
                         1]
                array_2 = [[5.27156123e-02, -2.47090783e-01, 1.42785180e-01, 2.50471113e-01,
                            9.02302260e-01, 4.44916817e-01, 1.24389998e+00, 7.27472773e-01,
                            2.58643873e-01, 1.73480714e-01, 3.01132646e-01, -6.57910943e-02,
                            1.74738428e-01, 1.21679508e-01, 2.43237713e-01, 1.18335135e+00,
                            6.75597460e-01, 3.11129322e-01, 2.83588695e-02, 4.89022289e-01,
                            2.19836395e-01, 2.94136350e-01, 9.97502100e-01, 5.73404886e-01,
                            -2.46263894e+00, -1.26114828e+00, -2.96899282e+00, -3.04843469e-01,
                            -5.61835542e-01, -4.60928236e-01, -3.18891078e-01, -1.80849992e-01,
                            -7.45858865e-01, -1.84950808e-01, -5.42464436e-01, -7.69256646e-02,
                            -5.66903348e-01, -5.18826043e-02, -4.50592727e-01, -1.59053786e-01,
                            -3.72006043e-01, -9.76486522e-01, -2.51248896e-01, -6.13605965e-01,
                            -9.54401620e-01, -1.43791203e+00, -6.75366721e-02, -3.20045520e-01,
                            -4.67332557e-01, -2.81173409e-01, -1.00871964e-01, 5.31425076e-01,
                            7.39646708e-01, 2.57156784e-01, -1.88617201e-02, 1.08873291e-02,
                            7.29562498e-04, -1.41616581]]
                before_final = np.multiply(array, array_2)
                final = np.sum(before_final)
                to_use = -final
                predict = 1 / (1 + np.exp(to_use))
                li = li[30:]
            if round(predict) == 1:
                return True
            else:
                array = [word_freq('make', li), word_freq('address', li), word_freq('all', li), word_freq('3d', li),
                         word_freq('our', li), word_freq('over', li), word_freq('remove', li),
                         word_freq('internet', li),
                         word_freq('order', li), word_freq('li', li), word_freq('receive', li), word_freq('will', li),
                         word_freq('people', li), word_freq('report', li), word_freq('addresses', li),
                         word_freq('free', li),
                         word_freq('business', li), word_freq('eli', li), word_freq('you', li), word_freq('credit', li),
                         word_freq('your', li), word_freq('font', li), word_freq('000', li), word_freq('money', li),
                         word_freq('hp', li), word_freq('hpl', li), word_freq('george', li), word_freq('650', li),
                         word_freq('lab', li), word_freq('labs', li), word_freq('telnet', li), word_freq('857', li),
                         word_freq('data', li), word_freq('415', li), word_freq('85', li), word_freq('technology', li),
                         word_freq('1999', li), word_freq('parts', li), word_freq('pm', li), word_freq('direct', li),
                         word_freq('cs', li), word_freq('meeting', li), word_freq('original', li),
                         word_freq('project', li),
                         word_freq('re', li), word_freq('edu', li), word_freq('table', li), word_freq('conference', li),
                         char_freq(';', li), char_freq('(', li), char_freq('[', li), char_freq('!', li),
                         char_freq('$', li),
                         char_freq('#', li),
                         capital_run_length_average(li), capital_run_length_longest(li), capital_run_length_total(li),
                         1]
                array_2 = [[5.27156123e-02, -2.47090783e-01, 1.42785180e-01, 2.50471113e-01,
                            9.02302260e-01, 4.44916817e-01, 1.24389998e+00, 7.27472773e-01,
                            2.58643873e-01, 1.73480714e-01, 3.01132646e-01, -6.57910943e-02,
                            1.74738428e-01, 1.21679508e-01, 2.43237713e-01, 1.18335135e+00,
                            6.75597460e-01, 3.11129322e-01, 2.83588695e-02, 4.89022289e-01,
                            2.19836395e-01, 2.94136350e-01, 9.97502100e-01, 5.73404886e-01,
                            -2.46263894e+00, -1.26114828e+00, -2.96899282e+00, -3.04843469e-01,
                            -5.61835542e-01, -4.60928236e-01, -3.18891078e-01, -1.80849992e-01,
                            -7.45858865e-01, -1.84950808e-01, -5.42464436e-01, -7.69256646e-02,
                            -5.66903348e-01, -5.18826043e-02, -4.50592727e-01, -1.59053786e-01,
                            -3.72006043e-01, -9.76486522e-01, -2.51248896e-01, -6.13605965e-01,
                            -9.54401620e-01, -1.43791203e+00, -6.75366721e-02, -3.20045520e-01,
                            -4.67332557e-01, -2.81173409e-01, -1.00871964e-01, 5.31425076e-01,
                            7.39646708e-01, 2.57156784e-01, -1.88617201e-02, 1.08873291e-02,
                            7.29562498e-04, -1.41616581]]
                before_final = np.multiply(array, array_2)
                final = np.sum(before_final)
                to_use = -final
                predict = 1 / (1 + np.exp(to_use))
                if round(predict) == 1:
                    return True
                return False
        else:
            array = [word_freq('make', li), word_freq('address', li), word_freq('all', li), word_freq('3d', li),
                     word_freq('our', li), word_freq('over', li), word_freq('remove', li), word_freq('internet', li),
                     word_freq('order', li), word_freq('li', li), word_freq('receive', li), word_freq('will', li),
                     word_freq('people', li), word_freq('report', li), word_freq('addresses', li),
                     word_freq('free', li),
                     word_freq('business', li), word_freq('eli', li), word_freq('you', li), word_freq('credit', li),
                     word_freq('your', li), word_freq('font', li), word_freq('000', li), word_freq('money', li),
                     word_freq('hp', li), word_freq('hpl', li), word_freq('george', li), word_freq('650', li),
                     word_freq('lab', li), word_freq('labs', li), word_freq('telnet', li), word_freq('857', li),
                     word_freq('data', li), word_freq('415', li), word_freq('85', li), word_freq('technology', li),
                     word_freq('1999', li), word_freq('parts', li), word_freq('pm', li), word_freq('direct', li),
                     word_freq('cs', li), word_freq('meeting', li), word_freq('original', li), word_freq('project', li),
                     word_freq('re', li), word_freq('edu', li), word_freq('table', li), word_freq('conference', li),
                     char_freq(';', li), char_freq('(', li), char_freq('[', li), char_freq('!', li), char_freq('$', li),
                     char_freq('#', li),
                     capital_run_length_average(li), capital_run_length_longest(li), capital_run_length_total(li), 1]
            array_2 = [[5.27156123e-02, -2.47090783e-01, 1.42785180e-01, 2.50471113e-01,
                        9.02302260e-01, 4.44916817e-01, 1.24389998e+00, 7.27472773e-01,
                        2.58643873e-01, 1.73480714e-01, 3.01132646e-01, -6.57910943e-02,
                        1.74738428e-01, 1.21679508e-01, 2.43237713e-01, 1.18335135e+00,
                        6.75597460e-01, 3.11129322e-01, 2.83588695e-02, 4.89022289e-01,
                        2.19836395e-01, 2.94136350e-01, 9.97502100e-01, 5.73404886e-01,
                        -2.46263894e+00, -1.26114828e+00, -2.96899282e+00, -3.04843469e-01,
                        -5.61835542e-01, -4.60928236e-01, -3.18891078e-01, -1.80849992e-01,
                        -7.45858865e-01, -1.84950808e-01, -5.42464436e-01, -7.69256646e-02,
                        -5.66903348e-01, -5.18826043e-02, -4.50592727e-01, -1.59053786e-01,
                        -3.72006043e-01, -9.76486522e-01, -2.51248896e-01, -6.13605965e-01,
                        -9.54401620e-01, -1.43791203e+00, -6.75366721e-02, -3.20045520e-01,
                        -4.67332557e-01, -2.81173409e-01, -1.00871964e-01, 5.31425076e-01,
                        7.39646708e-01, 2.57156784e-01, -1.88617201e-02, 1.08873291e-02,
                        7.29562498e-04, -1.41616581]]
            before_final = np.multiply(array, array_2)
            final = np.sum(before_final)
            to_use = -final
            predict = 1 / (1 + np.exp(to_use))
            if round(predict) == 1:
                return True
            return False

    def parse_uid(self, data):
        import re
        pattern_uid = re.compile(b'\d+ \(UID (?P<uid>\d+)\)'.decode())
        match = pattern_uid.match(data)
        return match.group('uid')

    def mailsafe(self):
        while 1:
            import imaplib
            import email
            from email.header import decode_header
            username = str(self.email)
            password1 = str(self.passwd)
            imap = imaplib.IMAP4_SSL("imap.gmail.com")
            try:
                imap.login(username, password1)
            except imaplib.IMAP4.error:
                import PySimpleGUI as sg
                sg.Popup(
                    'Invalid credentials or you have not enable Gmail API or less secure apps or Enable IMAP. Please '
                    'follow the steps below.')
                import time
                time.sleep(3)
                global t
                t.killed = True
            status, messages = imap.select("INBOX")
            N = 1
            messages = int(messages[0])
            retcode, messagess = imap.search(None, '(UNSEEN)')
            messagess = str(messagess[0]).split("'")[1].split(" ")
            for i in range(messages, messages - N, -1):
                res, msg = imap.fetch(str(i), "(RFC822)")
                for response in msg:
                    if isinstance(response, tuple):
                        msg = email.message_from_bytes(response[1])
                        subject = decode_header(msg["Subject"])[0][0]
                        if isinstance(subject, bytes):
                            subject = subject.decode()
                        from_ = msg.get("From")
                        o = msg.get('Message-ID')
                        if from_ == "Google <no-reply@accounts.google.com>":
                            pass
                        else:
                            if msg.is_multipart():
                                for part in msg.walk():
                                    content_type = part.get_content_type()
                                    content_disposition = str(part.get("Content-Disposition"))
                                    try:
                                        body = part.get_payload(decode=True).decode()
                                    except:
                                        pass
                                    if content_type == "text/plain" and "attachment" not in content_disposition:
                                        spam = self.detect_spam(body)
                                        if spam:
                                            if str(i) in messagess:
                                                imap.store(str(i), '-FLAGS', '\\Seen')
                                            resp, data = imap.fetch(str(i), "(UID)")
                                            msg_uid = self.parse_uid(data[0].decode())
                                            result = imap.uid('STORE', msg_uid, '+X-GM-LABELS',
                                                              'Spam_Messages_CyberRely')
                                            if result[0] == "OK":
                                                mov, ax = imap.uid('STORE', msg_uid, '+FLAGS', '(\Deleted)')
                                                imap.expunge()
                                            print("The message is spam!!")
                                        else:
                                            # import re
                                            #
                                            # def Find(string):
                                            #     regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)" \
                                            #             r"(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()" \
                                            #             r"<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
                                            #     url = re.findall(regex, string)
                                            #     return [x[0] for x in url]
                                            #
                                            # string = Find(body)
                                            # for link in string:
                                            #     checker = PhishSafe(link)
                                            #     if checker.validate()[0] == " Website Status: The Site Is Safe!!":
                                            #         print("The messag is not spam!!")
                                            #     else:
                                            #         print(checker.validate()[0].split(": ")[1])
                                            if str(i) in messagess:
                                                imap.store(str(i), '-FLAGS', '\\Seen')
                                            print("The message is not spam")

                            else:
                                content_type = msg.get_content_type()
                                body = msg.get_payload(decode=True).decode()
                                if content_type == "text/plain":
                                    spam = self.detect_spam(body)
                                    if spam:
                                        if str(i) in messagess:
                                            imap.store(str(i), '-FLAGS', '\\Seen')
                                        resp, data = imap.fetch(str(i), "(UID)")
                                        msg_uid = self.parse_uid(data[0].decode())
                                        result = imap.uid('STORE', msg_uid, '+X-GM-LABELS', 'Spam_Messages_CyberRely')
                                        if result[0] == "OK":
                                            mov, ax = imap.uid('STORE', msg_uid, '+FLAGS', '(\Deleted)')
                                            imap.expunge()
                                        print("The message is spam!!")
                                    else:
                                        # import re
                                        #
                                        # def Find(string):
                                        #     regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)" \
                                        #             r"(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()" \
                                        #             r"<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
                                        #     url = re.findall(regex, string)
                                        #     return [x[0] for x in url]
                                        #
                                        # string = Find(body)
                                        # for link in string:
                                        #     checker = PhishSafe(link)
                                        #     if checker.validate()[0] == " Website Status: The Site Is Safe!!":
                                        #         print("The messag is not spam!!")
                                        #     else:
                                        #         print(checker.validate()[0].split(": ")[1])
                                        if str(i) in messagess:
                                            imap.store(str(i), '-FLAGS', '\\Seen')
                                        print("The message is not spam")

            imap.close()
            imap.logout()


from cryptography.fernet import Fernet
from pyenigma import enigma
from pyenigma import rotor
import random

global check


class CyberRelyApp(App):
    def build(self):
        return sm

    def check(self, text):
        checker = PhishSafe(text)
        if checker is not None:
            check = TraceThread(target=checker.validate)
            check.start()
            return
        else:
            sm.get_screen("PhishSafe").ids[
                'result'].text = " Website Status: There is a connection problem with the site."
            return

    def encrypt(self):
        import pathlib
        import PySimpleGUI as sg
        filename = filebrowser("")
        if filename:
            file = pathlib.Path(filename)
        else:
            file = ""
        if file != "":
            return str(file)
        else:
            return ""

    def encryptme(self, filename, output):
        a = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
             'V',
             'W',
             'X', 'Y', 'Z']
        b = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
             'V',
             'W',
             'X', 'Y', 'Z']
        c = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
             'V',
             'W',
             'X', 'Y', 'Z']
        for_us_a = random.choice(a)
        for_us_b = random.choice(b)
        for_us_c = random.choice(c)
        selected_a = random.choice(a)
        selected_b = random.choice(b)
        selected_c = random.choice(c)
        final_for_user = str(selected_a + selected_b + selected_c)
        key3 = Fernet.generate_key()
        user_key = key3.decode() + final_for_user
        our_engine = enigma.Enigma(rotor.ROTOR_Reflector_A, rotor.ROTOR_I,
                                   rotor.ROTOR_II, rotor.ROTOR_III, key="PQZ",
                                   plugs="AS BV CL DG FZ HU IM KN OX RW")
        code = our_engine.encipher(key3.decode() + final_for_user)
        code = code.encode()
        our_engine1 = enigma.Enigma(rotor.ROTOR_Reflector_A, rotor.ROTOR_I,
                                    rotor.ROTOR_II, rotor.ROTOR_III, key="PQZ",
                                    plugs="AS BV CL DG FZ HU IM KN OX RW")
        code1 = our_engine1.encipher(code.decode())
        key1 = code1
        key1 = list(key1)
        one_key = key1[-1] + key1[-2] + key1[-3]
        key1.pop(-1)
        key1.pop(-1)
        key1.pop(-1)
        keys = ''.join(map(str, key1))
        f = Fernet(keys.encode())
        try:
            with open(filename, "rb") as file:
                file_data = file.read()
            encrypted_data = f.encrypt(file_data)
            op = enigma.Enigma(rotor.ROTOR_Reflector_A, rotor.ROTOR_I,
                               rotor.ROTOR_II, rotor.ROTOR_III, key=str(one_key),
                               plugs="AV BS CG DL FU HZ IN KM OW RX")
            encrypted_contents = op.encipher(encrypted_data.decode())
            with open(output, "wb") as file:
                if "win" in sys.platform:
                    file.write(
                        code + "|".encode() + (
                            filename.split("\\")[-1]).encode() + "\n".encode() + encrypted_contents.encode())
                else:
                    file.write(
                        code + "|".encode() + (
                            filename.split("/")[-1]).encode() + "\n".encode() + encrypted_contents.encode())
            return user_key

        except FileNotFoundError:
            return "File not Found"

    def encrypt_run(self, file, out):
        return self.encryptme(file, out)

    def decryptme(self, filename, key):
        import os
        try:
            try:
                with open(filename, "rb") as file:
                    password = file.read().decode()
                    restore = password
            except FileNotFoundError:
                return "File Not Found"
            finally:
                password = password.split("\n")
                password1 = password[0].split("|")
                passwords = password1[0].encode()
                password.pop(0)
                for item in password:
                    with open(filename, "wb") as file:
                        file.write(item.encode())
                our_engine2 = enigma.Enigma(rotor.ROTOR_Reflector_A, rotor.ROTOR_I,
                                            rotor.ROTOR_II, rotor.ROTOR_III, key="PQZ",
                                            plugs="AS BV CL DG FZ HU IM KN OX RW")
                codez = our_engine2.encipher(passwords.decode())
                if key == codez:
                    key = codez
                    key = list(key)
                    one_key = key[-1] + key[-2] + key[-3]
                    key.pop(-1)
                    key.pop(-1)
                    key.pop(-1)
                    key = ''.join(map(str, key))
                    f = Fernet(key.encode())
                    with open(filename, "rb") as file:
                        encrypted_data = file.read()
                    op = enigma.Enigma(rotor.ROTOR_Reflector_A, rotor.ROTOR_I,
                                       rotor.ROTOR_II, rotor.ROTOR_III, key=str(one_key),
                                       plugs="AV BS CG DL FU HZ IN KM OW RX")
                    encrypted_contents = op.encipher(encrypted_data.decode())
                    decrypted_data = f.decrypt(encrypted_contents.encode())
                    desktop = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop')
                    try:
                        if "win" in sys.platform:
                            with open(desktop + "\\" + password1[-1], "wb+") as file:
                                file.write(decrypted_data)
                        else:
                            with open(desktop + "/" + password1[-1], "wb+") as file:
                                file.write(decrypted_data)
                    except FileNotFoundError:
                        try:
                            desktop = os.path.join(os.path.join(os.path.join(os.path.expanduser('~')), 'OneDrive'),
                                                   "Desktop")
                            if "win" in sys.platform:
                                with open(desktop + "\\" + password1[-1], "wb+") as file:
                                    file.write(decrypted_data)
                            else:
                                with open(desktop + "/" + password1[-1], "wb+") as file:
                                    file.write(decrypted_data)
                        except FileNotFoundError:
                            return "File Not Found"
                    with open(filename, "wb") as file:
                        file.write(restore.encode())
                    return "Done! Placed on the desktop."
                else:
                    with open(filename, "wb") as file:
                        file.write(restore.encode())
                    return "Wrong Password"
        except Exception:
            return "An error occured while Decrypting File"

    def decrypt_run(self, file, password):
        return self.decryptme(file, password)

    def scan_me(self, text):
        ds = VirusSafe.scan()
        tb = ds.scan()
        if tb:
            return text + tb[1] + tb[0] + "\n\n"
        else:
            return ""

    def exempt_file(self, text):
        import PySimpleGUI as sg
        file = filebrowser("")
        if file != "()":
            if "win" in sys.platform:
                we = open("Application_Externals\\driver", "a")
            else:
                we = open("Application_Externals/driver", "a")
            we.write(file + "\n")
            we.close()
            return text + f"Generated exempt certificate for {file}" + "\n\n"
        else:
            return "Cancelled Operation"

    def en(self, file):
        file = file.split(".")
        return file[0] + ".cpg"

    def de(self, file):
        if file.endswith(".cpg"):
            with open(file, "rb") as file1:
                password = file1.read().decode()
            password = password.split("\n")
            password1 = password[0].split("|")
            return password1[-1]
        return ""

    def files(self):
        dfr = extra_resources()
        full_file_paths = dfr.get_filepaths(file_to_quarantine)
        tmp = []
        for i in full_file_paths:
            if i.endswith("~`Quarantine`~.txt"):
                pass
            else:
                tmp.append(i)
        return '\n'.join(map(str, tmp))

    def decrypt(self, filename, key):
        with open(filename, "rb") as file:
            password = file.read().decode()
        password = password.split("\n")
        password1 = password[0].split("|")
        passwords = password1[0].encode()
        password.pop(0)
        for item in password:
            with open(filename, "wb") as file:
                file.write(item.encode())
        our_engine2 = enigma.Enigma(rotor.ROTOR_Reflector_A, rotor.ROTOR_I,
                                    rotor.ROTOR_II, rotor.ROTOR_III, key="PQZ",
                                    plugs="AS BV CL DG FZ HU IM KN OX RW")
        codez = our_engine2.encipher(passwords.decode())
        if key == codez:
            key = key
            key = list(key)
            one_key = key[-1] + key[-2] + key[-3]
            key.pop(-1)
            key.pop(-1)
            key.pop(-1)
            key = ''.join(map(str, key))
            f = Fernet(key.encode())
            with open(filename, "rb") as file:
                encrypted_data = file.read()
            op = enigma.Enigma(rotor.ROTOR_Reflector_A, rotor.ROTOR_I,
                               rotor.ROTOR_II, rotor.ROTOR_III, key=str(one_key),
                               plugs="AV BS CG DL FU HZ IN KM OW RX")
            encrypted_contents = op.encipher(encrypted_data.decode())
            decrypted_data = f.decrypt(encrypted_contents.encode())
            import os
            wed = os.getcwd()
            if "win" in sys.platform:
                wed = wed.split("\\")
                wed.pop(-1)
                wed = '\\'.join(map(str, wed))
                file = open(wed + "\\" + password1[-1], "wb")
                file.write(decrypted_data)
                file.close()
                return wed + "\\" + password1[-1]
            else:
                wed = wed.split("/")
                wed.pop(-1)
                wed = '/'.join(map(str, wed))
                file = open(wed + "/" + password1[-1], "wb")
                file.write(decrypted_data)
                file.close()
                return wed + "/" + password1[-1]
        else:
            return "Wrong Password"

    def clear(self):
        return ""

    def delete(self):
        import pyautogui, os
        text = pyautogui.password(text="Enter file name", title="Delete File", mask="")
        if text:
            try:
                if "win" in sys.platform:
                    user_os = "\\"
                else:
                    user_os = "/"
                if user_os in text:
                    os.remove(text)
                else:
                    os.remove(file_to_quarantine + text)
            except FileNotFoundError:
                pass
        dfr = extra_resources()
        full_file_paths = dfr.get_filepaths(file_to_quarantine)
        return '\n'.join(map(str, full_file_paths))

    def delete_all(self):
        import os
        dfr = extra_resources()
        full_file_paths = dfr.get_filepaths(file_to_quarantine)
        for file in full_file_paths:
            os.remove(file)
        dfr = extra_resources()
        full_file_paths = dfr.get_filepaths(file_to_quarantine)
        return '\n'.join(map(str, full_file_paths))

    def restore(self):
        import pyautogui, os
        text = pyautogui.password(text="Enter file name", title="Restore File", mask="")
        we = VirusSafe.Quarentine()
        if text:
            try:
                if "win" in sys.platform:
                    user_os = "\\"
                else:
                    user_os = "/"
                if user_os in text:
                    we.decode_base64(text)
                else:
                    we.decode_base64(file_to_quarantine + text)
            except FileNotFoundError:
                pass
        dfr = extra_resources()
        full_file_paths = dfr.get_filepaths(file_to_quarantine)
        return '\n'.join(map(str, full_file_paths))

    def restore_all(self):
        import os
        dfr = extra_resources()
        full_file_paths = dfr.get_filepaths(file_to_quarantine)
        wea = VirusSafe.Quarentine()
        for file in full_file_paths:
            wea.decode_base64(file)
        dfr = extra_resources()
        full_file_paths = dfr.get_filepaths(file_to_quarantine)
        return '\n'.join(map(str, full_file_paths))

    def add_file(self):
        import pathlib
        import PySimpleGUI as sg
        filename = filebrowser("")
        wea = VirusSafe.Quarentine()
        if filename:
            file = str(pathlib.Path(filename))
        else:
            file = ""
        if file != "":
            wea.encode_base64(file, file_to_quarantine)
        else:
            pass
        dfr = extra_resources()
        full_file_paths = dfr.get_filepaths(file_to_quarantine)
        return '\n'.join(map(str, full_file_paths))

    def encrypt_cer(self, filename, output):
        import random
        a = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
             'U',
             'V',
             'W',
             'X', 'Y', 'Z']
        b = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
             'U',
             'V',
             'W',
             'X', 'Y', 'Z']
        c = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
             'U',
             'V',
             'W',
             'X', 'Y', 'Z']
        for_us_a = random.choice(a)
        for_us_b = random.choice(b)
        for_us_c = random.choice(c)
        selected_a = random.choice(a)
        selected_b = random.choice(b)
        selected_c = random.choice(c)
        final_for_user = str(selected_a + selected_b + selected_c)
        key3 = b"XvTg0cCTpYBiNraJto3F2n8aX7PHlAVtVpKI5Uj1RfQ=LYY"
        user_key = key3.decode()
        our_engine = enigma.Enigma(rotor.ROTOR_Reflector_A, rotor.ROTOR_I,
                                   rotor.ROTOR_II, rotor.ROTOR_III, key="PQZ",
                                   plugs="AS BV CL DG FZ HU IM KN OX RW")
        code = our_engine.encipher(key3.decode())
        code = code.encode()
        our_engine1 = enigma.Enigma(rotor.ROTOR_Reflector_A, rotor.ROTOR_I,
                                    rotor.ROTOR_II, rotor.ROTOR_III, key="PQZ",
                                    plugs="AS BV CL DG FZ HU IM KN OX RW")
        code1 = our_engine1.encipher(code.decode())
        key1 = code1
        key1 = list(key1)
        one_key = key1[-1] + key1[-2] + key1[-3]
        key1.pop(-1)
        key1.pop(-1)
        key1.pop(-1)
        keys = ''.join(map(str, key1))
        f = Fernet(keys.encode())
        with open(filename, "rb") as file:
            file_data = file.read()
        encrypted_data = f.encrypt(file_data)
        op = enigma.Enigma(rotor.ROTOR_Reflector_A, rotor.ROTOR_I,
                           rotor.ROTOR_II, rotor.ROTOR_III, key=str(one_key),
                           plugs="AV BS CG DL FU HZ IN KM OW RX")
        encrypted_contents = op.encipher(encrypted_data.decode())
        with open(output, "wb") as file:
            if "win" in sys.platform:
                file.write(
                    code + "|".encode() + (
                            (filename.split("\\")[-1]) + ".abc").encode() + "\n".encode() + encrypted_contents.encode())
            else:
                file.write(
                    code + "|".encode() + (
                            (filename.split("/")[-1]) + ".abc").encode() + "\n".encode() + encrypted_contents.encode())

    def mail(self, email, password):
        global t
        wed = MailSafe(email, password)
        t = TraceThread(target=wed.mailsafe)
        t.start()

    def texts(self):
        if "win" in sys.platform:
            return str((open("MailSafe_drivers\\b5cc1518914fa539dc4fb597e97206d2.dll", "rb").read()).decode())
        else:
            return str((open("MailSafe_drivers/b5cc1518914fa539dc4fb597e97206d2.dll", "rb").read()).decode())

    def certificate(self, text):
        from datetime import date
        from datetime import timedelta
        ws = self.encrypt()
        name = os.path.realpath(ws)
        name = name.split(".")
        name = name[0]
        er = extra_resources()
        md5 = er.create_md5(b"e4c1a4f9-b1c0-4772-a114-2c68af5046d4")
        today = date.today()
        self.texts = f"""# Certificate of Authenticity #
    class Certificate:
        def __init__(self):
            self.date_packed = {today}
            self.date_expiry = {today + timedelta(days=250)}
            self.md5 = {md5.decode()}

        def statement_of_authenticity(self):
            pass
    #e4c1a4f9-b1c0-4772-a114-2c68af5046d4#"""
        we = open(name + ".cyber-cer", "w")
        we.write(self.texts)
        we.close()
        self.encrypt_cer(name + ".cyber-cer", f"{name}.cyber-cer")
        return text + f"Security certificate generated for: {ws}" + "\n\n"

    def check_cer(self, text):
        import pathlib
        import PySimpleGUI as sg
        filename = filebrowser("CyberRely Certificates (*.cyber-cer)|*.cyber-cer")
        if filename:
            file = str(pathlib.Path(filename))
        else:
            return text
        file_de = self.decrypt(file, "XvTg0cCTpYBiNraJto3F2n8aX7PHlAVtVpKI5Uj1RfQ=LYY")
        wed = open(file_de, "r")
        content = wed.read()
        wed.close()
        import os
        from datetime import date
        from datetime import timedelta
        name = os.path.realpath(file)
        name = name.split(".")
        name = name[0]
        er = extra_resources()
        md5 = er.create_md5(b"e4c1a4f9-b1c0-4772-a114-2c68af5046d4")
        today = date.today()
        self.texts = f"""# Certificate of Authenticity #
        class Certificate:
            def __init__(self):
                self.date_packed = {today}
                self.date_expiry = {today + timedelta(days=250)}
                self.md5 = {md5.decode()}

            def statement_of_authenticity(self):
                pass
        #e4c1a4f9-b1c0-4772-a114-2c68af5046d4#"""

        we = open(name + ".cyber-cer", "w")
        we.write(self.texts)
        we.close()
        self.encrypt_cer(name + ".cyber-cer", f"{name}.cyber-cer")
        import os
        os.remove(file_de)
        content = content.split("\n")

        from datetime import datetime
        if datetime.strptime(content[3].split("= ")[1], '%Y-%m-%d') >= datetime.strptime(str(date.today()),
                                                                                         '%Y-%m-%d') <= datetime.strptime(
            content[4].split("= ")[1], '%Y-%m-%d'):
            er = extra_resources()
            if (er.create_md5(content[9].split("#")[1].encode())).decode() == (content[5].split("= ")[1]):
                return text + f"The security certificate is valid." + "\n\n"
            else:
                return text + f"The security certificate is not valid." + "\n\n"
        else:
            return text + f"The security certificate is not valid." + "\n\n"

    def kill(self):
        try:
            global t
            t.killed = True
        except NameError:
            pass


def scan_system():
    while 1:
        ads = extra_resources()
        if "win" in sys.platform:
            we = ads.get_filepaths("C:\\")
        else:
            we = ads.get_filepaths("/home")
        for file in we:
            try:
                print(file)
                weds = VirusSafe.scan()
                weds.scan1(file)
            except PermissionError:
                pass


def scan_processes():
    while 1:
        import subprocess
        if "win" in sys.platform:
            cmd = 'powershell "gps | where {$_.MainWindowTitle } | select Description,Id,Path'
        else:
            cmd = "ps -a"
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        for line in proc.stdout:
            if not line.decode()[0].isspace():
                print(line.decode().rstrip())
            else:
                print(line.decode().rstrip())


if __name__ == '__main__':
    if "win" in sys.platform:
        multiprocessing.freeze_support()
    import os

    if "win" in sys.platform:
        os_user = "\\"
    else:
        os_user = "/"
    if not os.path.isfile(f"EULA"):
        import PySimpleGUI as sg

        text_for_something = open("LICENSE", "r").read()
        sg.change_look_and_feel("black")
        is_use_disable = True
        layout = [
            [sg.Text('Terms & Conditions', font=('Consolas', 15))],
            [sg.Text("These are the Terms and Conditions for using the CyberRelyⒸ app. \nPlease Accept to continue.",
                     font=('Consolas', 9))],
            [sg.Multiline(size=(80, 20), key='_OUT_', font=('Consolas', 9),
                          default_text=text_for_something,
                          disabled=True)],
            [sg.Button('Accept', font=('Consolas', 9))]
        ]
        window = sg.Window('Terms & Conditions', layout, no_titlebar=True, grab_anywhere=True)
        while True:
            event, values = window.Read()
            if event in ["Accept", ]:
                break
        window.close()
        we = open(f"EULA", "w")
        we.write(
            "01010111 01101000 01111001 00100000 01100001 01110010 01100101 00100000 01111001 01101111 01110101 00100000 01110100 01110010 01111001 01101001 01101110 01100111 00100000 01110100 01101111 00100000 01110010 01100101 01100001 01100100 00100000 01110100 01101000 01101001 01110011")
        we.close()
    dsa = check_resources()
    a = dsa.start()
    if not a:
        import PySimpleGUI as sg

        sg.Popup("You have deleted/moved/changed a *.dll file or the logo file. This app will not run. "
                 "Please either move the file back, redo edits or download a new copy.")
        import time

        time.sleep(3)
        import sys

        t.killed = True
        sys.exit(0)

    # f = TraceThread(target=scan_processes)
    # f.start()
    # zsdfe = TraceThread(target=scan_system)
    # zsdfe.start()
    CyberRelyApp().run()
    try:
        t.killed = True
    except NameError:
        pass
    try:
        check.killed = True
    except NameError:
        pass
    # f.killed = True
    # zsdfe.killed = True

# ⒸopyRight: CyberRely All rights reserved for the Creators of Cyber-X co. #
# pip install kivy concurrent.futures idna PySimpleGUI wxpython PyAutoGUI bs4 xmltodict tldextract pyenigma cryptography openssl #
# Build for Windows-family type operating systems: {"Windows-family": ['_Win32', '_Win64'], "Linux-family": ['_i386', '_x86_64'], "Mac-family": ['_macros']} #
# ʕ-■-■ʔ ( ﾉ ﾟｰﾟ)ﾉ 🎶 ℂ𝕪𝕓𝕖𝕣-𝕏 #
