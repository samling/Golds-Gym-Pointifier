from __future__ import print_function
from apiclient.discovery import build as apiclient_build
from bs4 import BeautifulSoup
from httplib2 import Http
from oauth2client import file as oauth_file, client, tools
from selenium import webdriver

import base64
import http.client as http_client
import json
import logging
import requests
import urllib
import urllib3

# If modifying these scopes, delete the file token.json.
CHECKIN_URL = 'https://goldsgymsocal.perkville.com/earning/#checkin'
DRIVER_TYPE = 'chromedriver'
LOGIN_URL = 'https://goldsgymsocal.perkville.com/login/'
TWEET_URL = None
GOLDS_FROM = 'rewards@perkville.com'
GOLDS_SUBJECT = 'You earned'
SCOPE = 'https://www.googleapis.com/auth/gmail.modify'

#http_client.HTTPConnection.debuglevel = 1
#logging.basicConfig()
#logging.getLogger().setLevel(logging.DEBUG)
#requests_log = logging.getLogger("requests.packages.urllib3")
#requests_log.setLevel(logging.DEBUG)
#requests_log.propagate = True

class GMailAccount:
    def __init__(self, scope, golds_from, golds_subject):
        self.scope          = scope
        self.golds_from     = golds_from
        self.golds_subject  = golds_subject
        self.tweet_url      = None
        self.api_service    = None

    def __enter__(self):
        return self.__login()

    def __exit__(self, *args):
        pass

    def __login(self):
        # Authenticate to GMail using OAuth; store the token for reuse
        store = oauth_file.Storage('token.json')
        creds = store.get()
        if not creds or creds.invalid:
            flow = client.flow_from_clientsecrets('credentials.json', self.scope)
            creds = tools.run_flow(flow, store)
        self.api_service = apiclient_build('gmail', 'v1', http=creds.authorize(Http()))
        print(self.api_service)
        return self

    def query(self):
        # Call the Gmail API
        query = "newer_than:2d" # Only looking for emails within the last 24 hours
        results = self.api_service.users().messages().list(userId='me',labelIds=['INBOX', 'UNREAD'],q=query).execute()
        messages = results.get('messages', [])
        if not messages:
            print('No messages found.')
        else:
            for message in messages:
                content = self.api_service.users().messages().get(userId='me', id=message['id']).execute()
                payload = content['payload']
                headers = payload['headers']
                parts = payload['parts']
                for part in parts:
                    body = base64.urlsafe_b64decode(part['body']['data']).decode("utf-8")
                    soup = BeautifulSoup(body, 'html.parser')
                    links = soup.find_all('a')
                    for index, link in enumerate(links):
                        if index == 3:
                            # Fourth link in email is the 'tweet' link
                            self.tweet_url = link.get('href')
                for header in headers:
                    if header['name'] == 'From':
                        sender = header['value']
                    if header['name'] == 'Subject':
                        subject = header['value']
                if self.golds_from in sender and self.golds_subject in subject:
                    found = True
                    print("Sender: " + sender)
                    print("Subject: " + subject)
                    print("Referral URL: " + self.tweet_url)
                    #if token == None or sessionid == None: # TODO: check if past expiration date
                        #token, token_expires, sessionid, sessionid_expires = login(TWEET_URL, session)
                        #login(self.tweet_url, session, driver)
                        #print("Session: ")
                        #print(session.cookies.get_dict())
                        #tweet(self.tweet_url, session)
                    #else:
                        #tweet(TWEET_URL, sessionid, token)
                    #service.users().messages().modify(userId='me',id=message['id'],body={'removeLabelIds':['UNREAD']}).execute()
        return self.tweet_url

class PerkAccount:
    def __init__(self, checkin_url, login_url, tweet_url, driver_type):
        self.session        = requests.Session()
        self.checkin_url    = checkin_url
        self.login_url      = login_url
        self.tweet_url      = tweet_url
        self.driver_type    = driver_type
        self.driver         = webdriver.Chrome(self.driver_type)

    def __enter__(self):
        return self.__login()

    def __exit__(self, *args):
        self.driver.quit()

    def __login(self):
        # Disable HTTPS request warnings
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Grab the login page and get the CSRF middleware token from the login form
        login_html = requests.get(self.login_url, verify=False)
        soup = BeautifulSoup(login_html.content, 'html.parser')
        csrfToken = soup.find('input', {"name":"csrfmiddlewaretoken"}).get('value')
        print("CSRF Token: " + csrfToken)

        # Load our login credentials and submit the form data to the login URL
        with open('login.json') as f:
            creds = json.load(f)
        headers = {'Content-Type': 'text/html'}
        data = {
                'csrfmiddlewaretoken': csrfToken,
                'form_type': 'signin',
                'username': creds['username'],
                'password': creds['password'],
                'redirect_to': self.checkin_url
                }
        print("URL Params: " + urllib.parse.urlencode(data))
        #self.driver.get(self.login_url)
        #ss1 = self.driver.save_screenshot('login.png')
        r = self.session.post(self.login_url, json=data, headers=headers, allow_redirects=True)
        if r.ok:
            self.session.get(self.checkin_url)
            #self.driver.get(self.checkin_url)
            #ss1 = self.driver.save_screenshot('post_login.png')
            self.session.cookies.set('__hssc', '128999571.1.1533395930460')
            self.session.cookies.set('__hssrc', '1')
            self.session.cookies.set('__hstc', 'bc436e6e7d327a2d3b82730a341a3f10.1533395930460.1533395930460.1533395930460.1')
            self.session.cookies.set('_ga', 'GA1.2.937205870.1533395930')
            self.session.cookies.set('_gat', '1')
            self.session.cookies.set('_gid', 'GA1.2.1580480415.1533395930')
            self.session.cookies.set('hubspotutk', 'bc436e6e7d327a2d3b82730a341a3f10')
            self.session.cookies.set('intellimizeEUID', 'b41fc37723.1533395929')
            self.session.cookies.set('csrftoken', csrfToken)
            response = r.headers['Set-Cookie'].split(';')
            print("Response Headers: ")
            print(response)
            #token = response[0].split('=')[1]
            #token_expires = response[1].split('=')[1]
            #sessionid = response[4].split('=')[1]
            #sessionid_expires = response[6].split('=')[1]
            #print("Token: " + token)
            #print("Token Expires: " + token_expires)
            #print("SessionID: " + sessionid)
            #print("SessionID Expires: " + sessionid_expires)
        else:
            r.raise_for_status()
        #return token, token_expires, sessionid, sessionid_expires
        return self

    def tweet(self):
        # TODO: Get the page contents using the info grabbed above
        #print("Tweet URL: " + self.tweet_url)
        print("Testing:", self.checkin_url)
        #session.get(url)
        #print(session.get(url).text)

def main():
    """
    Get unread messages, look for unread emails from Gold's less than 24h old that say "You earned X points".
    If found, mark the message as read and tweet at Gold's for bonus points.
    """

    found = False
    sessionid = None
    sessionid_expires = None
    token = None
    token_expires = None
    TWEET_URL = None

    with GMailAccount(SCOPE, GOLDS_FROM, GOLDS_SUBJECT) as m:
        TWEET_URL = m.query()
        print(TWEET_URL)
    with PerkAccount(CHECKIN_URL, LOGIN_URL, TWEET_URL, DRIVER_TYPE) as p:
        p.tweet()


if __name__ == '__main__':
    main()
