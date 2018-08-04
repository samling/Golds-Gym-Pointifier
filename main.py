from __future__ import print_function
from apiclient.discovery import build
from bs4 import BeautifulSoup
from httplib2 import Http
from oauth2client import file as oauth_file, client, tools

import base64
import json
import requests
import urllib
import urllib3

# If modifying these scopes, delete the file token.json.
CHECKIN_URL = 'https://goldsgymsocal.perkville.com/earning/#checkin'
GOLDS_FROM = 'rewards@perkville.com'
GOLDS_SUBJECT = 'You earned'
SCOPES = 'https://www.googleapis.com/auth/gmail.modify'

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
    tweetURL = None

    session = requests.Session()

    # Authenticate to GMail using OAuth; store the token for reuse
    store = oauth_file.Storage('token.json')
    creds = store.get()
    if not creds or creds.invalid:
        flow = client.flow_from_clientsecrets('credentials.json', SCOPES)
        creds = tools.run_flow(flow, store)
    service = build('gmail', 'v1', http=creds.authorize(Http()))

    # Call the Gmail API
    query = "newer_than:2d" # Only looking for emails within the last 24 hours
    results = service.users().messages().list(userId='me',labelIds=['INBOX', 'UNREAD'],q=query).execute()
    messages = results.get('messages', [])
    if not messages:
        print('No messages found.')
    else:
        for message in messages:
            content = service.users().messages().get(userId='me', id=message['id']).execute()
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
                        tweetURL = link.get('href')
            for header in headers:
                if header['name'] == 'From':
                    sender = header['value']
                if header['name'] == 'Subject':
                    subject = header['value']
            if GOLDS_FROM in sender and GOLDS_SUBJECT in subject:
                found = True
                print("Sender: " + sender)
                print("Subject: " + subject)
                print("Referral URL: " + tweetURL)
                if token == None or sessionid == None: # TODO: check if past expiration date
                    #token, token_expires, sessionid, sessionid_expires = login(tweetURL, session)
                    login(tweetURL, session)
                    print("Session: ")
                    print(session.cookies.get_dict())
                    tweet(CHECKIN_URL, session)
                #else:
                    #tweet(tweetURL, sessionid, token)
                #service.users().messages().modify(userId='me',id=message['id'],body={'removeLabelIds':['UNREAD']}).execute()

def login(url, session):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    login_html = requests.get(url, verify=False)
    soup = BeautifulSoup(login_html.content, 'html.parser')
    csrfToken = soup.find('input', {"name":"csrfmiddlewaretoken"}).get('value')
    print("CSRF Token: " + csrfToken)

    with open('login.json') as f:
        creds = json.load(f)
    headers = {'Content-Type': 'text/html'}
    data = {
            'csrfmiddlewaretoken': csrfToken,
            'form_type': 'signin',
            'username': creds['username'],
            'password': creds['password'],
            'redirect_to': 'https://goldsgymsocal.perkville.com/earning/#checkin'
            }
    print("URL Params: " + urllib.parse.urlencode(data))
    r = session.post(url, json=data, headers=headers)
    if r.ok:
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

def tweet(url, session):
    # TODO: Get the page contents using the info grabbed above
    print(session.get(url).text)

if __name__ == '__main__':
    main()
