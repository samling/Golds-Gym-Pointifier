from __future__ import print_function
from apiclient.discovery import build
from bs4 import BeautifulSoup
from httplib2 import Http
from oauth2client import file as oauth_file, client, tools
import base64
import requests
import urllib3

# If modifying these scopes, delete the file token.json.
SCOPES = 'https://www.googleapis.com/auth/gmail.modify'
GOLDS_FROM = 'rewards@perkville.com'
GOLDS_SUBJECT = 'You earned'

def main():
    """
    Get unread messages, look for unread emails from Gold's less than 24h old that say "You earned X points".
    If found, mark the message as read and tweet at Gold's for bonus points.
    """
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
        found = False
        tweetURL = None
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
                print(sender)
                print(subject)
                print(tweetURL)
                login(tweetURL)
                found = True
                #service.users().messages().modify(userId='me',id=message['id'],body={'removeLabelIds':['UNREAD']}).execute()
        print(found)

def login(url):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    login_html = requests.get(url, verify=False)
    soup = BeautifulSoup(login_html.content, 'html.parser')
    csrfToken = soup.find('input', {"name":"csrfmiddlewaretoken"}).get('value')
    print(csrfToken)

if __name__ == '__main__':
    main()
