from flask import Flask,request
import sqlite3
from threading import Semaphore
import logging
import base64
from email.message import EmailMessage
from email.mime.text import MIMEText
import google.auth
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


import base64
from email.message import EmailMessage
import os.path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
SCOPES = ['https://www.googleapis.com/auth/gmail.send']
def gmail_send_message(emailId,subject="Test",body="default"):
    """Create and send an email message
    Print the returned  message id
    Returns: Message object, including message id

    Load pre-authorized user credentials from the environment.
    TODO(developer) - See https://developers.google.com/identity
    for guides on implementing OAuth2 for the application.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'creds.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentifor als the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    try:
        service = build('gmail', 'v1', credentials=creds)
        message = EmailMessage()

        # message.set_content('''''')
        # message = MIMEText(msg_text,"html")

        message['To'] = emailId
        # message['To'] = 'vibhavgopal2004@gmail.com'
        # message['From'] = 'SAC-Alumni Affairs'
        message['Subject'] = subject
        # message['Reply-To'] = returnpath
        # message.add_header('Content-Type', 'text/html')
        message.set_payload(body)
        # encoded message
        encoded_message = base64.urlsafe_b64encode(message.as_bytes()) \
            .decode()

        create_message = {
            'raw': encoded_message
        }
        # pylint: disable=E1101
        send_message = (service.users().messages().send
                        (userId="me", body=create_message).execute())
        print(F'Message Id: {send_message["id"]}')
    except HttpError as error:
        print(F'An error occurred: {error}')
        send_message = None
    return send_message
# setup sqlite database
authdb = sqlite3.connect("authUsers.db",check_same_thread=False)
cipherdb = sqlite3.connect("usedCiphers.db",check_same_thread=False)
verifydb = sqlite3.connect("emailverif.db",check_same_thread=False)
authcursor = authdb.cursor()
ciphercursor = cipherdb.cursor()
verifycursor = verifydb.cursor()
authkey = Semaphore()
cipherkey = Semaphore()
verifyKey = Semaphore()

initCmdAuth = """ CREATE TABLE AUTHCHECK (
EMAILHASH VARCHAR(255) NOT NULL
);"""
initCmdCipher = """ CREATE TABLE CIPHERS (
CIPHER VARCHAR(255) NOT NULL
);"""
initCmdVerif = """ CREATE TABLE VERIF (
EMAIL VARCHAR(255) NOT NULL,
SECRET VARCHAR(255) NOT NULL
);"""
try:
    authcursor.execute(initCmdAuth)
    authdb.commit()
except:
    pass
finally:
    logging.info("Auth DB setup")
try:
    ciphercursor.execute(initCmdCipher)
    cipherdb.commit()
except:
    pass
finally:
    logging.info("Cipher DB setup")
try:
    verifycursor.execute(initCmdVerif)
    verifydb.commit()
except:
    pass
finally:
    logging.info("Verify DB setup")

authdb.commit()
cipherdb.commit()
verifydb.commit()
# authdb.close()
# cipherdb.close()
app = Flask(__name__)

@app.route("/")
def hello_world():
    return "<p>ACCESS DENIED</p>"

@app.route("/checkuser",methods = ["POST"])
def checkuser():
    hashed = request.form['hashed']
    hashed = str(hashed)
    authkey.acquire()
    authcursor.execute(f"SELECT EMAILHASH FROM AUTHCHECK WHERE EMAILHASH = '{hashed}'")
    results = authcursor.fetchall()
    if len(results) == 0:
        authcursor.execute(f"INSERT INTO AUTHCHECK VALUES ('{hashed}')")
        authdb.commit()
        authkey.release()
        return "OK"
    else:
        authkey.release()
        return "NOTOK"
    
@app.route("/checkcipher",methods = ["POST"])
def checkcipher():
    cipher = request.form['cipher']
    cipher = str(cipher)
    cipherkey.acquire()
    ciphercursor.execute(f"SELECT CIPHER FROM CIPHERS WHERE CIPHER = '{cipher}'")
    results = ciphercursor.fetchall()
    if len(results) == 0:
        ciphercursor.execute(f"INSERT INTO CIPHERS VALUES ('{cipher}')")
        cipherdb.commit()
        cipherkey.release()
        return "OK"
    else:
        cipherkey.release()
        return "NOTOK"
    
@app.route("/verifyemail",methods = ["POST"])
def verify_email():
    email = str(request.form['email'])
    from allowed_emails import allowed
    if email in allowed:
        subj = "Authentication for Alumni Association voting"
        from random import randint
        otp = randint(100000,999999)
        body = f"Greetings,\nFind your OTP here: {otp}\nEnter this into the application to complete the verification\nRegards,\nAlumni Affairs"
        gmail_send_message(email,subj,body)
        verifyKey.acquire()
        verifycursor.execute(f"SELECT EMAIL FROM VERIF WHERE EMAIL = '{email}'")
        results = verifycursor.fetchall()
        if len(results) == 0:
            verifycursor.execute(f"INSERT INTO VERIF VALUES ('{email}','{str(otp)}')")
            verifydb.commit()
            verifyKey.release()
            
        else:
            verifycursor.execute(f"UPDATE VERIF SET SECRET = '{str(otp)}' WHERE EMAIL = '{email}'")
            verifydb.commit()
            verifyKey.release()
        return "OK"
    else:
        return "NOTOK"

@app.route("/checksecret",methods=["POST"])
def check_secret():
    email = str(request.form['email'])
    secret = str(request.form['secret'])
    from allowed_emails import allowed
    if email in allowed:
        verifyKey.acquire()
        verifycursor.execute(f"SELECT EMAIL FROM VERIF WHERE EMAIL = '{email}'")
        results = verifycursor.fetchall()
        if len(results) == 0:
            verifyKey.release()
            return "NOMAIL"
        elif len(results) == 1:
            print("Received",secret)
            verifycursor.execute(f"SELECT SECRET FROM VERIF WHERE EMAIL = '{email}'")
            results = verifycursor.fetchall()
            verifyKey.release()
            print("Expected",results[0][0])
            if results[0][0] == secret:
                return "OK"
            else:
                return "WRONGSECRET"
        else:
            verifyKey.release()
            return "UNKNOWN"
    else:
        return "NOTALLOWED"
