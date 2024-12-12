from flask import Flask,request
import sqlite3
from threading import Semaphore
import logging

# setup sqlite database
authdb = sqlite3.connect("authUsers.db",check_same_thread=False)
cipherdb = sqlite3.connect("usedCiphers.db",check_same_thread=False)
authcursor = authdb.cursor()
ciphercursor = cipherdb.cursor()
authkey = Semaphore()
cipherkey = Semaphore()

initCmdAuth = """ CREATE TABLE AUTHCHECK (
EMAILHASH VARCHAR(255) NOT NULL
);"""
initCmdCipher = """ CREATE TABLE CIPHERS (
CIPHER VARCHAR(255) NOT NULL
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

authdb.commit()
cipherdb.commit()

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