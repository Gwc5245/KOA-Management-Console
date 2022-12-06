import configparser
import hashlib
import logging
import os
import re
import shutil
from threading import Thread

import PySimpleGUI as sgd

import bcrypt
import pymongo as pymongo
import pymongo_auth_aws as g
import us as us
import wtforms
from wtforms import form
from flask import Flask, render_template, request, flash, url_for, redirect, session
from flask_pymongo import PyMongo
from pymongo.server_api import ServerApi
from remi.server import StandaloneServer, Server

app = Flask(__name__)
app.secret_key = "super secret key"
configFile = ()

cfg = configparser.ConfigParser()
path = os.path.abspath(__file__)
sgd.theme("reddit")
port = 25566
# MongoDB connection
s = g
appWindowMain = ()
client = pymongo.MongoClient(
    "mongodb+srv://<AWS access key>:<AWS secret "
    "key>@cluster0.re3ie7p.mongodb.net/?authSource=%24external&authMechanism=MONGODB-AWS&retryWrites=true&w=majority",
    server_api=ServerApi('1'))


# print("Collections: ", db.list_collection_names())
# print("MongoDB info: ", client.server_info())
@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('Login_UI.html')


def run():
    app.run(debug=True, port=port, host="0.0.0.0")


from pathlib import Path

ROOT_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__)))
# Create and configure logger

logging.basicConfig(filename=os.path.join(ROOT_DIR, 'static', 'ConsoleApplication.txt'),
                    format='%(asctime)s %(message)s',
                    filemode='w')

# Creating an object
logger = logging.getLogger()

# Setting the threshold of logger to DEBUG
logger.setLevel(logging.DEBUG)


def genConfigFile(db_url, in_port, m5_aws_access, m5_aws_secret):
    print("-genConfigFile-")
    try:

        cfg.add_section('MongoDB Configuration')
        db_url = db_url.replace('%', '%%')
        cfg.add_section('WebUI Configuration')
        port = (int(in_port))
        cfg.add_section('M5Stack Configuration')
        # client = pymongo.MongoClient(db_url, server_api=ServerApi('1'))
    except Exception as e:
        print("There was an issue generating configuration file. Message:")
        print(e)
        logger.exception("Configuration file generation error. " + str(e))

    cfg.set('MongoDB Configuration', 'client_connection', db_url)
    cfg.set('WebUI Configuration', 'web_ui_port', str(port))
    cfg.set('M5Stack Configuration', 'm5_aws_access', m5_aws_access)
    cfg.set('M5Stack Configuration', 'm5_aws_secret', m5_aws_secret)
    with open('KOAConsole.ini', 'w') as configfile:
        print(cfg.write(configfile))
        logger.info("Wrote configuration to KOAConsole.ini")


def openConfigurationFileSelection():
    print("-openConfigurationFileSelection-")
    logger.info("Opening configuration file selection window.")
    file_list_column = [
        [sgd.Text("Configuration File"),
         sgd.In(size=(25, 1), enable_events=True, key="-FOLDER-"),
         sgd.FileBrowse(), ],

    ]

    layout = [
        [sgd.Text("A valid configuration file was not detected. Please select a configuration file.",
                  key='validation')],
        [sgd.Column(file_list_column)],
        # [sgd.Text('Username', size=(15, 1)), sgd.InputText('', key='Username')],
        [sgd.Button("Save", key='SaveButton')],
        [sgd.Button("Discard")]
    ]
    # window = sg.Window(title="KOA Management Console Login", layout=layout2, margins=(500, 500)).read()

    window = sgd.Window(title="KOA Management Console Configuration", layout=layout)
    while True:
        event, values = window.read()
        if event == "Exit" or event == sgd.WIN_CLOSED:
            break
        # Folder name was filled in, make a list of files in the folder
        if event == "-FOLDER-":
            folder = values["-FOLDER-"]
            try:
                # Get list of files in folder
                # file_list = os.listdir(folder)
                configFile = values["-FOLDER-"]
                # configFile = configFile.replace('/', "")
                # configFile = f'"{configFile}"'
                shutil.copyfile(configFile, "KOAConsole.ini")
            except Exception as e:
                print("Error occured with the selected ini file.")
                print(e)

        if event == "SaveButton":
            cfg.read('KOAConsole.ini')
            configCheck = checkConfig()

            if configCheck:
                config = parseConfiguration()
                logger.critical("New configuration saved and will be used by the program.")
                window.close()
            elif not configCheck:
                window['validation'].update(
                    value='Invalid configuration detected. \nPlease make sure all necessary fields are entered.', )
                logger.error("Invalid configuration detected. There may be a missing parameter or typo in "
                             "KOAConsole.ini.")


clientPass = ""


def checkConfig():
    try:
        print("-checkConfig-")
        # print("Configuration being checked:", config, type(config))
        print("Sections:", (cfg.sections()))
        portIn = (cfg.get('WebUI Configuration', "web_ui_port"))
        client_connection = (cfg.get("MongoDB Configuration", "client_connection"))
        print(client_connection, portIn)
        if not portIn:
            print("Port connection not found in configuration file.")
            logger.error("-checkConfig- There was an issue with the configuration file: no port found for web_ui_port.")
            return False
        if not client_connection:
            print("Client connection not found in configuration file.")
            logger.error(
                "-checkConfig- There was an issue with the configuration file: Mongo URI for ""client_connection"" not found or is invalid.")
            return False
    except Exception as e:
        print("There is an issue with the configuration file:", e)
        logger.exception(
            "-checkConfig- There is a critical issue with the configuration file. Response received: " + str(e))
        sgd.Popup(("There is an issue with the configuration file:\n" + "Error: " + str(
            e) + "\nPlease make sure all of the necessary settings are configured!"), keep_on_top=True)
        return False
    clientPass = client_connection
    print("Client connected:", client)
    return True


def startMongo(client_connection):
    print("-startMongo-")
    print("Client information:", client_connection)
    clientAppMain = pymongo.MongoClient(
        client_connection,
        server_api=ServerApi('1'))
    return clientAppMain


def configurator(fileLocated):
    print("-configurator-")

    if not fileLocated:
        print("Opening configuration file selection.")
        openConfigurationFileSelection()
    if fileLocated and checkConfig():
        print("Launching main application.")
        clientPass = cfg.get("MongoDB Configuration", "client_connection")
        startMongo(clientPass)


def startMongoNoCheck():
    print("-startMongoNoCheck-")
    logger.info("-startMongoNoCheck- Contacting MongoDB database.")
    cfg.read('KOAConsole.ini')
    try:
        clientPass = cfg.get("MongoDB Configuration", "client_connection")
    except Exception as e:
        logger.exception("-startMongoNoCheck- There was an issue connecting to MongoDB. " + str(e))
        parseConfiguration()

    return startMongo(clientPass)


def autoParse():
    parseConfiguration(False)


@app.route('/ConsoleApplication.txt', methods=["GET"])
def logTXT(address=None):
    return app.send_static_file('ConsoleApplication.txt')


@app.route('/static/KOAWeather.gif', methods=["GET"])
def logoGIF(address=None):
    return app.send_static_file('KOAWeather.gif')


@app.route('/getlogs/', methods=["GET"])
def openLogScreen():
    return render_template("consoleLog_UI.html")


def parseConfiguration():
    print("-parseConfiguration-")
    try:

        config = cfg.read('KOAConsole.ini')

        configInput = [cfg.get("MongoDB Configuration", "client_connection"),
                       cfg.get("WebUI Configuration", "web_ui_port"),
                       cfg.get("M5Stack Configuration", "m5_aws_access"),
                       cfg.get("M5Stack Configuration", "m5_aws_secret")
                       ]
        print("Configuration Read:", configInput)

        if not config:
            print("1")
            logger.error(
                "-parseConfiguration- There is an issue with the configuration file or none is present in root directory. "
                "Opening configuration prompt.")
            configurator(False)
        elif config and checkConfig():
            print("2")
        #  configurator(True)
        else:
            config = cfg.read('KOAConsole.ini')
            logger.info("-parseConfiguration- Configuration file read.")
            # cfg.get("client_connection", "web_ui_port")

    except Exception as e:
        configurator(False)
        print("There was an issue reading the configuration file. Error message:")
        print(e)
        logger.exception("-parseConfiguration- + Configuration parsing exception. " + str(e))
        # configurator(False)
    try:
        return configInput
    except:
        return False


# Calculates the hash of the directory the python file is in.
def calcHash():
    fname = os.path.abspath(__file__)
    print("My path: " + fname)
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(2 ** 20), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


# Management Console main class.


_userName = ''
menu = ['',
        ['Show Window', 'Hide Window', '---', '!Disabled Item', 'Change Icon', ['Happy', 'Sad', 'Plain'], 'Exit']]
tooltip = 'KOA Management Console'

tray = sgd.SystemTray(menu, tooltip=tooltip)

state_names = [state.name for state in us.states.STATES_AND_TERRITORIES]


@app.route('/login/', methods=['POST'])
def verifyCredentials():
    print("-verifyCredentials-")
    try:
        if request.method == "POST":
            print(request.form['username'])

            _userName = request.form['username']

            clientAppMain = startMongoNoCheck()
            print("User I am searching for: ", _userName)
            print("Users", clientAppMain.KOADB.ManagementUsers.find({}))
            userEquate = clientAppMain.KOADB.ManagementUsers.find({'Username': _userName})
            print("User Cursor: ", userEquate)
            print("Entered pass:", request.form['password'])
            userAuthenticate = check_password_mongoDB(request.form['password'], userEquate)
            print("Verified? ", userAuthenticate)
            if userAuthenticate:
                print("Authentication Successful.")
                logger.info("-verifyCredentials- User authentication successful. User: " + _userName)
                session["name"] = request.form.get("username")
                return openWelcomeScreen()
            # thread = Thread(target=openWelcomeScreen(getSensors()))
            # thread.start()

            else:
                logger.error("-verifyCredentials- Invalid credentials were entered for user " +
                             request.form['username'])
                print("Invalid credentials entered.")
                flash("Invalid credentials were entered. Please check your username and password.")
                return redirect(url_for("index"))
    except Exception as e:
        print("Error verifying credentials. Error:\n", e)
        logger.exception("-verifyCredentials- There was an exception while verifying credentials. " + str(e))
        return redirect(url_for("index"))

        #     window['title'].update(value='Invalid credentials were entered!', text_color='red')
        #     tray.show_message("Warning!", "You entered invalid credentials!")


@app.route("/logout")
def logout():
    logger.info("-logout- User sign-out: " + session["name"])
    session["name"] = None
    return redirect("/")


@app.route("/login/", methods=['GET'])
def openLoginScreen():
    session["name"] = None
    return redirect(url_for("index"))


@app.route("/consoleAction/", methods=['POST'])
def proccessWelcomeAction():
    print("-proccessWelcomeAction-")
    # stationSelected = request.form[""]
    try:
        stationSelected = request.form['stationlist']
        actionSelected = request.form['actionSelection']
        station = startMongoNoCheck().KOADB.WeatherStations.find_one({'name': stationSelected})
        print("Station selected:", stationSelected, "Action selected:", actionSelected)
        if actionSelected == "add":
            print("-Add Station-")
            logger.info("-proccessWelcomeAction- User " + session[
                "name"] + "is performing the following action: " + actionSelected + " on station " + stationSelected)
            return render_template('addStation_UI.html', stationStateList=us_state_to_abbrev)
        elif actionSelected == "modify":
            print("-Modify Station-")
            logger.info("-proccessWelcomeAction- User " + session[
                "name"] + "is performing the following action: " + actionSelected + " on station " + stationSelected)
            return render_template('modify_UI.html', stationSelected=stationSelected,
                                   stationStateList=us_state_to_abbrev,
                                   stationStreet=station['street'], stationMunicipality=station['municipality'],
                                   stationState=station['state'], stationZipcode=station['zip code'])
        elif actionSelected == "remove":
            mongo_id = getDocumentID("WeatherStations", "name", stationSelected)
            print("-Remove Station-")
            logger.info("-proccessWelcomeAction- User " + session[
                "name"] + "is performing the following action: " + actionSelected + " on station " + stationSelected)
            startMongoNoCheck().KOADB.WeatherStations.delete_one({"_id": mongo_id})
            return openWelcomeScreen()
        elif actionSelected == "getlogs":
            logger.info("-proccessWelcomeAction- User " + session[
                "name"] + " is performing the following action: " + actionSelected + ".")
            return openLogScreen()
        elif actionSelected == "allreadings":
            logger.info("-proccessWelcomeAction- User " + session[
                "name"] + "is performing the following action: " + actionSelected)
            return openAllSensorsScreen()
    except Exception as e:
        print("Exception occurred performing the requesting action.", str(e))
        flash("Your requested action could not be performed at this time. Please see logs for details.")
        logger.exception("-processWelcomeAction- There was a critical error while processing user " + session[
            'name'] + "'s requested action. " + str(e))


@app.route("/modifyAction/", methods=['POST'])
def processModifyAction():
    print("-processModifyAction-")
    try:

        stationName = request.form['name']
        stationStreet = request.form['street']
        stationMunicipality = request.form['municipality']
        stationState = request.form['stationstate']
        stationZip = request.form['zipcode']
        mongo_id = getDocumentID("WeatherStations", "name", stationName)
        weatherDict = {"name": stationName, "street": stationStreet,
                       "municipality": stationMunicipality,
                       "state": stationState,
                       "zip code": stationZip}
        print("Mongo Object ID:", mongo_id, "Station Updated:", weatherDict)
        logger.info(("-processModifyAction- User has updated station with Mongo Object ID: " + mongo_id + " Station Updated:" + weatherDict))
        startMongoNoCheck().KOADB.WeatherStations.update_one({'_id': mongo_id}, {"$set": weatherDict},
                                                             upsert=False)
        return openWelcomeScreen()
    except Exception as e:
        logger.exception("-processModifyAction- There was an issue with the user's modification request. Exception caught: " + str(e))
        flash("There was an issue processing your request. Please try again or return to the home screen.")


@app.route("/addAction/", methods=['POST'])
def processAddAction():
    try:
        stationName = request.form['name']
        stationStreet = request.form['street']
        stationMunicipality = request.form['municipality']
        stationState = request.form['stationstate']
        stationZip = request.form['zipcode']
        weatherDict = {"name": stationName, "street": stationStreet,
                       "municipality": stationMunicipality,
                       "state": stationState,
                       "zip code": stationZip}
        print("Station Added:", weatherDict)
        startMongoNoCheck().KOADB.WeatherStations.insert_one(weatherDict)
        logger.info("-processAddAction- User " + session['name'] +" has added a new weather station to the database. "
                                                                  "Station info: "+ weatherDict)
        return openWelcomeScreen()
    except Exception as e:
        flash("There was an issue processing your request. Please try again or return to the home screen.")
        logger.exception("-processAddAction- There was an issue with the user's post request. Exception caught: " + str(e))


@app.route("/register/", methods=['POST', 'GET'])
def registerUser():
    print("-registerUser-")
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if request.method == "GET":
        return render_template('Register_UI.html')
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        confpassword = request.form['password2']
        email = request.form["email"]
        firstname = request.form["firstname"]
        lastname = request.form["lastname"]

        if username == "":
            flash("Enter a valid username.")
            return redirect(url_for("registerUser"))
        elif email == "" or not (re.fullmatch(regex, email)):
            flash("Enter valid e-mail address.")
            return redirect(url_for("registerUser"))
        elif password != confpassword:
            flash('Your passwords must match.')
            return redirect(url_for("registerUser"))
        elif password == "":
            flash("You must enter a password.")
            return redirect(url_for("registerUser"))
        elif (firstname == "") & (lastname == ""):
            flash("You must enter a valid name.")
            return redirect(url_for("registerUser"))
        elif confpassword == password:
            userDict = {"Username": username,
                        "Password": get_hashed_password(password.encode('utf-8')),
                        "Firstname": firstname,
                        "Lastname": lastname,
                        "E-mail address": lastname}
            print("Inserting a new user into the database.")
            startMongoNoCheck().KOADB.ManagementUsers.insert_one(userDict)
            return render_template('Login_UI.html')
    return "There was an issue with entered credentials."


@app.route("/forward/", methods=['GET'])
# Opens the main dashboard that the user first sees after login, presenting to them a menu of options.
def openWelcomeScreen():
    print("-openWelcomeScreen-")
    if not session.get("name"):
        return redirect("/")
    return render_template('welcome_UI.html', dropdown_list=getSensors())


@app.route("/getAllSensorReadings/", methods=['GET'])
def openAllSensorsScreen():
    print("-openAllSensorsScreen-")
    return render_template('allSensorReadings_UI.html', stationReadings=getAllSensorReadings())


# Returns all the weather stations.
def getSensors():
    print("-getSensors-")
    sensors = []
    for x in startMongoNoCheck().KOADB.WeatherStations.find({}, {"_id": 0, "name": 1}):
        sensors.append(x["name"])
    return sensors


def getAllSensorReadings():
    print("-getAllSensorReadings-")
    sensors = []
    sensors2 = []
    for x in startMongoNoCheck().KOADB.WeatherStationData.find({}, {"_id": 0, "station": 1, "tempF": 1, "tempC": 1,
                                                                    "humidity": 1, "pressure": 1, "time": 1,
                                                                    "date": 1}):
        sensors.append((x["station"], "Temperature:", str(x["tempF"]), "℉", str(x["tempC"]), "℃", "Humidity:",
                        str(x["humidity"]) + "%", "Pressure:", str(x["pressure"]) + " in", "Time:",
                        str(x["time"]), "Date:",
                        str(x["date"]) + ""))
    for s in sensors:
        s = str(s).replace(',', '')
        s = s.replace("'", "")
        sensors2.append(s)
    return sensors2


def getSensorReading(sensor):
    print("-getSensorReading-")

    sensorData = []
    try:
        for x in startMongoNoCheck().KOADB.WeatherStationData.find(({"station": sensor}),
                                                                   {"_id": 0, "station": 1, "tempF": 1, "tempC": 1,
                                                                    "humidity": 1, "pressure": 1, "time": 1,
                                                                    "date": 1}):
            sensorData.append({
                "Temperature℉": str(x["tempF"]),
                "Temperature℃": str(x["tempC"]),
                "Humidity": str(x["humidity"]),
                "Pressure": str(x["pressure"]),
                "Time": str(x["time"]),
                "Date": str(x["date"])})

        return sensorData
    except Exception as e:
        print("An error occurred while getting a sensor reading for", sensor, " Error:\n", e)
        return False


# Returns the current registered user utilizing the console.
def getCurrentUser():
    print("-getCurrentUser-")
    return _userName


# Salt hashes a plaint text password (str) using bcrypt's hashpw method.
# Returns a Python "bytes" object.
def get_hashed_password(plain_text_password):
    # Hash a password for the first time
    #   (Using bcrypt, the salt is saved into the hash itself)
    return bcrypt.hashpw(plain_text_password, bcrypt.gensalt())


# Validates a salt hashed password with a plaintext string.
# Returns a boolean.
def check_password(plain_text_password, hashed_password):
    # Check hashed password. Using bcrypt, the salt is saved into the hash itself
    return bcrypt.checkpw(plain_text_password, hashed_password)


# Verifies a plaintext password with a salt hashed password (PyMongo cursor).
# Returns a boolean.
def check_password_mongoDB(entry, userEquate):
    print("-check_password_mongoDB-")
    try:

        if userEquate != [""]:

            userEquateListStr = []
            records = dict((record['Password'], record) for record in userEquate)

            print("Records:", records)

            for i in records:
                userEquateListStr.append(i)
                print("Value in list: ", userEquateListStr)
            print("Checking password...")
            print("userEquateListStr:", userEquateListStr)
            PWs = ('{} {}'.format(userEquateListStr, ''))

            PWs = repr(PWs)[4:-1]
            PWs = PWs[:-3]
            print("PW: ", PWs, " Entry: ", entry.encode('utf-8'))
            verifyPW = check_password(entry.encode('utf-8'), PWs.encode('utf-8'))
            return verifyPW
        else:
            return False
    except Exception as e:
        print("Exception caught when trying to verify credentials with MongoDB.")
        print("Exception message:", e)
        return False


# Finds the document id within a collection in the MongoDB client "db".
def getDocumentID(collectionName, fieldName, fieldEntry):
    collection = startMongoNoCheck().KOADB[collectionName]
    cursor = collection.find_one({fieldName: fieldEntry})
    return cursor["_id"]


def retrieveMongoDocument(collectionName, searchFieldName, searchFieldValue):
    print("Searching for", searchFieldName, "with a value of", searchFieldValue, "in collection",
          collectionName + ".")
    cursor = [i for i in startMongoNoCheck().KOADB[collectionName].find({searchFieldName: (searchFieldValue)})]
    return cursor


# Source: https://gist.github.com/rogerallen/1583593
us_state_to_abbrev = {
    "Alabama": "AL",
    "Alaska": "AK",
    "Arizona": "AZ",
    "Arkansas": "AR",
    "California": "CA",
    "Colorado": "CO",
    "Connecticut": "CT",
    "Delaware": "DE",
    "Florida": "FL",
    "Georgia": "GA",
    "Hawaii": "HI",
    "Idaho": "ID",
    "Illinois": "IL",
    "Indiana": "IN",
    "Iowa": "IA",
    "Kansas": "KS",
    "Kentucky": "KY",
    "Louisiana": "LA",
    "Maine": "ME",
    "Maryland": "MD",
    "Massachusetts": "MA",
    "Michigan": "MI",
    "Minnesota": "MN",
    "Mississippi": "MS",
    "Missouri": "MO",
    "Montana": "MT",
    "Nebraska": "NE",
    "Nevada": "NV",
    "New Hampshire": "NH",
    "New Jersey": "NJ",
    "New Mexico": "NM",
    "New York": "NY",
    "North Carolina": "NC",
    "North Dakota": "ND",
    "Ohio": "OH",
    "Oklahoma": "OK",
    "Oregon": "OR",
    "Pennsylvania": "PA",
    "Rhode Island": "RI",
    "South Carolina": "SC",
    "South Dakota": "SD",
    "Tennessee": "TN",
    "Texas": "TX",
    "Utah": "UT",
    "Vermont": "VT",
    "Virginia": "VA",
    "Washington": "WA",
    "West Virginia": "WV",
    "Wisconsin": "WI",
    "Wyoming": "WY",
    "District of Columbia": "DC",
    "American Samoa": "AS",
    "Guam": "GU",
    "Northern Mariana Islands": "MP",
    "Puerto Rico": "PR",
    "United States Minor Outlying Islands": "UM",
    "U.S. Virgin Islands": "VI",
}


def get_db():
    """
    Configuration method to return db instance
    """
    db = getattr(g, "_database", None)

    if db is None:
        db = g._database = PyMongo(app).db

    return db


def create_app():
    app.config['DEBUG'] = True
    app.config['MONGO_URI'] = cfg.get("MongoDB Configuration", "client_connection")
    app.config["SESSION_PERMANENT"] = False
    # db.init_app(app)

    # from yourapplication.views.admin import admin
    # from yourapplication.views.frontend import frontend
    # app.register_blueprint(admin)
    # app.register_blueprint(frontend)

    return app


if __name__ == "__main__":
    #    test = getAllSensorReadings()
    #   for x in test:
    #        print(x)

    parseConfiguration()
    app1 = create_app()
    Thread = Thread(target=app.run(port=port))
    Thread.run()

    # clientAppMain = startMongoNoCheck()
    # print("Thread created.")
    # thread = Thread(target=startMongoNoCheck)
    # print("Running Flask")
    # thread.start()

    # print(thread)

    
    
    
    
    
#code from M5-Weather Station to access AWS, read data stored as files,
#parse in JSON, and then push to Mongo starts from here downwards

import boto3
import json


import pymongo as pymongo
from pymongo import MongoClient
from pymongo.server_api import ServerApi

#creating config parser and setting parameters
config = configparser.ConfigParser()		
AWS = ''
clientInfo = ''
access_key= ''
secret_key = ''

def configParse():
    config.read("M5_Config.ini")
    #gets parameters to be used as variables in code
    Mongo = config['MongoConfig']
    AWS = config['AWSConfig']
    access_key = AWS["access_key"]
    secret_key = AWS["secret_key"]
    #setting variable for Mongo connection string
    clientInfo = Mongo["clientInfo"]
    #test to ensure config data is properly retrieved
    print(access_key)
    print(secret_key)
    print(clientInfo)

configParse()


#pymongo connection code
Mongo = config['MongoConfig']
clientInfo = Mongo["clientInfo"]
print('Starting Mongo Connection...')
client = pymongo.MongoClient(clientInfo, server_api = ServerApi('1'))
db = client.KOADB
collection = db.WeatherStationData
#attempts to connect to Mongo deployment and prints out a statement corresponding to its success or failure
try:
    conn = MongoClient()
    print("Successfully connected to MongoDB!")
except:
    print("Failed to Connect to MongoDB.")


#establishes connection to AWS IAM role and contains permissions needed to access and read files within bucket
AWS = config['AWSConfig']
access_key = AWS["access_key"]
secret_key = AWS["secret_key"]
s3 = boto3.resource(
    's3',
    region_name = 'us-east-1',
    aws_access_key_id = access_key,
    aws_secret_access_key = secret_key
)


#variable used to keep track of how many items (stored sensor readings) are in bucket
item_count = 0

#iterates over all files present in bucket, reads files, converts data to json, then parses and prints
bucket = s3.Bucket('ist440w-m5-bucket')

for obj in bucket.objects.all():
    item_count = item_count + 1
    key = obj.key                                           #reads file and acquires key_id used by AWS (basically primary keys) for each file
    body = obj.get()['Body'].read().decode('utf-8')         #reads file and acquires the actual contents of each file       
    parsed_data = json.loads(body)
    collection.insert_one(parsed_data)
#   print(parsed_data)
#   print(parsed_data['date'])              #just had this here to test



print("There are", item_count, "items in the bucket.")
