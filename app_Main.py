import configparser
import hashlib
import logging
import os
import re
import shutil
from threading import Thread

import PySimpleGUI as sgd
import PySimpleGUIWeb as sg
import bcrypt
import pymongo as pymongo
import pymongo_auth_aws as g
import us as us
import wtforms
from flask import Flask, render_template, request, flash, url_for, redirect
from flask_pymongo import PyMongo
from pymongo.server_api import ServerApi
from remi.server import StandaloneServer, Server

from wtforms import form

app = Flask(__name__)
app.secret_key = "super secret key"
configFile = ()
cfg = configparser.ConfigParser()
path = os.path.abspath(__file__)
sg.theme("reddit")
port = 25566
# MongoDB connection
s = g
appWindowMain = ()
client = pymongo.MongoClient(
    "mongodb+srv://<AWS access key>:<AWS secret "
    "key>@cluster0.re3ie7p.mongodb.net/?authSource=%24external&authMechanism=MONGODB-AWS&retryWrites=true&w=majority",
    server_api=ServerApi('1'))

db = client.KOADB


# print("Collections: ", db.list_collection_names())
# print("MongoDB info: ", client.server_info())
@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('Login_UI.html')


def run():
    app.run(debug=True, port=port, host="0.0.0.0")


def genConfigFile(db_url, in_port):
    print("-genConfigFile-")
    try:

        cfg.add_section('MongoDB Configuration')
        db_url = db_url.replace('%', '%%')
        cfg.add_section('WebUI Configuration')
        port = (int(in_port))
        # client = pymongo.MongoClient(db_url, server_api=ServerApi('1'))
    except Exception as e:
        print("There was an issue with the url entered for the Mongo Client. Message:")
        print(e)

    cfg.set('MongoDB Configuration', 'client_connection', db_url)
    cfg.set('WebUI Configuration', 'web_ui_port', port)
    with open('KOAConsole.ini', 'w') as configfile:
        print(cfg.write(configfile))


def openConfigurationFileSelection():
    print("-openConfigurationFileSelection-")
    file_list_column = [
        [sgd.Text("Configuration File"),
         sgd.In(size=(25, 1), enable_events=True, key="-FOLDER-"),
         sgd.FileBrowse(), ],
        [sgd.Listbox(values=[], enable_events=True, size=(40, 20), key="-FILE LIST-")],
    ]

    layout = [
        [sgd.Text("Please select a configuration file.", key='validation')],
        [sgd.Column(file_list_column)],
        # [sgd.Text('Username', size=(15, 1)), sgd.InputText('', key='Username')],
        [sgd.Button("Save", key='SaveButton')],
        [sgd.Button("Discard")]
    ]
    # window = sg.Window(title="KOA Management Console Login", layout=layout2, margins=(500, 500)).read()

    window = sgd.Window(title="KOA Management Console Configuration", layout=layout)
    while True:
        event, values = window.read()
        if event == "Exit" or event == sg.WIN_CLOSED:
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

            configCheck = checkConfig()

            if configCheck:
                config = parseConfiguration(True)
                window.close()
            elif not configCheck:
                window['validation'].update(
                    value='Invalid configuration detected. \nPlease make sure all necessary fields are entered.', )


clientPass = ""


def checkConfig():
    try:
        print("-checkConfig-")
        # print("Configuration being checked:", config, type(config))
        print("Sections:", (cfg.sections()))
        portIn = (cfg.get('WebUI Configuration', "Port"))
        client_connection = (cfg.get("MongoDB Configuration", "client_connection"))
        print(client_connection, portIn)
        if not portIn:
            print("Port connection not found in configuration file.")
            return False
        if not client_connection:
            print("Client connection not found in configuration file.")
            return False
    except Exception as e:
        print("There is an issue with the configuration file:", e)
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

    print("Databases:", clientAppMain.list_databases())

    # threadLogin()
    return clientAppMain
    print("\n!!!!!!!!! Thread started.")


def configurator(fileLocated):
    print("-configurator-")
    cfg.read('KOAConsole.ini')
    if not fileLocated:
        print("Opening configuration file selection.")
        openConfigurationFileSelection()
    if fileLocated and checkConfig():
        print("Launching main application.")
        clientPass = cfg.get("MongoDB Configuration", "client_connection")
        startMongo(clientPass)


def startMongoNoCheck():
    print("-startMongoNoCheck-")
    cfg.read('KOAConsole.ini')
    clientPass = cfg.get("MongoDB Configuration", "client_connection")
    return startMongo(clientPass)


def start(main_gui_class, **kwargs):
    """This method starts the webserver with a specific App subclass."""
    debug = kwargs.pop('debug', False)
    standalone = kwargs.pop('standalone', False)

    logging.basicConfig(level=logging.DEBUG if debug else logging.INFO,
                        format='%(name)-16s %(levelname)-8s %(message)s')
    logging.getLogger('remi').setLevel(
        level=logging.DEBUG if debug else logging.INFO)

    if standalone:
        s = StandaloneServer(main_gui_class, start=True, **kwargs)
    else:
        s = Server(main_gui_class, multiple_instance=True, start=True, **kwargs)


def autoParse():
    parseConfiguration(False)


def parseConfiguration():
    print("-parseConfiguration-")
    try:

        config = cfg.read('KOAConsole.ini')

        configInput = [cfg.get("MongoDB Configuration", "client_connection"), cfg.get("WebUI Configuration", "Port")]
        print("Configuration Read:", configInput)

        if not config:
            print("1")
        #  configurator(False)
        elif config and checkConfig():
            print("2")
        #  configurator(True)
        else:
            config = cfg.read('KOAConsole.ini')
            cfg.get("client_connection", "port")

    except Exception as e:
        print("There was an issue reading the configuration file. Error message:")
        print(e)
        # configurator(False)
    return [cfg.get("MongoDB Configuration", "client_connection"), cfg.get("WebUI Configuration", "Port"), ]


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


@app.route('/login/', methods=['GET', 'POST'])
def verifyCredentials():
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
            return render_template('welcome_UI.html', dropdown_list=getSensors())
        # thread = Thread(target=openWelcomeScreen(getSensors()))
        # thread.start()

        else:
            print("Invalid credentials entered.")
            flash("Invalid credentials were entered. Please check your username and password.")
            return redirect(url_for("index"))

        #     window['title'].update(value='Invalid credentials were entered!', text_color='red')
        #     tray.show_message("Warning!", "You entered invalid credentials!")


@app.route("/consoleAction/", methods=['POST'])
def proccessWelcomeAction():
    # stationSelected = request.form[""]

    stationSelected = request.form['stationlist']
    print(stationSelected)
    return render_template('welcome_UI.html', dropdown_list=getSensors())


@app.route("/register/", methods=['POST', 'GET'])
def registerUser():
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


@app.route("/forward/", methods=['POST'])
# Opens the main dashboard that the user first sees after login, presenting to them a menu of options.
def openWelcomeScreen(self, stations):
    print("-openWelcomeScreen-")


# Returns all the weather stations.
def getSensors():
    print("-getSensors-")
    sensors = []
    for x in startMongoNoCheck().KOADB.WeatherStations.find({}, {"_id": 0, "name": 1}):
        sensors.append(x["name"])
    return sensors


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

    # db.init_app(app)

    # from yourapplication.views.admin import admin
    # from yourapplication.views.frontend import frontend
    # app.register_blueprint(admin)
    # app.register_blueprint(frontend)

    return app


if __name__ == "__main__":
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
