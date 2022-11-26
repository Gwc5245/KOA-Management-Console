import configparser
import hashlib
import logging
import os
import shutil
from threading import Thread

import remi.gui as gui
from remi import start, App
import PySimpleGUI as sgd
import PySimpleGUIWeb as sg

import bcrypt
import pymongo as pymongo
import us as us
from pymongo.server_api import ServerApi
from remi.server import StandaloneServer, Server
from flask import Flask

app = Flask(__name__)

configFile = ()
cfg = configparser.ConfigParser()
path = os.path.abspath(__file__)
sg.theme("reddit")
port = 25566
# MongoDB connection


client = pymongo.MongoClient(
    "mongodb+srv://<AWS access key>:<AWS secret key>@cluster0.re3ie7p.mongodb.net/?authSource=%24external&authMechanism=MONGODB-AWS&retryWrites=true&w=majority",
    server_api=ServerApi('1'))

db = client.KOADB


# print("Collections: ", db.list_collection_names())
# print("MongoDB info: ", client.server_info())

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
    print("Starting MongoDB")

    print("Client information:", client_connection)
    clientAppMain = pymongo.MongoClient(
        client_connection,
        server_api=ServerApi('1'))
    db = clientAppMain.KOADB

    print("Databases:", clientAppMain.list_databases())
    print("Client", clientAppMain)
    print("Database", db)
    threadLogin()
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

    cfg.read('KOAConsole.ini')
    print("Launching main application.")
    clientPass = cfg.get("MongoDB Configuration", "client_connection")
    startMongo(clientPass)

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
        print("Reading configuration...")
        configInput = [cfg.get("MongoDB Configuration", "client_connection"), cfg.get("WebUI Configuration", "Port")]
        print("Configuration Read:", configInput)

        if not config:
            print("1")
            configurator(False)
        elif config and checkConfig():
            print("2")
            configurator(True)
        else:
            config = cfg.read('KOAConsole.ini')
            cfg.get("client_connection", "port")

    except Exception as e:
        print("There was an issue reading the configuration file. Error message:")
        print(e)
        configurator(False)
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

def threadLogin():
    thread = Thread(target=openLoginScreen())
    print("Thread created.")
    thread.start()

# Opens the login screen that requests user's credentials.

@app.route('/login',methods=["GET"])

def openLoginScreen():

    layout = [
        [sg.Text("Please login to continue.", key='title')],
        [sg.Text('Username', size=(15, 1)), sg.InputText('', key='Username')],
        [sg.Text('Password', size=(15, 1)), sg.InputText('', key='Password', password_char='*')],
        [sg.Button("OK")],
        [sg.Button("No Account?")]
    ]
    # window = sg.Window(title="KOA Management Console Login", layout=layout2, margins=(500, 500)).read()
    window = sg.Window(title="KOA Management Console Login", layout=layout, disable_close=True, web_port=port,
    web_start_browser=True, web_multiple_instance=True)

    while True:
        event, values = window.read()
        # End program if user closes window or
        # presses the OK button
        if event == "OK":
            _userName = values['Username']
            user = values["Username"]
            print("User I am searching for: ", user)
            print("Users", clientAppMain.KOADB.ManagementUsers.find({}))
            userEquate = clientAppMain.KOADB.ManagementUsers.find({'Username': user})
            print("User Cursor: ", userEquate)
            print("Entered pass:", values["Password"])
            userAuthenticate = check_password_mongoDB(values["Password"], userEquate)
            print("Verified? ", userAuthenticate)
            if userAuthenticate:
                print("Starting Login Thread...")
                thread = Thread(target=openWelcomeScreen(getSensors()))
                thread.start()
            else:
                print("Invalid credentials entered.")
                window['title'].update(value='Invalid credentials were entered!', text_color='red')
                tray.show_message("Warning!", "You entered invalid credentials!")

        if event == sg.WIN_CLOSED:
            break
        if event == "No Account?":
            openSignupScreen()

    window.close()

state_names = [state.name for state in us.states.STATES_AND_TERRITORIES]

def openSignupScreen(self):

    layout = [
        [sg.Text("Create a new account.")],
        [sg.Text('Username', size=(15, 1)), sg.InputText('', key='Username')],
        [sg.Text('Password', size=(15, 1)), sg.InputText('', key='Password', password_char='*')],
        [sg.Text('Confirm password', size=(15, 1)), sg.InputText('', key='PasswordConf', password_char='*')],
        [sg.Text('Firstname', size=(15, 1)), sg.InputText('', key='Firstname')],
        [sg.Text('Lastname', size=(15, 1)), sg.InputText('', key='Lastname')],
        [sg.Text('E-mail address', size=(15, 1)), sg.InputText('', key='Email')],
        [sg.Button("OK")],
    ]
    # margins=(500, 500)
    signupWindow = sg.Window(title="KOA Create Account", layout=layout, web_multiple_instance=True, )

    print('Username: ' + getCurrentUser())
    while True:
        event, values = signupWindow.read()
        # End program if user closes window or
        # presses the OK button

        if event == "OK":
            userDict = {"Username": values["Username"],
                        "Password": get_hashed_password(values["Password"].encode('utf-8')),
                        "Firstname": values["Firstname"],
                        "Lastname": values["Lastname"],
                        "E-mail address": values["Email"]}
            db.ManagementUsers.insert_one(userDict)

            break
        if event == sg.WIN_CLOSED:
            break

# Opens the main dashboard that the user first sees after login, presenting to them a menu of options.
def openWelcomeScreen(self, stations):
    print("-openWelcomeScreen-")
    items = ["Add Station", "Modify Station", "Remove Station"]

    username = (getCurrentUser())

    layout = [
        [sg.Text("Welcome to the Management Dashboard, " + username.capitalize() + '.')],
        [sg.Text("Select Weather Station:")],
        [sg.Listbox(values=stations, select_mode='SINGLE', key='stationsBox', size=(30, 6),
                    tooltip='Select a weather station to modify.')],
        [sg.Text("Select a menu option:")],
        #    [sg.Radio('Add Station', "RADIO1", default=False, key="-ADD-")],
        #    [sg.Radio('Modify Station', "RADIO1", default=False, key="-MODIFY-")],
        [sg.InputCombo(items, size=(20, 1), key="stationAction_combobox")],
        [sg.Button("OK")],
    ]
    # margins=(500, 500)
    ws= (sg.Window(title="KOA Management Console", layout=layout))
    ws.FindElement('stationAction_combobox').Update('')

    print('Username: ' + getCurrentUser())
    while True:
        print("Listening...")
        event, values = ws.read()
        if values["stationAction_combobox"]:

            if values["stationAction_combobox"] == "Add Station":
                openAddStation()
            elif values["stationAction_combobox"] == "Modify Station":
                print("Weather Station selected: ", values['stationsBox'])
                openModifyStation(values['stationsBox'][0])



def openAddStation(self):
    print("-openAddStation-")
    layout = [
        [sg.Text("Enter weather station info to add it to the database.")],
        [sg.Text('Station Name', size=(15, 1)), sg.InputText('', key='Station Name')],
        [sg.Text('Station Street', size=(15, 1)), sg.InputText('', key='Station Street')],
        [sg.Text('Station Municipality', size=(15, 1)), sg.InputText('', key='Station Municipality')],
        [sg.Text('Station State', size=(15, 1)),
         sg.Combo(state_names, default_value='Utah', key='Station State', readonly=True)],
        [sg.Text('Station Zip Code', size=(15, 1)), sg.InputText('', key='Station Zip Code')],
        [sg.Button("OK")],
        [sg.Button("Cancel")],

    ]
    # window = sg.Window(title="KOA Management Console Login", layout=layout2, margins=(500, 500)).read()
    window = sg.Window(title="KOA Management Console Add Station", layout=layout)

    while True:
        event, values = window.read()
        # End program if user closes window or
        # presses the OK button
        if event == "OK":
            weatherDict = {"name": values["Station Name"], "street": values["Station Street"],
                           "municipality": values["Station "
                                                  "Municipality"],
                           "state": values["Station State"],
                           "zip code": values["Station Zip Code"]}
            clientAppMain.KOADB.WeatherStations.insert_one(weatherDict)

            break
        if event == "Cancel":
            openWelcomeScreen(getSensors())
    print("-Opening Welcome Screen-")
    openWelcomeScreen(getSensors())

def openModifyStation(self, stationName):
    print("-openModifyStation-")
    print("Station being modified: ", stationName)

    station = clientAppMain.KOADB.WeatherStations.find_one({'name': stationName})
    print("Found document in DB: ", station)
    print("Full Document: ", list(station))

    mongo_id = getDocumentID("WeatherStations", "name", stationName)
    print("With Object ID: ", mongo_id)

    layout = [
        [sg.Text("Modify weather station information.")],
        [sg.Text('Station Name', size=(15, 1)),
         sg.InputText(clientAppMain.KOADB.WeatherStations.find_one({"name": stationName})["name"],
                      key='Station Name')],
        [sg.Text('Station Street', size=(15, 1)),
         sg.InputText(clientAppMain.KOADB.WeatherStations.find_one({"name": stationName})["street"],
                      key='Station Street')],
        [sg.Text('Station Municipality', size=(15, 1)),
         sg.InputText(clientAppMain.KOADB.WeatherStations.find_one({"name": stationName})["municipality"],
                      key='Station Municipality')],
        [sg.Text('Station State', size=(15, 1)),
         sg.Combo(state_names,
                  default_value=clientAppMain.KOADB.WeatherStations.find_one({"name": stationName})["state"],
                  key='Station State', readonly=True)],
        [sg.Text('Station Zip Code', size=(15, 1)),
         sg.InputText(clientAppMain.KOADB.WeatherStations.find_one({"name": stationName})["zip code"],
                      key='Station Zip Code')],
        [sg.Button("OK")],
        [sg.Button("Cancel")],

    ]

    # window = sg.Window(title="KOA Management Console Login", layout=layout2, margins=(500, 500)).read()
    window = sg.Window(title="KOA Management Console Add Station", layout=layout)

    while True:
        event, values = window.read()
        # End program if user closes window or
        # presses the OK button
        if event == "OK":
            if values["Station Name"] == '':
                values["Station Name"] = clientAppMain.KOADB.WeatherStations.find_one({"name": stationName})[
                    "name"]
            if values["Station Street"] == '':
                values["Station Street"] = clientAppMain.KOADB.WeatherStations.find_one({"name": stationName})[
                    "street"]
            if values["Station Municipality"] == '':
                values["Station Municipality"] = \
                    clientAppMain.KOADB.WeatherStations.find_one({"name": stationName})["municipality"]
            if values["Station Zip Code"] == '':
                values["Station Zip Code"] = \
                    clientAppMain.KOADB.WeatherStations.find_one({"name": stationName})["zip code"]

            weatherDict = {"name": values["Station Name"], "street": values["Station Street"],
                           "municipality": values["Station "
                                                  "Municipality"],
                           "state": values["Station State"],
                           "zip code": values["Station Zip Code"]}
            print("Station Updated:", weatherDict)
            clientAppMain.KOADB.WeatherStations.update_one({'_id': mongo_id}, {"$set": weatherDict},
                                                                upsert=False)

            break
        if event == "Cancel" or event == sg.WIN_CLOSED:
            openWelcomeScreen(getSensors())
            break

    openWelcomeScreen(getSensors())

# Returns all the weather stations.
def getSensors(self):
    print("-getSensors-")
    sensors = []
    for x in clientAppMain.KOADB.WeatherStations.find({}, {"_id": 0, "name": 1}):
        sensors.append(x["name"])
    return sensors

# Returns the current registered user utilizing the console.
def getCurrentUser(self):
    print("-getCurrentUser-")
    return _userName

# Salt hashes a plaint text password (str) using bcrypt's hashpw method.
# Returns a Python "bytes" object.
def get_hashed_password(self, plain_text_password):
    # Hash a password for the first time
    #   (Using bcrypt, the salt is saved into the hash itself)
    return bcrypt.hashpw(plain_text_password, bcrypt.gensalt())

# Validates a salt hashed password with a plaintext string.
# Returns a boolean.
def check_password(self, plain_text_password, hashed_password):
    # Check hashed password. Using bcrypt, the salt is saved into the hash itself
    return bcrypt.checkpw(plain_text_password, hashed_password)

# Verifies a plaintext password with a salt hashed password (PyMongo cursor).
# Returns a boolean.
def check_password_mongoDB(self, entry, userEquate):
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
def getDocumentID(self, collectionName, fieldName, fieldEntry):
    collection = clientAppMain.KOADB[collectionName]
    cursor = collection.find_one({fieldName: fieldEntry})
    return cursor["_id"]

def retrieveMongoDocument(self, collectionName, searchFieldName, searchFieldValue):

    print("Searching for", searchFieldName, "with a value of", searchFieldValue, "in collection",
          collectionName + ".")
    cursor = [i for i in clientAppMain.KOADB[collectionName].find({searchFieldName: (searchFieldValue)})]
    return cursor

def on_window_close(self):
    print("User has disconnected.")
    _stop_update_flag = True
    try:
        for ws in websockets:
            ws.close()
    except Exception as e:
        print("No sockets to close.")

def onload(self, emitter):
    """ WebPage Event that occurs on webpage loaded """
    super(appWindowMain, self).onload(emitter)
    # the page reloaded, the timeout timer gets canceled
    if not (timer_timeout == None):
        timer_timeout.cancel()
        timer_timeout = None


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
if __name__ == "__main__":

    print("Thread created.")
    thread = Thread(target=startMongoNoCheck)
    print("Running Flask")
    run()
    thread.start()
