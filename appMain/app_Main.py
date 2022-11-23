import configparser
import hashlib
import os
import shutil

import PySimpleGUI as sgd
import PySimpleGUIWeb as sg
import bcrypt
import pymongo as pymongo
import us as us
from pymongo.server_api import ServerApi

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


def configurator(fileLocated):
    print("-configurator-")
    cfg.read('KOAConsole.ini')
    if not fileLocated:
        print("Opening configuration file selection.")
        openConfigurationFileSelection()
    if fileLocated and checkConfig():
        print("Launching main application.")
        clientPass = cfg.get("MongoDB Configuration", "client_connection")
        windowMain = appWindowMain(clientPass)
        windowMain.openLoginScreen()


def parseConfiguration(passToConfigurator):
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
        elif not passToConfigurator:
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
class appWindowMain():

    def __init__(self, client_connection):
        print("Client information:", client_connection)
        self.clientAppMain = pymongo.MongoClient(
            client_connection,
            server_api=ServerApi('1'))
        db = self.clientAppMain.KOADB
        self.welcomewindow = ()
        print("Databases:", self.clientAppMain.list_databases())
        print("Client", self.clientAppMain)
        print("Database", db)
        super().__init__()

    _userName = ''
    menu = ['',
            ['Show Window', 'Hide Window', '---', '!Disabled Item', 'Change Icon', ['Happy', 'Sad', 'Plain'], 'Exit']]
    tooltip = 'KOA Management Console'

    tray = sgd.SystemTray(menu, tooltip=tooltip)

    # Opens the login screen that requests user's credentials.
    def openLoginScreen(self):

        layout = [
            [sg.Text("Please login to continue.", key='title')],
            [sg.Text('Username', size=(15, 1)), sg.InputText('', key='Username')],
            [sg.Text('Password', size=(15, 1)), sg.InputText('', key='Password', password_char='*')],
            [sg.Button("OK")],
            [sg.Button("No Account?")]
        ]
        # window = sg.Window(title="KOA Management Console Login", layout=layout2, margins=(500, 500)).read()
        window = sg.Window(title="KOA Management Console Login", layout=layout, web_port=port)

        while True:
            event, values = window.read()
            # End program if user closes window or
            # presses the OK button
            if event == "OK":
                self._userName = values['Username']
                user = values["Username"]
                print("User I am searching for: ", user)
                print("Users", self.clientAppMain.KOADB.ManagementUsers.find({}))
                userEquate = self.clientAppMain.KOADB.ManagementUsers.find({'Username': user})
                print("User Cursor: ", userEquate)
                print("Entered pass:", values["Password"])
                userAuthenticate = self.check_password_mongoDB(values["Password"], userEquate)
                print("Verified? ", userAuthenticate)
                if userAuthenticate:
                    self.openWelcomeScreen(self.getSensors())
                else:
                    print("Invalid credentials entered.")
                    window['title'].update(value='Invalid credentials were entered!', text_color='red')
                    self.tray.show_message("Warning!", "You entered invalid credentials!")

            if event == sg.WIN_CLOSED:
                break
            if event == "No Account?":
                self.openSignupScreen()

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
        self.signupWindow = sg.Window(title="KOA Create Account", layout=layout, )

        print('Username: ' + self.getCurrentUser())
        while True:
            event, values = self.signupWindow.read()
            # End program if user closes window or
            # presses the OK button

            if event == "OK":
                userDict = {"Username": values["Username"],
                            "Password": self.get_hashed_password(values["Password"].encode('utf-8')),
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

        username = (self.getCurrentUser())

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
        self.welcomewindow = sg.Window(title="KOA Management Console", layout=layout, )
        self.welcomewindow.FindElement('stationAction_combobox').Update('')

        print('Username: ' + self.getCurrentUser())
        while True:
            print("Listening...")
            event, values = self.welcomewindow.read()
            if event == sg.WIN_CLOSED or event == "Exit":
                self._stop_update_flag = True
                for ws in self.websockets:
                    ws.close()
                break
            elif values["stationAction_combobox"]:

                if values["stationAction_combobox"] == "Add Station":
                    self.openAddStation()
                elif values["stationAction_combobox"] == "Modify Station":
                    print("Weather Station selected: ", values['stationsBox'])
                    self.openModifyStation(values['stationsBox'][0])

    def openAddStation(self):
        print("-openAddStation-")
        layout = [
            [sg.Text("Enter weather station info to add it to the database.")],
            [sg.Text('Station Name', size=(15, 1)), sg.InputText('', key='Station Name')],
            [sg.Text('Station Street', size=(15, 1)), sg.InputText('', key='Station Street')],
            [sg.Text('Station Municipality', size=(15, 1)), sg.InputText('', key='Station Municipality')],
            [sg.Text('Station State', size=(15, 1)),
             sg.Combo(self.state_names, default_value='Utah', key='Station State', readonly=True)],
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
                self.clientAppMain.KOADB.WeatherStations.insert_one(weatherDict)

                break
            if event == "Cancel":
                self.openWelcomeScreen(self.getSensors())
        print("-Opening Welcome Screen-")
        self.openWelcomeScreen(self.getSensors())

    def openModifyStation(self, stationName):
        print("-openModifyStation-")
        print("Station being modified: ", stationName)

        station = self.clientAppMain.KOADB.WeatherStations.find_one({'name': stationName})
        print("Found document in DB: ", station)
        print("Full Document: ", list(station))

        mongo_id = self.getDocumentID("WeatherStations", "name", stationName)
        print("With Object ID: ", mongo_id)

        layout = [
            [sg.Text("Modify weather station information.")],
            [sg.Text('Station Name', size=(15, 1)),
             sg.InputText(self.clientAppMain.KOADB.WeatherStations.find_one({"name": stationName})["name"],
                          key='Station Name')],
            [sg.Text('Station Street', size=(15, 1)),
             sg.InputText(self.clientAppMain.KOADB.WeatherStations.find_one({"name": stationName})["street"],
                          key='Station Street')],
            [sg.Text('Station Municipality', size=(15, 1)),
             sg.InputText(self.clientAppMain.KOADB.WeatherStations.find_one({"name": stationName})["municipality"],
                          key='Station Municipality')],
            [sg.Text('Station State', size=(15, 1)),
             sg.Combo(self.state_names,
                      default_value=self.clientAppMain.KOADB.WeatherStations.find_one({"name": stationName})["state"],
                      key='Station State', readonly=True)],
            [sg.Text('Station Zip Code', size=(15, 1)),
             sg.InputText(self.clientAppMain.KOADB.WeatherStations.find_one({"name": stationName})["zip code"],
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
                    values["Station Name"] = self.clientAppMain.KOADB.WeatherStations.find_one({"name": stationName})[
                        "name"]
                if values["Station Street"] == '':
                    values["Station Street"] = self.clientAppMain.KOADB.WeatherStations.find_one({"name": stationName})[
                        "street"]
                if values["Station Municipality"] == '':
                    values["Station Municipality"] = \
                        self.clientAppMain.KOADB.WeatherStations.find_one({"name": stationName})["municipality"]
                if values["Station Zip Code"] == '':
                    values["Station Zip Code"] = \
                        self.clientAppMain.KOADB.WeatherStations.find_one({"name": stationName})["zip code"]

                weatherDict = {"name": values["Station Name"], "street": values["Station Street"],
                               "municipality": values["Station "
                                                      "Municipality"],
                               "state": values["Station State"],
                               "zip code": values["Station Zip Code"]}
                print("Station Updated:", weatherDict)
                self.clientAppMain.KOADB.WeatherStations.update_one({'_id': mongo_id}, {"$set": weatherDict},
                                                                    upsert=False)

                break
            if event == "Cancel" or event == sg.WIN_CLOSED:
                self.openWelcomeScreen(self.getSensors())
                break

        self.openWelcomeScreen(self.getSensors())

    # Returns all the weather stations.
    def getSensors(self):
        print("-getSensors-")
        sensors = []
        for x in self.clientAppMain.KOADB.WeatherStations.find({}, {"_id": 0, "name": 1}):
            sensors.append(x["name"])
        return sensors

    # Returns the current registered user utilizing the console.
    def getCurrentUser(self):
        print("-getCurrentUser-")
        return self._userName

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
                verifyPW = self.check_password(entry.encode('utf-8'), PWs.encode('utf-8'))
                return verifyPW
            else:
                return False
        except Exception as e:
            print("Exception caught when trying to verify credentials with MongoDB.")
            print("Exception message:", e)
            return False

    # Finds the document id within a collection in the MongoDB client "db".
    def getDocumentID(self, collectionName, fieldName, fieldEntry):
        collection = self.clientAppMain.KOADB[collectionName]
        cursor = collection.find_one({fieldName: fieldEntry})
        return cursor["_id"]

    def retrieveMongoDocument(self, collectionName, searchFieldName, searchFieldValue):

        print("Searching for", searchFieldName, "with a value of", searchFieldValue, "in collection",
              collectionName + ".")
        cursor = [i for i in self.clientAppMain.KOADB[collectionName].find({searchFieldName: (searchFieldValue)})]
        return cursor

    def on_window_close(self):
        print("User has disconnected.")
        self._stop_update_flag = True
        try:
            for ws in self.websockets:
                ws.close()
        except Exception as e:
            print("No sockets to close.")


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
    parseConfiguration("False")
