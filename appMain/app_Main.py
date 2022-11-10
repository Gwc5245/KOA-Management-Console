import hashlib
import json
import re

import PySimpleGUI as sg
import os

import bcrypt

import pymongo as pymongo
import us as us
from pymongo.server_api import ServerApi

path = os.path.abspath(__file__)
sg.theme("reddit")

# MongoDB connection



client = pymongo.MongoClient("mongodb+srv://<AWS access key>:<AWS secret key>@cluster0.re3ie7p.mongodb.net/?authSource=%24external&authMechanism=MONGODB-AWS&retryWrites=true&w=majority", server_api=ServerApi('1'))
db = client.KOADB
print("Collections: ", db.list_collection_names())
print("MongoDB info: ", client.server_info())


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
class appWindowMain:
    _userName = ''
    stations = ["Station 1", "Station 2", "Station 3"]

    # Opens the login screen that requests user's credentials.
    def openLoginScreen(self):
        print("My hash - " + calcHash())
        layout = [
            [sg.Text("Please login to continue.")],
            [sg.Text('Username', size=(15, 1)), sg.InputText('', key='Username')],
            [sg.Text('Password', size=(15, 1)), sg.InputText('', key='Password', password_char='*')],
            [sg.Button("OK")],
            [sg.Button("No Account?")]
        ]
        # window = sg.Window(title="KOA Management Console Login", layout=layout2, margins=(500, 500)).read()
        window = sg.Window(title="KOA Management Console Login", layout=layout)

        while True:
            event, values = window.read()
            # End program if user closes window or
            # presses the OK button
            if event == "OK":
                self._userName = values['Username']
                user = values["Username"]
                print("User I am searching for: ", user)
                userEquate = db.ManagementUsers.find({'Username': user})
                print("Verified? ", self.check_password_mongoDB(values["Password"], userEquate))
                break
            if event == sg.WIN_CLOSED:
                break
            if event == "No Account?":
                self.openSignupScreen()

        window.close()
        # print('Username: ' + values['Username'])
        print('Username: ' + self._userName)
        print('Password: ' + values['Password'])

    state_names = [state.name for state in us.states.STATES_AND_TERRITORIES]

    def openAddStation(self):
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
                db.WeatherStations.insert_one(weatherDict)
                self.refreshUI()
                break
            if event == "Cancel":
                window.close()
        window.close()

    # Opens the main dashboard that the user first sees after login, presenting to them a menu of options.
    def openWelcomeScreen(self, stations):
        username = (self.getCurrentUser())
        layout = [
            [sg.Text("Welcome to the Management Dashboard, " + username.capitalize() + '.')],
            [sg.Text("Select Weather Station:")],
            [sg.Listbox(values=stations, select_mode='SINGLE', key='stationsBox', size=(30, 6),
                        tooltip='Select a weather station to modify.')],
            [sg.Text("Select a menu option:")],
            [sg.Radio('Add Station', "RADIO1", default=False, key="-ADD-")],
            [sg.Radio('Modify Station', "RADIO1", default=False, key="-MODIFY-")],
            [sg.Button("OK")],
        ]
        # margins=(500, 500)
        self.welcomewindow = sg.Window(title="KOA Management Console", layout=layout, )

        print('Username: ' + self.getCurrentUser())
        while True:
            event, values = self.welcomewindow.read()
            if event == sg.WIN_CLOSED or event == "Exit":
                break
            elif values["-ADD-"]:
                print("Add is selected.")
                self.openAddStation()
            elif values["-MODIFY-"]:
                print("MODIFY is selected.")

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
                self.signupWindow.close()
                break

    # Returns all the weather stations.
    def getSensors(self):
        sensors = []
        for x in db.WeatherStations.find({}, {"_id": 0, "name": 1}):
            sensors.append(x["name"])
        return sensors

    # Returns the current registered user utilizing the console.
    def getCurrentUser(self):
        return self._userName

    def genSalt(self):

        # Open in "wb" mode to
        # write a new file, or
        # "ab" mode to append
        if not os.path.isfile("saltFile.txt"):
            with open("saltFile.txt", "wb") as binary_file:
                # Write bytes to file
                salt = bcrypt.gensalt()
                print("Salt: ", salt)

                binary_file.write(salt)
                print("Wrote salt file in ", os.getcwd())
        else:
            print("Salt file found.")

    # Retrieves the salt hash and returns the object.
    def getSalt(self):
        saltFile = open("saltFile.txt", "rb")
        salt = saltFile.read()
        saltFile.close()
        # listSaltByte = list(salt)
        # print("Retrieved salt from file. Salt: ", listSaltByte)
        return salt

    def refreshUI(self):
        self.welcomewindow['stationsBox'].update(self.getSensors())

    def get_hashed_password(self, plain_text_password):
        # Hash a password for the first time
        #   (Using bcrypt, the salt is saved into the hash itself)
        return bcrypt.hashpw(plain_text_password, bcrypt.gensalt())

    def check_password(self, plain_text_password, hashed_password):
        # Check hashed password. Using bcrypt, the salt is saved into the hash itself
        return bcrypt.checkpw(plain_text_password, hashed_password)

    def check_password_mongoDB(self, entry, userEquate):
        # userEquateList = list(userEquate)

        # userEquateListStr = ('{} {}'.format(i, ''))
        if userEquate != [""]:
            userEquateListStr = []
            records = dict((record['Password'], record) for record in userEquate)

            for i in records:
                userEquateListStr.append(i)
                print("Value in list: ", userEquateListStr)
            print("Checking password...")
            # print("PW ", userEquateList["Password"])
            PWs = ('{} {}'.format(userEquateListStr, ''))
            print("Type PW: ", type(PWs))
            PWs = repr(PWs)[4:-1]
            PWs = PWs[:-3]
            print("Type PW: ", type(PWs))
            print("PW: ", PWs, " Entry: ", entry.encode('utf-8'))
            verifyPW = self.check_password(entry.encode('utf-8'), PWs.encode('utf-8'))
            return verifyPW

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

windowMain = appWindowMain()
windowMain.genSalt()
windowMain.getSalt()
# windowMain.genTestStations()
windowMain.openLoginScreen()
# TODO: needs user verification prior to launching.
windowMain.openWelcomeScreen(windowMain.getSensors())
