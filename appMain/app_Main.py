import PySimpleGUI as sg

sg.theme("reddit")


class appWindowMain:
    _userName = ''
    stations = ["Station 1", "Station 2", "Station 3"]

    def openLoginScreen(self):
        layout = [
            [sg.Text("Please login to continue.")],
            [sg.Text('Username', size=(15, 1)), sg.InputText('', key='Username')],
            [sg.Text('Password', size=(15, 1)), sg.InputText('', key='Password', password_char='*')],
            [sg.Button("OK")]
        ]
        # window = sg.Window(title="KOA Management Console Login", layout=layout2, margins=(500, 500)).read()
        window = sg.Window(title="KOA Management Console Login", layout=layout)

        # label = tk.Label(text="KOA Management Console", fg="white", bg="black")
        # label.pack()
        # window.mainloop()
        while True:
            event, values = window.read()
            # End program if user closes window or
            # presses the OK button
            if event == "OK" or event == sg.WIN_CLOSED:
                self._userName = values['Username']
                break

        window.close()
        # print('Username: ' + values['Username'])
        print('Username: ' + self._userName)
        print('Password: ' + values['Password'])

    def openWelcomeScreen(self, stations):
        username = (self.getCurrentUser())
        layout = [
            [sg.Text("Welcome to the Management Dashboard, " + username.capitalize() + '.')],
            [sg.Text("Select Weather Station:")],
            [sg.Listbox(values=stations, select_mode='SINGLE', key='fac', size=(30, 6),
                        tooltip='Select a weather station to modify.')],
            [sg.Text("Select a menu option:")],
            [sg.Radio('Add Station', "RADIO1", default=False, key="-ADD-")],
            [sg.Radio('Modify Station', "RADIO1", default=False, key="-MODIFY-")],
            [sg.Button("OK")],
        ]
        # margins=(500, 500)
        window = sg.Window(title="KOA Management Console", layout=layout, )

        print('Username: ' + self.getCurrentUser())
        while True:
            event, values = window.read()
            if event == sg.WIN_CLOSED or event == "Exit":
                break
            elif values["-ADD-"]:
                print("Add is selected.")

    def getSensors(self):
        return appWindowMain.stations

    def getCurrentUser(self):
        return self._userName


windowMain = appWindowMain()
windowMain.openLoginScreen()
# TODO: needs user verification prior to launching.
windowMain.openWelcomeScreen(windowMain.getSensors())
