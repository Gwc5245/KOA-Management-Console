import PySimpleGUI as sg


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
                _userName = values['Username']
                break

        window.close()
        # print('Username: ' + values['Username'])
        print('Username: ' + _userName)
        print('Password: ' + values['Password'])

    def openWelcomeScreen(self, stations):

        layout = [
            [sg.Text("KOA Management Console: Welcome.")],
            [sg.Text("Select Weather Station:")],
            [sg.Listbox(values=stations, select_mode='SINGLE', key='fac', size=(30, 6),
                        tooltip='Select a weather station to modify.')],
        ]
        window = sg.Window(title="KOA Management Console", layout=layout, margins=(500, 500)).read()

    def getSensors(self):
        return appWindowMain.stations


windowMain = appWindowMain()
windowMain.openLoginScreen()
# TODO: needs user verification prior to launching.
windowMain.openWelcomeScreen(windowMain.getSensors())
