import tkinter as tk
import PySimpleGUI as sg


class appWindowMain:
    _userName = ''

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

    def openWelcomeScreen(self):
        layout = [
            [sg.Text("KOA Management Console: Welcome.")],
        ]
        window = sg.Window(title="KOA Management Console", layout=layout)


windowMain = appWindowMain()
windowMain.openLoginScreen()
