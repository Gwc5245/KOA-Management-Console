import tkinter as tk


class appWindowMain:
    def openLoginScreen(self):
        window = tk.Tk()
        label = tk.Label(text="KOA Management Console", fg="white", bg="black")
        label.pack()
        window.mainloop()


windowMain = appWindowMain()
windowMain.openLoginScreen()
