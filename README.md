# KOA-Management-Console
### PySimpleGUI: https://github.com/PySimpleGUI/PySimpleGUI#installing--
#### Flask: https://palletsprojects.com/p/flask/

In order for the app to work you will need to set up a configuration file with the valid credentials. 
Example template:
----
[MongoDB Configuration] <br>
client_connection = mongodb+srv://--AWS access key--:--AWS secret key--@--your cluster--.mongodb.net/?authSource=%24external&authMechanism=MONGODB-AWS&retryWrites=true <br>
                             

[WebUI Configuration] <br>
web_ui_port = port number for Flask to run on. <br>

[M5Stack Configuration] <br>
m5_aws_access = AWS access key <br>
m5_aws_secret = AWS secret key <br>
bucket_name = AWS m5 bucket name <br>
refreshInterval = # of seconds <br>
#refreshInterval is in seconds. <br>

[Twitter Configuration] <br>
consumer_key = Twitter API consumer key <br>
consumer_secret = Twitter API consumer secret <br>
access_key = Twitter OAuth access key <br>
access_secret = Twitter OAuth access secret <br>
callback uri = twitter callback uri <br>

----
Upon running the Flask server for the first time you will be prompted to select a valid configuration file. If any of the parameters are missing it will not accept that configuration file. The program will make a copy of the configuration file that you selected and will format it accordingly so it can be parsed by Python. Formatting is especially crucial for the MongoDB URI.

### Deployment
To deploy the project first run startApp.bat, this will install all of the required Python modules for the program to function.
If you are running on a non-Windows system, you can deploy the app with these commands:

First install the required modules.
pip install -r requirements.txt

Then run the Python app.
"python" .\app_main.py"
  
----
##### A program log will be stored in the \static folder for reference.
----

A valid MongoDB is required, with KOADB being the database cluster utilized by the program and the follow collections need to be present:

- ManagementUsers
- WeatherStationData
- WeatherStations

----

Note that the MongoDB URI we have in the template is utilizing AWS IAM. You can find a guide on setting that up here:
https://www.mongodb.com/docs/atlas/security/passwordless-authentication/
