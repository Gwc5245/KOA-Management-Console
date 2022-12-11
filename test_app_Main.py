import unittest
import app_Main as appMain
from mock import patch, MagicMock
import configparser
import hashlib
import logging
import os
import re
import shutil
import signal
import tweepy

from datetime import timedelta, datetime

import threading, time, signal

import PySimpleGUI as sgd
import boto3
import json

from pymongo.server_api import ServerApi

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
import pynguin
from pathlib import Path
import tweepy


class TestAppMain(unittest.TestCase):
    def negator(*args, title=None, button_color=None, background_color=None, text_color=None,
                auto_close=False,
                auto_close_duration=None, custom_text=(None, None), non_blocking=False, icon=None, line_width=None,
                font=None, no_titlebar=False, grab_anywhere=False,
                keep_on_top=None, location=(None, None), relative_location=(None, None), any_key_closes=False,
                image=None,
                modal=True):
        keep_on_top
        pass

    @patch("app_Main.sgd.Popup", negator)
    # Tests whether function successfully can detect an invalid configuration file.
    def test_checkConfig(self):
        self.assertEqual(appMain.checkConfig(), (False))

    # Tests whether startMongo method handles an invalid client configuration correctly.
    # This should return false if there is an invalid MongoDB URI.
    def test_startMongo(self):
        client = pymongo.MongoClient("mongodb+srv://<AWS access key>:<AWS secret key>@cluster0"
                                     ".re3ie7p.mongodb.net/?authSource=%24external&authMechanism=MONGODB-AWS&retryWrites=true"
                                     "&w=majority", server_api=ServerApi('1'))
        self.assertEqual(appMain.startMongo(client), (False))

    # Tests the parseConfiguration method whether it will catch an invalid configuration.
    # A blank configuration file is passed as the test configuration.
    @patch("app_Main.configurator", negator)
    def test_parseConfiguration(self):
        self.assertEqual(appMain.parseConfiguration("Invalidfile.ini"), (False, "No section: 'MongoDB Configuration'"))

    # Tests the startMongoNoCheck method for detection of an invalid Mongo database.
    # If the database is not present this should return that there is no KOADB collection in the Mongo cluster.
    @patch("app_Main.startMongoNoCheck", negator)
    def test_getSensors(self):
        self.assertEqual(appMain.getSensors(), (False, "'NoneType' object has no attribute 'KOADB'"))


if __name__ == '__main__':
    unittest.main()
