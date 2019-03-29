# Phishing-Pharming_NeuralNetwork
==================================
Deep Learning project to classify website as phishy, not phishy and suspicious.
This is help for people looking forward to build an extension for detecting suspicious websites. For Pharming detection i.e. DNS/IP address based phishing detection we go for IP address comparison from local and reference DNS and webpage screenshots comparison using imgkit.

## Getting Started
These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. 

## Prerequisites
Python 3.6
wkhtmltoimage.exe from https://wkhtmltopdf.org/downloads.html
Flask

## Installing
Upload the Chrome Extension folder in your browser:
Settings > More Tools > Extensions > Developer mode > Load unpacked > Upload the folder(ChromeExtension)
After uploading is complete, activate it.


Set the location to the APP folder(folder with all python files, model.h5 file and scalar.save file for loading weights).Run the app.py file to get the flask app started using these commands:
~ mukul$ export FLASK_APP=app.py
~ mukul$ flask run --host=0.0.0.0

The extension icon shall change and get updated to green tick(legitimate), red cross(phishy) and orange cross(suspicious).
