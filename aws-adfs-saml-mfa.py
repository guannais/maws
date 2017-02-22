#!/usr/bin/python

import sys
import boto.sts
import requests
import errno
import os
import datetime
import getpass
import configparser
import base64
import subprocess
import json
from datetime import datetime
import logging
import xml.etree.ElementTree as ET
import re
from bs4 import BeautifulSoup
from os.path import expanduser
from urllib.parse import urlparse, urlunparse
import argparse

##########################################################################
# Parse arguments from command line
 
parser = argparse.ArgumentParser(description='Ask for user specific information')

parser.add_argument('-c', '--configfile',
                    action="store", dest="awsconfigfile",
                    help="default AWS configfile, default is /.aws/credentials", default="/.aws/credentials")

parser.add_argument('-r', '--region',
                    action="store", dest="region",
                    help="default AWS region, default is eu-west-1", default="eu-west-1")
 
args = parser.parse_args()

##########################################################################
# Vars
##########################################################################

alias_roles_dic = {
    'arn:aws:iam::000000000001:role/ROLENAME01' : 'ROLEALIAS01',
    'arn:aws:iam::000000000002:role/ROLENAME02' : 'ROLEALIAS02',
    'arn:aws:iam::000000000003:role/ROLENAME03' : 'ROLEALIAS03',
    'arn:aws:iam::000000000004:role/ROLENAME04' : 'ROLEALIAS04'
}

regions_roles_dic = {
    'ROLEALIAS01' : 'us-west-1',
    'ROLEALIAS04' : 'us-west-1'
}

region_predefined = args.region
maws_bash_path = os.path.dirname(os.path.abspath(__file__)) + "/maws.sh -e"
domain = '****************'
idpentryurl = 'https://'+domain+'/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices'
filename = expanduser("~") + args.awsconfigfile

##########################################################################
# Vars
##########################################################################

def check_file_expiration_dates():

    global profile_expired

    profile_expired = 0

    config = configparser.ConfigParser()
    config.read(filename)
    alias_list = config.sections()

    if config.has_section('default'):
        alias_list.remove('default')

    alias_total = len(alias_list)

    if alias_total == 0:
        profile_expired = 1
    else:
        now = datetime.utcnow()
        i = 0
        while (i < alias_total) and (profile_expired == 0):
            expired_date = config.get(alias_list[i], 'expiration')
            expiration_date = datetime.strptime(expired_date, '%Y-%m-%dT%H:%M:%SZ')
            if expiration_date < now:
                profile_expired = 1
            i += 1

def username_password_login():

    global session
    global response
    global username

    # Get the federated credentials from the user
    username = input('Username: DOMAIN\\')
    username = 'DOMAIN\\' + username
    password = getpass.getpass()

    # Initiate session handler
    session = requests.Session()

    # Programmatically get the SAML assertion
    # Opens the initial IdP url and follows all of the HTTP302 redirects, and
    # gets the resulting login page
    formresponse = session.get(idpentryurl, verify=True, timeout=10)
    # Capture the idpauthformsubmiturl, which is the final url after all the 302s
    idpauthformsubmiturl = formresponse.url

    # Parse the response and extract all the necessary values
    # in order to build a dictionary of all of the form values the IdP expects
    formsoup = BeautifulSoup(formresponse.text, "html.parser")
    payload = {}

    for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
        name = inputtag.get('name', '')
        value = inputtag.get('value', '')
        if "user" in name.lower():
            #Make an educated guess that this is the right field for the username
            payload[name] = username
        elif "email" in name.lower():
            #Some IdPs also label the username field as 'email'
            payload[name] = username
        elif "pass" in name.lower():
            #Make an educated guess that this is the right field for the password
            payload[name] = password
        else:
            #Simply populate the parameter with the existing value
            #(picks up hidden fields in the login form)
            payload[name] = value

    for inputtag in formsoup.find_all(re.compile('(FORM|form)')):
        action = inputtag.get('action')
        actionURL = urlparse(action)
        if (actionURL.scheme == '' and actionURL.netloc == '') and actionURL.path:
            parsedurl = urlparse(idpentryurl)
            idpauthformsubmiturl = parsedurl.scheme + "://" + parsedurl.netloc + action
        else:
            idpauthformsubmiturl = action
    # Performs the submission of the IdP login form with the above post data
    response = session.post(idpauthformsubmiturl, data=payload, verify=True)

    # Overwrite and delete the credential variables, just for safety
    username = '##############################################'
    password = '##############################################'
    del username
    del password

    if 'errorText' in response.text:
        print('Error login or password incorrect.')
        sys.exit(0)

def check_if_mfa():

    global response

    if 'pin' not in response.text:
        print('No MFA login enable for user.')
        sys.exit(0)

def mfa_login():

    global session
    global response

    # Multi-Factor Authentication (MFA) Handle
    # Depending upon the MFA provider, you may replace
    # the string found in response.text to identify the MFA
    idpauthformsubmiturl = response.url
    otp = input('OTP: ')
    formsoup = BeautifulSoup(response.text, "html.parser")
    payload = {}
    for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
        name = inputtag.get('name', '')
        value = inputtag.get('value', '')
        if "pin" in name.lower():
            # OTP
            payload[name] = otp
        else:
            if "options" not in name.lower():
                # Disable options
                payload[name] = value
    # Performs the submission of the IdP login form with the above post data
    response = session.post(idpauthformsubmiturl, data=payload, verify=True)

def check_saml_mfa():

    global assertion

    # Decode the response and extract the SAML assertion
    soup = BeautifulSoup(response.text, "html.parser")

    assertion = ''

    # Look for the SAMLResponse attribute of the input tag (determined by
    # analyzing the debug print lines above)
    for inputtag in soup.find_all('input'):
        if inputtag.get('name') == 'SAMLResponse':
            #print(inputtag.get('value'))
            assertion = inputtag.get('value')

    # Better error handling is required for production use.
    if assertion == '':
        print('Response did not contain a valid SAML assertion. MFA must be wrong.')
        sys.exit(0)

def retrive_roles():

    global assertion
    global roles_ordered
    global awsroles

    # Parse the returned assertion and extract the authorized roles
    awsroles = []
    root = ET.fromstring(base64.b64decode(assertion))

    saml_urn_attribute_value = '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'
    for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        if saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role':
            for saml2attributevalue in saml2attribute.iter(saml_urn_attribute_value):
                awsroles.append(saml2attributevalue.text)

    # Note the format of the attribute value should be role_arn,principal_arn
    # but lots of blogs list it as principal_arn,role_arn so let's reverse
    # them if needed
    for awsrole in awsroles:
        chunks = awsrole.split(',')
        if'saml-provider' in chunks[0]:
            newawsrole = chunks[1] + ',' + chunks[0]
            index = awsroles.index(awsrole)
            awsroles.insert(index, newawsrole)
            awsroles.remove(awsrole)

def order_roles():

    global awsroles
    global roles_ordered

    # If I have more than one role, ask the user which one they want,
    # otherwise just proceed
    roles_list = []
    roles_ordered = []

    #print "please choose the role you would like to assume:"
    i = 1
    for awsrole in awsroles:
        finded = 0
        for alias_roles_dic_key, alias_roles_dic_value in alias_roles_dic.items():
            if awsrole.split(',')[0] == alias_roles_dic_key:
                role_predefined_region = region_predefined
                for regions_roles_dic_key, regions_roles_dic_value in regions_roles_dic.items():
                    if alias_roles_dic_value == regions_roles_dic_key:
                        role_predefined_region = regions_roles_dic_value
                        split00 = awsrole.split(',')[0]
                        split01 = awsrole.split(',')[1]
                roles_list.append((alias_roles_dic_value, split00, split01, role_predefined_region))
                finded = 1
        if finded == 0:
            split00 = awsrole.split(',')[0]
            split01 = awsrole.split(',')[1]
            roles_list.append(("NO_NAME_" + str(i), split00, split01, role_predefined_region))
            i += 1

    roles_ordered = sorted(roles_list, key=lambda x: x[0])

def write_config_file():

    global roles_ordered

    # Read in the existing config file
    config = configparser.RawConfigParser()
    config.read(filename)
    if not config.has_section('default'):
        config.add_section('default')
        config.set('default', 'output', '')
        config.set('default', 'region', '')
        config.set('default', 'aws_access_key_id', '')
        config.set('default', 'aws_secret_access_key', '')
        config.set('default', 'aws_session_token', '')
        config.set('default', 'expiration', '')
        # Write the updated config file
        with open(filename, 'w+') as configfile:
            config.write(configfile)

    i = 0
    for awsrole in roles_ordered:
        role_alias = roles_ordered[int(i)][0]
        role_access_key = roles_ordered[int(i)][1]
        role_secret_key = roles_ordered[int(i)][2]
        region = roles_ordered[int(i)][3]
        # Use the assertion to get an AWS STS token using Assume Role with SAML
        conn = boto.sts.connect_to_region(region)
        token = conn.assume_role_with_saml(role_access_key, role_secret_key, assertion)
        # Write the AWS STS token into the AWS credential file

        # Read in the existing config file
        config = configparser.RawConfigParser()
        config.read(filename)

        # Put the credentials into a specific profile instead of clobbering
        # the default credentials
        if not config.has_section(role_alias):
            config.add_section(role_alias)

        config.set(role_alias, 'output', 'json')
        config.set(role_alias, 'region', region)
        config.set(role_alias, 'aws_access_key_id', token.credentials.access_key)
        config.set(role_alias, 'aws_secret_access_key', token.credentials.secret_key)
        config.set(role_alias, 'aws_session_token', token.credentials.session_token)
        config.set(role_alias, 'expiration', format(token.credentials.expiration))

        # Write the updated config file
        with open(filename, 'w+') as configfile:
            config.write(configfile)
        i += 1

    config.remove_section('default')
    with open(filename, 'w+') as configfile:
        config.write(configfile)

def main():
    check_file_expiration_dates()
    if profile_expired == 1:
        username_password_login()
        check_if_mfa()
        mfa_login()
        check_saml_mfa()
        retrive_roles()
        order_roles()
        write_config_file()
    subprocess.call(maws_bash_path, shell=True)

if __name__ == "__main__":
    main()
