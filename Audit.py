"""
Copyright 2017 Akamai Technologies, Inc. All Rights Reserved.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""

"""
This code leverages akamai OPEN API. to control Certificates deployed in Akamai Network.
In case you need quick explanation contact the initiators.
Initiators: vbhat@akamai.com
"""

import json
import webbrowser
from prettytable import PrettyTable
import sys
from akamai.edgegrid import EdgeGridAuth, EdgeRc
from PapiWrapper import PapiWrapper
import argparse
import configparser
import requests
import os
import logging
import helper
import re
import dns.resolver 
import subprocess
import datetime
from datetime import date
import dns
from dns import resolver


PACKAGE_VERSION = "1.0.8"

# Setup logging
if not os.path.exists('logs'):
    os.makedirs('logs')
log_file = os.path.join('logs', 'ruleupdater.log')

# Set the format of logging in console and file separately
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_formatter = logging.Formatter("%(message)s")
root_logger = logging.getLogger()

logfile_handler = logging.FileHandler(log_file, mode='a')
logfile_handler.setFormatter(log_formatter)
root_logger.addHandler(logfile_handler)

console_handler = logging.StreamHandler()
console_handler.setFormatter(console_formatter)
root_logger.addHandler(console_handler)
# Set Log Level to DEBUG, INFO, WARNING, ERROR, CRITICAL
root_logger.setLevel(logging.INFO)


def init_config(edgerc_file, section):
    if not edgerc_file:
        if not os.getenv("AKAMAI_EDGERC"):
            edgerc_file = os.path.join(os.path.expanduser("~"), '.edgerc')
        else:
            edgerc_file = os.getenv("AKAMAI_EDGERC")

    if not os.access(edgerc_file, os.R_OK):
        root_logger.error("Unable to read edgerc file \"%s\"" % edgerc_file)
        exit(1)

    if not section:
        if not os.getenv("AKAMAI_EDGERC_SECTION"):
            section = "papi"
        else:
            section = os.getenv("AKAMAI_EDGERC_SECTION")


    try:
        edgerc = EdgeRc(edgerc_file)
        base_url = edgerc.get(section, 'host')

        session = requests.Session()
        session.auth = EdgeGridAuth.from_edgerc(edgerc, section)

        return base_url, session
    except configparser.NoSectionError:
        root_logger.error("Edgerc section \"%s\" not found" % section)
        exit(1)
    except Exception:
        root_logger.info(
            "Unknown error occurred trying to read edgerc file (%s)" %
            edgerc_file)
        exit(1)


def cli():
    prog = get_prog_name()
    if len(sys.argv) == 1:
        prog += " [command]"

    parser = argparse.ArgumentParser(
        description='Akamai CLI for Property/hostname(s) Audits',
        add_help=False,
        prog=prog)
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s ' +
                PACKAGE_VERSION)

    subparsers = parser.add_subparsers(
        title='Commands', dest="command", metavar="")

    actions = {}

    subparsers.add_parser(
        name="help",
        help="Show available help",
        add_help=False).add_argument(
        'args',
        metavar="",
        nargs=argparse.REMAINDER)

    actions["list_groups"] = create_sub_command(
        subparsers,
        "list-groups",
        "List groups",
        [],
        [])

    actions["list_properties"] = create_sub_command(
        subparsers, "list-properties", "List all the properties",
        [{"name": "groupId", "help": "Group Id. It may or maynot have the grp_ prefix"},
         {"name": "groupName", "help": "Name of the Group"}],
        [])

    actions["check_hostnames"] = create_sub_command(
        subparsers, "check-hostnames", "Check hostnames to be onboarded",
        [{"name": "hostnames", "help": "List of hostnames separated by comma or space within quotes"},
         {"name": "file", "help": "A csv file with hostnames (No title line)"}],
        [])

    actions["check_cert_expiry"] = create_sub_command(
        subparsers, "check-cert-expiry", "Check expiration of certificates",
        [{"name": "groupId", "help": "List of hostnames separated by comma or space within quotes"},
         {"name": "groupName", "help": "Name of the Group"}],
        [])

    actions["create_case"] = create_sub_command(
        subparsers, "create-case", "Create Akatec Case",
        [{"name": "groupId", "help": "List of hostnames separated by comma or space within quotes"},
         {"name": "groupName", "help": "Name of the Group"}],
        [])

    args = parser.parse_args()

    if len(sys.argv) <= 1:
        parser.print_help()
        return 0

    if args.command == "help":
        if len(args.args) > 0:
            if actions[args.args[0]]:
                actions[args.args[0]].print_help()
        else:
            parser.prog = get_prog_name() + " help [command]"
            parser.print_help()
        return 0


    # Override log level if user wants to run in debug mode
    # Set Log Level to DEBUG, INFO, WARNING, ERROR, CRITICAL
    if args.debug:
        root_logger.setLevel(logging.DEBUG)

    return getattr(sys.modules[__name__], args.command.replace("-", "_"))(args)


def create_sub_command(
        subparsers,
        name,
        help,
        optional_arguments=None,
        required_arguments=None):
    action = subparsers.add_parser(name=name, help=help, add_help=False)

    if required_arguments:
        required = action.add_argument_group("required arguments")
        for arg in required_arguments:
            name = arg["name"]
            del arg["name"]
            required.add_argument("--" + name,
                                  required=True,
                                  **arg)

    optional = action.add_argument_group("optional arguments")
    if optional_arguments:
        for arg in optional_arguments:
            name = arg["name"]
            del arg["name"]
            if name == 'insertAfter' or name == 'insertBefore' or name == 'insertLast' \
            or name == 'addVariables':
                optional.add_argument(
                    "--" + name,
                    required=False,
                    **arg,
                    action="store_true")
            else:
                optional.add_argument("--" + name,
                                      required=False,
                                      **arg)

    optional.add_argument(
        "--edgerc",
        help="Location of the credentials file [$AKAMAI_EDGERC]",
        default=os.path.join(
            os.path.expanduser("~"),
            '.edgerc'))

    optional.add_argument(
        "--section",
        help="Section of the credentials file [$AKAMAI_EDGERC_SECTION]",
        default="papi")

    optional.add_argument(
        "--debug",
        help="DEBUG mode to generate additional logs for troubleshooting",
        action="store_true")

    optional.add_argument(
        "--account-key",
        help="Account Switch Key",
        default="")

    return action

def tabulate(title, columns, data, filename):
    fancy_table = '''
                <head>
                    <link href="https://unpkg.com/tabulator-tables@4.9.3/dist/css/tabulator.min.css" rel="stylesheet">
                    <script type="text/javascript" src="https://unpkg.com/tabulator-tables@4.9.3/dist/js/tabulator.min.js"></script>
                    <script type="text/javascript" src="https://oss.sheetjs.com/sheetjs/xlsx.full.min.js"></script>
                    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/1.3.5/jspdf.min.js"></script>
                    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.0.5/jspdf.plugin.autotable.js"></script>

                </head>

                <body>
                    <div>
                        <button id="download-csv">Download CSV</button>
                        <button id="download-json">Download JSON</button>
                        <button id="download-xlsx">Download XLSX</button>
                        <button id="download-pdf">Download PDF</button>
                        <button id="download-html">Download HTML</button>
                    </div>                
                    <h2>%s</h2>
                    <div id="example-table"></div>

                    <script>
                            var table = new Tabulator("#example-table", {
                            height:"700px",
                            layout:"fitColumns",
                            pagination:"local",
                            paginationSize:100,
                            paginationSizeSelector:[25, 50, 100],
                            movableColumns:true,
                            columns: %s,
                            });

                            var None = 'None'
                            var tableData = %s

                            table.setData(tableData);            

                            //trigger download of data.csv file
                            document.getElementById("download-csv").addEventListener("click", function(){
                                table.download("csv", "data.csv");
                            });

                            //trigger download of data.json file
                            document.getElementById("download-json").addEventListener("click", function(){
                                table.download("json", "data.json");
                            });

                            //trigger download of data.xlsx file
                            document.getElementById("download-xlsx").addEventListener("click", function(){
                                table.download("xlsx", "data.xlsx", {sheetName:"My Data"});
                            });

                            //trigger download of data.pdf file
                            document.getElementById("download-pdf").addEventListener("click", function(){
                                table.download("pdf", "data.pdf", {
                                    orientation:"portrait", //set page orientation to portrait
                                    title:"Example Report", //add title to report
                                });
                            });

                            //trigger download of data.html file
                            document.getElementById("download-html").addEventListener("click", function(){
                                table.download("html", "data.html", {style:true});
                            });                            
                    </script>    

                </body>
        ''' % (title, columns, data)

    with open(filename,'w') as tab_file_handler:
        tab_file_handler.write(fancy_table)

    webbrowser.open_new_tab('file://' + os.path.realpath(filename))  

def list_groups(args):
    access_hostname, session = init_config(args.edgerc, args.section)
    papiObject = PapiWrapper(access_hostname, args.account_key)

    table = PrettyTable(['Group Name', 'Group ID'])
    table.align = "l"
    
    groupsResponse = papiObject.getGroups(session)
    #Find the property details (IDs)
    if groupsResponse.status_code == 200:
        groupsResponseDetails = groupsResponse.json()
        for everyGroup in groupsResponseDetails['groups']['items']:
            rowData = []
            rowData.append(everyGroup['groupName'])
            rowData.append(everyGroup['groupId'])
            table.add_row(rowData)
        print(table)   
        columns = '''
                    [
                        {title:"Group Name", field:"groupName", headerFilter:"input"},
                        {title:"Group ID", field:"groupId", hozAlign:"center", sorter:"date",  headerFilter:"input"},
                    ]
        '''       
        title = 'Group Audit Report'     
        tabulate(title, columns, groupsResponseDetails['groups']['items'], 'groups_info.html') 
            
    else:
       root_logger.info('Unable to fetch group details\n')
       

def process_properties(session, papiObject, everyGroup, all_properties):
    root_logger.info('  ..Processing the group: ' + everyGroup['groupName'])                    
    properties_response = papiObject.getAllProperties(session,everyGroup['contractIds'][0],everyGroup['groupId'])
    root_logger.info('      ..Total of ' + str(len(properties_response.json()['properties']['items'])) + ' properties found.')
    counter = 1
    for everyProperty in properties_response.json()['properties']['items']:
        root_logger.info('          ..Processing ' + str(counter) + ' of ' + str(len(properties_response.json()['properties']['items'])))
        counter += 1
        everyProperty['groupName'] = everyGroup['groupName']

        #Get the hostnames of latest version
        hostname_list = []
        if everyProperty['latestVersion']:
            hostnames_response = papiObject.listHostnames(session, everyProperty['propertyId'], everyProperty['latestVersion'], everyProperty['contractId'], everyProperty['groupId'])
            if hostnames_response.status_code == 200:
                hostnames = hostnames_response.json()['hostnames']['items']
                hostname_list = []
                for every_hostname in hostnames:
                    hostname_list.append(every_hostname['cnameFrom'])
            else:
                root_logger.info('Unable to fetch hostnames\n')        
            everyProperty['lat_hostnames'] = hostname_list 

        #Get the hostnames of staging version
        hostname_list = []
        if everyProperty['stagingVersion']:
            hostnames_response = papiObject.listHostnames(session, everyProperty['propertyId'], everyProperty['stagingVersion'], everyProperty['contractId'], everyProperty['groupId'])
            if hostnames_response.status_code == 200:
                hostnames = hostnames_response.json()['hostnames']['items']
                hostname_list = []
                for every_hostname in hostnames:
                    hostname_list.append(every_hostname['cnameFrom'])
            else:
                root_logger.info('Unable to fetch hostnames\n')        
            everyProperty['stg_hostnames'] = hostname_list 

        #Get the hostnames of production version
        hostname_list = []
        if everyProperty['productionVersion']:
            hostnames_response = papiObject.listHostnames(session, everyProperty['propertyId'], everyProperty['productionVersion'], everyProperty['contractId'], everyProperty['groupId'])
            if hostnames_response.status_code == 200:
                hostnames = hostnames_response.json()['hostnames']['items']
                hostname_list = []
                for every_hostname in hostnames:
                    hostname_list.append(every_hostname['cnameFrom'])
            else:
                root_logger.info('Unable to fetch hostnames\n')        
            everyProperty['prd_hostnames'] = hostname_list                             

        all_properties.append(everyProperty)      
    return all_properties

#Function that returns hostnames list for certProvisioningType = DEFAULT
def list_cert_properties(session, papiObject, everyGroup, all_properties):
    root_logger.info('  ..Processing the group: ' + everyGroup['groupName'])                    
    properties_response = papiObject.getAllProperties(session,everyGroup['contractIds'][0],everyGroup['groupId'])
    root_logger.info('      ..Total of ' + str(len(properties_response.json()['properties']['items'])) + ' properties found.')
    counter = 1
    for everyProperty in properties_response.json()['properties']['items']:
        root_logger.info('          ..Processing ' + str(counter) + ' of ' + str(len(properties_response.json()['properties']['items'])))
        counter += 1
        everyProperty['groupName'] = everyGroup['groupName']

        #Get the hostnames of latest version
        hostname_list = []
        if everyProperty['latestVersion']:
            hostnames_response = papiObject.listHostnames(session, everyProperty['propertyId'], everyProperty['latestVersion'], everyProperty['contractId'], everyProperty['groupId'])
            if hostnames_response.status_code == 200:
                hostnames = hostnames_response.json()['hostnames']['items']
                hostname_list = []
                for every_hostname in hostnames:
                    if every_hostname['certProvisioningType'] == 'DEFAULT':
                        hostname_list.append(every_hostname['cnameFrom'])
            else:
                root_logger.info('Unable to fetch hostnames\n')        
        everyProperty['lat_hostnames'] = hostname_list 

        #Get the hostnames of staging version
        hostname_list = []
        if everyProperty['stagingVersion']:
            hostnames_response = papiObject.listHostnames(session, everyProperty['propertyId'], everyProperty['stagingVersion'], everyProperty['contractId'], everyProperty['groupId'])
            if hostnames_response.status_code == 200:
                hostnames = hostnames_response.json()['hostnames']['items']
                hostname_list = []
                for every_hostname in hostnames:
                    if every_hostname['certProvisioningType'] == 'DEFAULT':
                        hostname_list.append(every_hostname['cnameFrom'])
            else:
                root_logger.info('Unable to fetch hostnames\n')        
        everyProperty['stg_hostnames'] = hostname_list 

        #Get the hostnames of production version
        hostname_list = []
        if everyProperty['productionVersion']:
            hostnames_response = papiObject.listHostnames(session, everyProperty['propertyId'], everyProperty['productionVersion'], everyProperty['contractId'], everyProperty['groupId'])
            if hostnames_response.status_code == 200:
                #print(json.dumps(hostnames_response.json(), indent=4))
                hostnames = hostnames_response.json()['hostnames']['items']
                hostname_list = []
                for every_hostname in hostnames:
                    if every_hostname['certProvisioningType'] == 'DEFAULT':
                        hostname_list.append(every_hostname['cnameFrom'])
            else:
                root_logger.info('Unable to fetch hostnames\n')        
        everyProperty['prd_hostnames'] = hostname_list                             

        all_properties.append(everyProperty)      
    return all_properties

def list_properties(args):
    access_hostname, session = init_config(args.edgerc, args.section)
    papiObject = PapiWrapper(access_hostname, args.account_key)
    all_properties = []
    table = PrettyTable(['Group Name', 'Group ID'])
    table.align = "l"

    groupsResponse = papiObject.getGroups(session)
    #Find the property details (IDs)
    if groupsResponse.status_code == 200:
        groupsResponseDetails = groupsResponse.json()
        root_logger.info('Total of ' + str(len(groupsResponseDetails['groups']['items'])) + ' groups found')

        for everyGroup in groupsResponseDetails['groups']['items']:
            if not args.groupId and not args.groupName:
                list_of_properties = process_properties(session, papiObject, everyGroup, [])
                for every_property in list_of_properties:
                    all_properties.append(every_property)
            elif args.groupId:
                if args.groupId == everyGroup['groupId']:
                    root_logger.info('  ..Found the group: ' + str(args.groupId))
                    all_properties = process_properties(session, papiObject, everyGroup, [])                      
            elif args.groupName:
                if args.groupName in everyGroup['groupName']:
                    root_logger.info('  ..Found the group: ' + str(args.groupId))
                    all_properties = process_properties(session, papiObject, everyGroup, [])                     
            
        columns = '''
                    [
                        {title:"Property Name", field:"propertyName", headerFilter:"input"},
                        {title:"Group ID", field:"groupId", hozAlign:"center", sorter:"date",  headerFilter:"input"},
                        {title:"Group Name", field:"groupName", hozAlign:"center", sorter:"date",  headerFilter:"input"},
                        {title:"Contract ID", field:"contractId", hozAlign:"center", sorter:"date",  headerFilter:"input"},
                        {title:"Latest Version", field:"latestVersion", hozAlign:"center", sorter:"date",  headerFilter:"input"},
                        {title:"Latest Hostnames", field:"lat_hostnames", hozAlign:"center", sorter:"date",  headerFilter:"input", formatter:"textarea"},
                        {title:"Staging Version", field:"stagingVersion", hozAlign:"center", sorter:"date",  headerFilter:"input"},
                        {title:"Staging Hostnames", field:"stg_hostnames", hozAlign:"center", sorter:"date",  headerFilter:"input", formatter:"textarea"},
                        {title:"Production Version", field:"productionVersion", hozAlign:"center", sorter:"date",  headerFilter:"input"},
                        {title:"Production Hostnames", field:"prd_hostnames", hozAlign:"center", sorter:"date",  headerFilter:"input", formatter:"textarea"},
                    ]
        '''    
        title = 'Property Audit Report'        
        tabulate(title, columns, all_properties, 'properties.html') 
            
    else:
        root_logger.info('Unable to fetch group details\n')
            
def check_hostnames(args):
    access_hostname, session = init_config(args.edgerc, args.section)
    papiObject = PapiWrapper(access_hostname, args.account_key)

    table = PrettyTable(['Hostname', 'Configuration Name',' Property Id', 'Group ID','EdgeHostname','Waf Status'])
    table.align = "l"

    hostnames = args.hostnames.replace(',',':').replace(' ',':').replace('::',':').split(':')
    
    print('Finding details of hostname(s)\n')
    final_data = []
    columns = '''
                [
                    {title:"Hostname", field:"hostname", headerFilter:"input"},
                    {title:"Status", field:"status", hozAlign:"center", headerFilter:"input", formatter:"tickCross"},
                    {title:"Account ID", field:"accountId", headerFilter:"input"},
                    {title:"Property Name", field:"propertyName", headerFilter:"input"},
                    {title:"Property Id", field:"propertyId", headerFilter:"input"},
                    {title:"Group ID", field:"groupId", hozAlign:"center", sorter:"date",  headerFilter:"input"},
                    {title:"Contract ID", field:"contractId", hozAlign:"center", sorter:"date",  headerFilter:"input"},
                    {title:"Version", field:"propertyVersion", hozAlign:"center", sorter:"date",  headerFilter:"input"},
                    {title:"Staging Status", field:"stagingStatus", hozAlign:"center", sorter:"date",  headerFilter:"input", formatter:"textarea"},
                    {title:"Prod Status", field:"productionStatus", hozAlign:"center", sorter:"date",  headerFilter:"input"}
                ]
    '''    
    title = 'Hostname Audit Report'   

    for each_hostname in hostnames:
        print('Processing ' + each_hostname + ' ...')
        #Send a request to Akamai network to check for 200

        url = "https://" + each_hostname + "/"
        stream = os.popen('curl -s -o /dev/null -w "%{http_code}" -k --connect-to ::e1.a.akamaiedge-staging.net ' + url)
        output = stream.read()
        if str(output) != str(400):    
            hostname_response = papiObject.searchProperty(session, propertyName='optional', hostname=each_hostname, edgeHostname='optional')
            #print(json.dumps(hostname_response.json(), indent=4))

            if hostname_response.status_code == 200:
                if len(hostname_response.json()['versions']['items']) > 0:    
                    for every_hostname_detail in hostname_response.json()['versions']['items']:    
                        final_data.append(every_hostname_detail)
                else:
                    print(' ..Not found in your account.\n')        
                    hostname_details = {}
                    hostname_details['hostname'] = each_hostname
                    hostname_details['accountId'] = 'Unknown'
                    final_data.append(hostname_details)

        else:
            hostname_details = {}
            hostname_details['hostname'] = each_hostname
            hostname_details['status'] = 1
            final_data.append(hostname_details)
            print(' ..' + each_hostname + ' is good to onbaord.')                        

    #Tabulate after processing all hostnames
    tabulate(title, columns, final_data, 'hostnames.html') 


def check_cert_expiry(args):
    access_hostname, session = init_config(args.edgerc, args.section)
    papiObject = PapiWrapper(access_hostname, args.account_key)
    all_properties = []
    table = PrettyTable(['Group Name', 'Group ID'])
    table.align = "l"

    groupsResponse = papiObject.getGroups(session)
    #Find the property details (IDs)
    if groupsResponse.status_code == 200:
        groupsResponseDetails = groupsResponse.json()
        root_logger.info('Total of ' + str(len(groupsResponseDetails['groups']['items'])) + ' groups found')

        for everyGroup in groupsResponseDetails['groups']['items']:
            if not args.groupId and not args.groupName:
                list_of_properties = list_cert_properties(session, papiObject, everyGroup, [])
                for every_property in list_of_properties:
                    all_properties.append(every_property)
            elif args.groupId:
                if args.groupId == everyGroup['groupId']:
                    root_logger.info('  ..Found the group: ' + str(args.groupId))
                    all_properties = list_cert_properties(session, papiObject, everyGroup, [])                      
            elif args.groupName:
                if args.groupName in everyGroup['groupName']:
                    root_logger.info('  ..Found the group: ' + str(args.groupId))
                    all_properties = list_cert_properties(session, papiObject, everyGroup, [])  
                    #print(json.dumps(all_properties, indent=4))  
        
        final_list_of_properties = []
        format = "%b %d %H:%M:%S %Y GMT"

        for every_property in all_properties:
            if 'prd_hostnames' in every_property:
                if len(every_property['prd_hostnames']) != 0:    
                    #print(json.dumps(every_property, indent=4))
                    #Split the hostnames as seperate item
                    for every_hostname in every_property['prd_hostnames']:
                        #print(every_hostname)
                        individual_item = dict(every_property)
                        del individual_item['lat_hostnames']
                        del individual_item['stg_hostnames']
                        del individual_item['prd_hostnames']
                        individual_item['hostname'] = every_hostname

                        host_port = every_hostname + ':443'
                        #command = ['echo', '|', 'openssl', 's_client', '-servername', every_hostname, '-connect', host_port, '2>/dev/null', '|', 'openssl', 'x509', '-noout', '-dates', '|' ,'grep', 'notAfter']
                        command = 'echo | openssl s_client -servername ' + every_hostname + ' -connect ' + host_port + ' 2>/dev/null | openssl x509 -noout -dates | grep notAfter'
                        expiry_date = str(subprocess.Popen(command, shell=True, stdout=subprocess.PIPE).stdout.read())
                        if 'notAfter' in expiry_date:
                            expiry_date = expiry_date.split('=')[1].split('\\')[0]
                        else:
                            expiry_date = 'Invalid Certificate'
                        
                        #Calculate the diff
                        if expiry_date != 'Invalid Certificate':
                            expiry_date_obj = datetime.datetime.strptime(expiry_date, format).date()
                            current_date = date.today()
                            remaining_days = abs((expiry_date_obj - current_date).days)
                        else:
                            remaining_days = 'N/A'

                        #Add expiry info to dict    
                        individual_item['expiry'] = expiry_date
                        individual_item['remainingDays'] = remaining_days

                        #Check CAA record of toplevel domain
                        individual_item['CAA'] = 'N/A'
                        try:
                            domain = every_hostname.partition(".")[-1]
                            result = dns.resolver.query(domain, 'CAA')
                            for val in result:
                                print('CAA: ', val.to_text())
                                individual_item['CAA'] =  val.to_text()
                        except:
                            print('             ..CAA record not found for: ' + domain)        

                        #Append new item to final list
                        final_list_of_properties.append(individual_item)                    

                else:
                    #No hostnames found
                    pass
            else:
                #No SBD hostnames
                pass

        #print(json.dumps(final_list_of_properties, indent=4))        
            
        columns = '''
                    [
                        {title:"Property Name", field:"propertyName", headerFilter:"input"},
                        {title:"Group ID", field:"groupId", hozAlign:"center", sorter:"date",  headerFilter:"input"},
                        {title:"Group Name", field:"groupName", hozAlign:"center", sorter:"date",  headerFilter:"input"},
                        {title:"Contract ID", field:"contractId", hozAlign:"center", sorter:"date",  headerFilter:"input"},
                        {title:"Staging Version", field:"stagingVersion", hozAlign:"center", sorter:"date",  headerFilter:"input"},
                        {title:"Production Version", field:"productionVersion", hozAlign:"center", sorter:"date",  headerFilter:"input"},
                        {title:"Hostname", field:"hostname", hozAlign:"center", sorter:"date",  headerFilter:"input", formatter:"textarea"},
                        {title:"Expiry", field:"expiry", hozAlign:"center", sorter:"date",  headerFilter:"input"},
                        {title:"Reamaining Days", field:"remainingDays", hozAlign:"center", sorter:"date",  headerFilter:"input", headerFilterPlaceholder:"<=",headerFilterFunc:"<="},
                        {title:"CAA", field:"CAA", hozAlign:"center", sorter:"date",  headerFilter:"input"}
                    ]
        '''    
        title = 'Property Audit Report'        
        tabulate(title, columns, final_list_of_properties, 'properties.html') 
            
    else:
        root_logger.info('Unable to fetch group details\n')                        


def create_case(args):
    access_hostname, session = init_config(args.edgerc, args.section)
    papiObject = PapiWrapper(access_hostname, args.account_key)

    all_properties = []
    groupsResponse = papiObject.getGroups(session)
    #Find the property details (IDs)
    if groupsResponse.status_code == 200:
        groupsResponseDetails = groupsResponse.json()
        root_logger.info('Total of ' + str(len(groupsResponseDetails['groups']['items'])) + ' groups found')

        for everyGroup in groupsResponseDetails['groups']['items']:
            if not args.groupId and not args.groupName:
                list_of_properties = list_cert_properties(session, papiObject, everyGroup, [])
                for every_property in list_of_properties:
                    all_properties.append(every_property)
            elif args.groupId:
                if args.groupId == everyGroup['groupId']:
                    root_logger.info('  ..Found the group: ' + str(args.groupId))
                    all_properties = list_cert_properties(session, papiObject, everyGroup, [])                      
            elif args.groupName:
                if args.groupName in everyGroup['groupName']:
                    root_logger.info('  ..Found the group: ' + str(args.groupId))
                    all_properties = list_cert_properties(session, papiObject, everyGroup, [])  
        
        #Loop through all properties
        for every_property in all_properties:
            if every_property['productionVersion'] is None:
                #Create a case
                case_body = '''
                    {
                        "severity": "2-Major",
                        "subject": "Property version being NULL",
                        "description": "Property version being NULL",
                        "categoryType": "Technical",
                        "questionnaire": {
                            "questionnaireId": "100",
                            "questions": [
                                {
                                    "questionId": "670",
                                    "currentAnswers": [
                                        "2015-11-29T11:58:53.273Z"
                                    ]
                                },
                                {
                                    "questionId": "671",
                                    "currentAnswers": [
                                        "986"
                                    ]
                                }
                            ]
                        },
                        "userDetail": {
                            "userName": "Salesforce IAT",
                            "userPhone": "080398137489",
                            "userEmail": "dl-salesforce-iat@akamai.com",
                            "userCompany": "Akamai"
                        },
                        "subCategories": [
                            {
                                "displayName": "Product",
                                "subCategoryType": "product",
                                "subCategoryValue": "Alta"
                            },
                            {
                                "displayName": "Problem",
                                "subCategoryType": "problem",
                                "subCategoryValue": "Alerts"
                            }
                        ]
                    }
                '''

                print('Creating a case now...')
                caseResponse = papiObject.createCase(session, case_body)
                if caseResponse.status_code == 200:
                    print('Case created with case ID: ' + caseResponse.json()['caseId'])
                else:
                    print('Failed to create Akatec case')
            else:
                #All versions are fine
                pass
            
    else:
        root_logger.info('Unable to fetch group details\n')                        



def get_prog_name():
    prog = os.path.basename(sys.argv[0])
    if os.getenv("AKAMAI_CLI"):
        prog = "akamai ruleupdater"
    return prog


def get_cache_dir():
    if os.getenv("AKAMAI_CLI_CACHE_DIR"):
        return os.getenv("AKAMAI_CLI_CACHE_DIR")

    return os.curdir

# Final or common Successful exit
if __name__ == '__main__':
    try:
        status = cli()
        exit(status)
    except KeyboardInterrupt:
        exit(1) 