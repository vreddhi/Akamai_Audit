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
import shutil


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
        description='Akamai CLI for RuleUpdater',
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
    root_logger.info('Total of ' + str(len(properties_response.json()['properties']['items'])) + ' properties found.')
    counter = 1
    for everyProperty in properties_response.json()['properties']['items']:
        root_logger.info('  ..Processing ' + str(counter) + ' of ' + str(len(properties_response.json()['properties']['items'])))
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

def list_properties(args):
    access_hostname, session = init_config(args.edgerc, args.section)
    papiObject = PapiWrapper(access_hostname, args.account_key)

    table = PrettyTable(['Group Name', 'Group ID'])
    table.align = "l"

    groupsResponse = papiObject.getGroups(session)
    #Find the property details (IDs)
    if groupsResponse.status_code == 200:
        groupsResponseDetails = groupsResponse.json()
        root_logger.info('Total of ' + str(len(groupsResponseDetails['groups']['items'])) + ' groups found')
        counter = 1

        for everyGroup in groupsResponseDetails['groups']['items']:
            if not args.groupId and not args.groupName:
                all_properties = process_properties(session, papiObject, everyGroup, [])
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