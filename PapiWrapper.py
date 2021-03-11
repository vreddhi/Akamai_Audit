'''
// Good luck with this code. This leverages akamai OPEN API.
// In case you need
// explanation contact the initiators.
Initiators: vbhat@akamai.com and aetsai@akamai.com
'''

import json


__all__=['PapWrapper']

class PapiWrapper(object):
    """All basic operations that can be performed using PAPI """

    final_response = "NULL" #This variable holds the SUCCESS or FAILURE reason
    headers = {
        "Content-Type": "application/json"
    }

    access_hostname = "mandatory"
    property_name = "optional"
    version = "optional"
    notes = "optional"
    emails = "optional"
    groupId = "optional"
    contractId = "optional"
    propertyId = "optional"

    def __init__(self, access_hostname, account_switch_key, property_name = "optional", \
                version = "optional",notes = "optional", emails = "optional", \
                groupId = "optional", contractId = "optional", propertyId = "optional"):
        self.access_hostname = access_hostname
        self.property_name = property_name
        self.version = version
        self.notes = notes
        self.emails = emails
        self.groupId = groupId
        self.contractId = contractId
        self.propertyId = propertyId
        if account_switch_key != '':
            self.account_switch_key = '&accountSwitchKey=' + account_switch_key
        else:
            self.account_switch_key = ''        

    def getContracts(self,session):
        """
        Function to fetch all contracts

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        contractsResponse : contractsResponse
            (contractsResponse) Object with all details
        """
        contractsUrl = 'https://' + self.access_hostname + '/papi/v0/contracts/'
        contractsUrl = self.formUrl(contractsUrl)

        contractsResponse = session.get(contractsUrl)
        return contractsResponse

    def getPropertyInfo(self,session,property_name):
        """
        Function to fetch property ID and update the proerty object with corresponding values

        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object
        property_name: <string>
            Property or configuration name

        Returns
        -------
        self : self
            (PapiWrapper) Object with propertyId, contractId and groupId as attributes
        """
        groupsInfo = self.getGroups(session)
        for eachDataGroup in groupsInfo.json()['groups']['items']:
            try:
                contractIdList = eachDataGroup['contractIds']
                for contractId in contractIdList:
                    groupId = eachDataGroup['groupId']
                    url = 'https://' + self.access_hostname + '/papi/v0/properties/?contractId=' + contractId +'&groupId=' + groupId
                    propertiesResponse = session.get(url)
                    if propertiesResponse.status_code == 200:
                        propertiesResponseJson = propertiesResponse.json()
                        propertiesList = propertiesResponseJson['properties']['items']
                        for propertyInfo in propertiesList:
                            propertyName = propertyInfo['propertyName']
                            propertyId = propertyInfo['propertyId']
                            propertyContractId = propertyInfo['contractId']
                            propertyGroupId = propertyInfo['groupId']
                            if propertyName == property_name or propertyName == property_name + ".xml":
                                #Update the self attributes with correct values
                                self.groupId = propertyGroupId
                                self.contractId = propertyContractId
                                self.propertyId = propertyId
                                self.final_response = "SUCCESS"
                                return self
            except KeyError:
                pass
        #Return the self as it is without updated information
        self.final_response = "FAILURE"
        return self


    def getGroups(self,session):
        """
        Function to fetch all the groups under the contract

        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        groupResponse : groupResponse
            (groupResponse) Object with all response details.
        """

        groupUrl = 'https://' + self.access_hostname + '/papi/v0/groups/'
        groupUrl = self.formUrl(groupUrl)

        groupResponse = session.get(groupUrl)
        if groupResponse.status_code == 200:
            self.final_response = "SUCCESS"
        else:
            self.final_response = "FAILURE"
        return groupResponse

    def searchProperty(self,session,propertyName='optional',hostname='optional',edgeHostname='optional'):
        """
        Function to fetch property ID

        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        searchResponse : searchResponse
            (searchResponse) Object with all response details.
        """

        searchUrl = 'https://' + self.access_hostname + '/papi/v0/search/find-by-value'
        searchUrl = self.formUrl(searchUrl)

        if propertyName != 'optional':
            seachTag = 'propertyName'
            searchValue = propertyName
        elif hostname != 'optional':
            seachTag = 'hostname'
            searchValue = hostname
        if edgeHostname != 'optional':
            seachTag = 'edgeHostname'
            searchValue = edgeHostname

        searchData = """
        {
            "%s": "%s"
        } """ % (seachTag,searchValue)

        searchResponse = session.post(searchUrl, data=searchData,headers=self.headers)
        if searchResponse.status_code == 200:
            self.final_response = "SUCCESS"
        else:
            self.final_response = "FAILURE"

        return searchResponse

    def getAllProperties(self,session,contractId,groupId):
        """
        Function to fetch list of all properties under the group

        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        allProperties : <dict>
            A dictionarty containing name, propertyId, contractId and groupId of all properties under the customer account
        """
        url = 'https://' + self.access_hostname + '/papi/v0/properties/?contractId=' + contractId +'&groupId=' + groupId
        url = self.formUrl(url)

        propertiesResponse = session.get(url)
        return propertiesResponse

    def getPropertyRules(self,session,property_name,version):
        """
        Function to download rules from a property

        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object
        property_name: <string>
            Property or configuration name
        version : <int>
            Property orconfiguration version number

        Returns
        -------
        rulesResponse : rulesResponse
            (rulesResponse) Object with all response details.
        """

        self.getPropertyInfo(session, property_name)
        rulesUrl = 'https://' + self.access_hostname  + '/papi/v0/properties/' + self.propertyId +'/versions/'+str(version)+'/rules/?contractId='+ self.contractId +'&groupId='+ self.groupId
        rulesUrl = self.formUrl(rulesUrl)

        rulesResponse = session.get(rulesUrl)
        if rulesResponse.status_code == 200:
            self.final_response = "SUCCESS"
        else:
            self.final_response = rulesResponse.json()['detail']
        return rulesResponse

    def getPropertyRulesfromPropertyId(self,session,propertyId,version,contractId,groupId):
        """
        Function to download rules from a property

        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object
        property_name: <string>
            Property or configuration name
        version : <int>
            Property orconfiguration version number

        Returns
        -------
        rulesResponse : rulesResponse
            (rulesResponse) Object with all response details.
        """

        rulesUrl = 'https://' + self.access_hostname  + '/papi/v0/properties/' + propertyId +'/versions/'+str(version)+'/rules/?contractId='+ contractId +'&groupId='+ groupId
        rulesUrl = self.formUrl(rulesUrl)

        rulesResponse = session.get(rulesUrl)
        if rulesResponse.status_code == 200:
            self.final_response = "SUCCESS"
        else:
            self.final_response = rulesResponse.json()['detail']
        return rulesResponse

    def createVersion(self,session,baseVersion,property_name):
        """
        Function to create or checkout a version of property

        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object
        baseVersion : <int>
            Property or configuration version number to checkout from
        property_name: <string>
            Property or configuration name

        Returns
        -------
        createVersionResponse : createVersionResponse
            (createVersionResponse) Object with all response details.
        """

        self.getPropertyInfo(session, property_name)
        newVersionData = """
        {
            "createFromVersion": %s
        }
        """ % (baseVersion)
        createVersionUrl = 'https://' + self.access_hostname + '/papi/v0/properties/' + self.propertyId + '/versions/?contractId=' + self.contractId + '&groupId=' + self.groupId
        createVersionUrl = self.formUrl(createVersionUrl)

        createVersionResponse = session.post(createVersionUrl, data=newVersionData,headers=self.headers)
        if createVersionResponse.status_code == 201:
            self.final_response = "SUCCESS"
        return createVersionResponse

    def getVersion(self,session,property_name,activeOn="LATEST",propertyId='optional',contractId='optional',groupId='optional'):
        """
        Function to get the latest or staging or production version

        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object
        activeOn : <string>
            Network Type (STAGING OR PRODUCTION) or the LATEST Version
        property_name: <string>
            Property or configuration name

        Returns
        -------
        VersionResponse : VersionResponse
            (VersionResponse) Object with all response details.
        """

        if propertyId == 'optional' or groupId == 'optional' or contractId == 'optional':
            self.getPropertyInfo(session, property_name)
        else:
            self.propertyId = propertyId
            self.groupId = groupId
            self.contractId = contractId

        if activeOn == "LATEST":
            VersionUrl = 'https://' + self.access_hostname + '/papi/v0/properties/' + self.propertyId + '/versions/latest?contractId=' + self.contractId +'&groupId=' + self.groupId
        elif activeOn == "STAGING":
            VersionUrl = 'https://' + self.access_hostname + '/papi/v0/properties/' + self.propertyId + '/versions/latest?contractId=' + self.contractId +'&groupId=' + self.groupId + '&activatedOn=STAGING'
        elif activeOn == "PRODUCTION":
            VersionUrl = 'https://' + self.access_hostname + '/papi/v0/properties/' + self.propertyId + '/versions/latest?contractId=' + self.contractId +'&groupId=' + self.groupId + '&activatedOn=PRODUCTION'

        VersionUrl = self.formUrl(VersionUrl)

        VersionResponse = session.get(VersionUrl)
        return VersionResponse

    def listVersions(self,session,property_name,propertyId='optional',contractId='optional',groupId='optional'):
        """
        Function to list all versions of a property

        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object
        property_name: <string>
            Property or configuration name

        Returns
        -------
        VersionResponse : VersionResponse
            (VersionResponse) Object with all response details.
        """

        if propertyId == 'optional' or groupId == 'optional' or contractId == 'optional':
            self.getPropertyInfo(session, property_name)
        else:
            self.propertyId = propertyId
            self.groupId = groupId
            self.contractId = contractId

        VersionUrl = 'https://' + self.access_hostname + '/papi/v1/properties/' + self.propertyId + '/versions/?contractId=' + self.contractId +'&groupId=' + self.groupId
        VersionUrl = self.formUrl(VersionUrl)

        VersionResponse = session.get(VersionUrl)
        return VersionResponse

    def uploadRules(self,session,updatedData,property_name,version,propertyId='optional',contractId='optional',groupId='optional'):
        """
        Function to upload rules to a property

        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object
        updatedData : <json>
            Complete JSON rules dataset to be uploaded
        property_name: <string>
            Property or configuration name

        Returns
        -------
        updateResponse : updateResponse
            (updateResponse) Object with all response details.
        """
        if propertyId == 'optional' or groupId == 'optional' or contractId == 'optional':
            self.getPropertyInfo(session, property_name)
        else:
            self.propertyId = propertyId
            self.groupId = groupId
            self.contractId = contractId

        updateurl = 'https://' + self.access_hostname  + '/papi/v0/properties/'+ self.propertyId + "/versions/" + str(version) + '/rules/' + '?contractId=' + self.contractId +'&groupId=' + self.groupId
        updateurl = self.formUrl(updateurl)

        updatedData = json.dumps(updatedData)
        updateResponse = session.put(updateurl,data=updatedData,headers=self.headers)
        if updateResponse.status_code == 403:
            self.final_response == "FAILURE"
        elif updateResponse.status_code == 404:
            self.final_response == "FAILURE"
        elif updateResponse.status_code == 200:
            self.final_response == "SUCCESS"
        return updateResponse

    def activateConfiguration(self,session,property_name,version,network,emailList,notes,propertyId='optional',contractId='optional',groupId='optional',ignoreWarnings='optional'):
        """
        Function to activate a configuration or property

        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object
        property_name: <string>
            Property or configuration name
        version : <int>
            version number to be activated
        network : <string>
            network type on which configuration has to be activated on (STAGING or PRODUCTION)
        emailList : <List>
            List of emailIds separated by comma to be notified
        notes : <string>
            Notes that describes the activation reason

        Returns
        -------
        activationResponse : activationResponse
            (activationResponse) Object with all response details.
        """
        if propertyId == 'optional' or contractId == 'optional' or groupId == 'optional':
            self.getPropertyInfo(session, property_name)
        else:
            self.propertyId = propertyId
            self.groupId = groupId
            self.contractId = contractId

        emails = json.dumps(emailList)
        activationDetails = """
             {
                "propertyVersion": %s,
                "network": "%s",
                "note": "%s",
                "notifyEmails": %s
            } """ % (version,network.upper(),notes,emails)

        if ignoreWarnings == 'optional':
            actUrl  = 'https://' + self.access_hostname + '/papi/v0/properties/'+ self.propertyId + '/activations/?contractId=' + self.contractId +'&groupId=' + self.groupId
        else:
            actUrl  = 'https://' + self.access_hostname + '/papi/v0/properties/'+ self.propertyId + '/activations/?contractId=' + self.contractId +'&groupId=' + self.groupId + '&acknowledgeAllWarnings=true'

        actUrl = self.formUrl(actUrl)

        activationResponse = session.post(actUrl, data=activationDetails, headers=self.headers)
        try:
            if activationResponse.status_code == 400 and activationResponse.json()['detail'].find('following activation warnings must be acknowledged'):
                acknowledgeWarnings = []
                for eachWarning in activationResponse.json()['warnings']:
                    #print("WARNING: " + eachWarning['detail'])
                    acknowledgeWarnings.append(eachWarning['messageId'])
                    acknowledgeWarningsJson = json.dumps(acknowledgeWarnings)
                print("\nAutomatically acknowledging the warnings.\n")
                #The details has to be within the three double quote or comment format
                updatedactivationDetails = """
                     {
                        "propertyVersion": %s,
                        "network": "%s",
                        "note": "%s",
                        "notifyEmails": %s,
                        "acknowledgeWarnings": %s
                    } """ % (version,network.upper(),notes,emails,acknowledgeWarningsJson)
                print("Please wait while we activate the config for you.. Hold on... \n")
                updatedactivationResponse = session.post(actUrl,data=updatedactivationDetails,headers=self.headers)
                if updatedactivationResponse.status_code == 201:
                    print("Here is the activation link, that can be used to track\n")
                    #print(updatedactivationResponse.json()['activationLink'])
                    self.final_response = "SUCCESS"
                else:
                    self.final_response = "FAILURE"
                    #print(updatedactivationResponse.json())
                return updatedactivationResponse
            elif activationResponse.status_code == 422 and activationResponse.json()['detail'].find('version already activated'):
                print("Property version already activated")
                self.final_response = "SUCCESS"
            elif activationResponse.status_code == 404 and activationResponse.json()['detail'].find('unable to locate'):
                print("The system was unable to locate the requested version of configuration")
                self.final_response = "FAILURE"
            return activationResponse
        except KeyError:
            self.final_response = "FAILURE"
            print("Looks like there is some error in configuration. Unable to activate configuration at this moment\n")
            return activationResponse

    def cloneConfig(self,session,property_name,new_property_name,version):
        """
        Function to Clone a configuration

        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object
        property_name: <string>
            Property or configuration name
        new_property_name: <string>
            Destination/New Property or configuration name
        version: <int>
            Property version to refer OR base from

        Returns
        -------
        cloneResponse : cloneResponse
            (cloneResponse) Object with all response details.
        """

        self.getPropertyInfo(session, property_name)
        versionUrl = 'https://' + self.access_hostname  + '/papi/v0/properties/'+ self.propertyId + "/versions/" + '?contractId=' + self.contractId +'&groupId=' + self.groupId
        versionUrl = self.formUrl(versionUrl)

        productId = ''
        versionEtag = ''
        versionResponse = session.get(versionUrl)
        for eachItem in versionResponse.json()['versions']['items']:
            if str(eachItem['propertyVersion']) == str(version):
                versionEtag = eachItem['etag']
                productId = "prd_Fresca"


        cloneData = """
        {
            "productId"    : "%s",
            "propertyName" : "%s",
            "cloneFrom": {
                "propertyId"    : "%s",
                "version"       : %s,
                "copyHostnames" : true,
                "cloneFromVersionEtag" : "%s"
            }
        }
        """ % (productId,new_property_name,self.propertyId,version,versionEtag)

        cloneUrl = 'https://' + self.access_hostname  + '/papi/v0/properties/?contractId=' + self.contractId +'&groupId=' + self.groupId
        cloneUrl = self.formUrl(cloneUrl)

        cloneResponse = session.post(cloneUrl, data=cloneData, headers=self.headers)
        return cloneResponse

    def createConfig(self,session,new_property_name,productId,contractId='options',groupId='optional'):
        """
        Function to create a configuration

        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object
        new_property_name: <string>
            Destination/New Property or configuration name

        Returns
        -------
        createResponse : createResponse
            (createResponse) Object with all response details.
        """
        if contractId == 'optional' or groupId == 'optional':
            self.getPropertyInfo(session, property_name)
        else:
            self.contractId = contractId
            self.groupId = groupId

        createData = """
        {
            "productId"    : "%s",
            "propertyName" : "%s"
        }
        """ % (productId,new_property_name)

        createUrl = 'https://' + self.access_hostname  + '/papi/v0/properties/?contractId=' + self.contractId +'&groupId=' + self.groupId
        createUrl = self.formUrl(createUrl)

        createResponse = session.post(createUrl, data=createData, headers=self.headers)
        return createResponse

    def deleteProperty(self,session,property_name):
        """
        Function to delete a property

        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object
        property_name: <string>
            Property or configuration name

        Returns
        -------
        deleteResponse : deleteResponse
            (deleteResponse) Object with all response details.
        """

        self.getPropertyInfo(session, property_name)
        deleteurl = 'https://' + self.access_hostname  + '/papi/v0/properties/'+ self.propertyId + '?contractId=' + self.contractId +'&groupId=' + self.groupId
        deleteurl = self.formUrl(deleteurl)

        deleteResponse = session.delete(deleteurl)
        if deleteResponse.status_code == 403:
            self.final_response == "FAILURE"
        elif deleteResponse.status_code == 404:
            self.final_response == "FAILURE"
        elif deleteResponse.status_code == 200:
            self.final_response == "SUCCESS"
        else:
            self.final_response == "FAILURE"
        return deleteResponse

    def listProducts(self,session,contractId='optional'):
        """
        Function to fetch all products

        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        Nothing: It rather prints the data
        """
        if contractId == 'optional':
            contractsResponse = self.getContracts(session)
            for everyItem in contractsResponse.json()['contracts']['items']:
                contractId = everyItem['contractId']
                productsUrl = 'https://' + self.access_hostname + '/papi/v0/products/?contractId=' + contractId
                productsUrl = self.formUrl(productsUrl)

                productsResponse = session.get(productsUrl)
        else:
            productsUrl = 'https://' + self.access_hostname + '/papi/v0/products/?contractId=' + contractId
            productsUrl = self.formUrl(productsUrl)

            productsResponse = session.get(productsUrl)
        return productsResponse


    def listRuleFormats(self,session):
        """
        Function to Get a list of available rule formats

        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        ruleFomratResponse : ruleFomratResponse
            (ruleFomratResponse) Object with all response details.
        """
        ruleFomratUrl = 'https://' + self.access_hostname + '/papi/v0/rule-formats'
        ruleFomratUrl = self.formUrl(ruleFomratUrl)

        ruleFomratResponse = session.get(ruleFomratUrl)
        return ruleFomratResponse

    def getRuleTree(self,session,property_name,version,latestTimeStamp='latest'):
        """
        Function to get the entire rule tree for a property version

        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        ruleTreeResponse : ruleTreeResponse
            (ruleTreeResponse) Object with all response details.
        """
        #latestTimeStamp='latest' this is not a desired value, but can be used to fetch rule tree
        AcceptValue = "application/vnd.akamai.papirules." + latestTimeStamp + "+json"
        mime_header = {
            "Accept": AcceptValue
        }
        self.getPropertyInfo(session, property_name)
        '/papi/v0/properties/' + self.propertyId + '/versions/' + version + '/rules/?contractId=' + self.contractId + '&groupId=' + self.groupId
        ruleTreeUrl = 'https://' + self.access_hostname + '/papi/v0/properties/' + self.propertyId + '/versions/' + version + '/rules/?contractId=' + self.contractId + '&groupId=' + self.groupId
        ruleTreeUrl = self.formUrl(ruleTreeUrl)

        ruleTreeResponse = session.get(ruleTreeUrl,headers=mime_header)
        return ruleTreeResponse

    def updateRuleTree(self,session,property_name,version,TimeStamp):
        """
        Function to update the entire rule tree for a property version to

        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        updateruleTreeResponse : ruleTreeResponse
            (updateruleTreeResponse) Object with all response details.
        """
        mime_header = {
            "Content-Type": "application/vnd.akamai.papirules.v2016-11-15+json"
        }
        self.getPropertyInfo(session, property_name)
        '/papi/v0/properties/' + self.propertyId + '/versions/' + version + '/rules/?contractId=' + self.contractId + '&groupId=' + self.groupId
        updateruleTreeUrl = 'https://' + self.access_hostname + '/papi/v0/properties/' + self.propertyId + '/versions/' + version + '/rules/?contractId=' + self.contractId + '&groupId=' + self.groupId
        updateruleTreeUrl = self.formUrl(updateruleTreeUrl)

        updateruleTreeResponse = session.put(updateruleTreeUrl,headers=mime_header)
        return updateruleTreeResponse

    def createEdgeHostname(self,session,hostname,productId,contractId,groupId):
        """
        Function to update hostname of property

        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        createEdgeHostnameResponse : createEdgeHostnameResponse
            (createEdgeHostnameResponse) Object with all response details.
        """
        self.contractId = contractId
        self.groupId = groupId

        hostnameData = """
        {
            "productId": "%s",
            "domainPrefix": "%s",
            "domainSuffix": "edgesuite.net",
            "ipVersionBehavior": "IPV4"
        }
        """ % (productId,hostname)
        createEdgeHostnameUrl = 'https://' + self.access_hostname + '/papi/v0/edgehostnames/?contractId=' + self.contractId + '&groupId=' + self.groupId
        createEdgeHostnameUrl = self.formUrl(createEdgeHostnameUrl)

        createEdgeHostnameResponse = session.post(createEdgeHostnameUrl,data=hostnameData,headers=self.headers)
        return createEdgeHostnameResponse

    def updateHostname(self,session,hostname,edgeHostnameId,version,propertyId,contractId,groupId):
        """
        Function to update hostname of property

        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        updateHostnameResponse : updateHostnameResponse
            (updateHostnameResponse) Object with all response details.
        """
        self.propertyId = propertyId
        self.contractId = contractId
        self.groupId = groupId

        hostnameData = """
        [
            {
                "cnameType": "EDGE_HOSTNAME",
                "cnameFrom": "%s",
                "edgeHostnameId": "%s"
            }
        ]
        """ % (hostname,edgeHostnameId)

        updateHostnameUrl = 'https://' + self.access_hostname + '/papi/v0/properties/' + self.propertyId + '/versions/' + str(version) + '/hostnames/?contractId=' + self.contractId + '&groupId=' + self.groupId + '&validateHostnames=false'
        updateHostnameUrl = self.formUrl(updateHostnameUrl)

        updateHostnameResponse = session.put(updateHostnameUrl,data=hostnameData,headers=self.headers)
        return updateHostnameResponse

    def verifyCreds(self,session):
        """
        Function to check credentials

        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        credsResponse : credsResponse
            (credsResponse) Object with all response details.
        """
        credsUrl = 'https://' + self.access_hostname + '/-/client-api/active-grants/implicit'
        credsUrl = self.formUrl(credsUrl)

        credsResponse = session.get(credsUrl)
        return credsResponse

    def listEdgeHostnames(self,session,contractId='optional',groupId='optional'):
        """
        Function to fetch all edgehostnames

        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object
        contractId : contractId
            corresponding contractId
        groupId : groupId
            corresponding groupId
        Returns
        -------
        edgehostname : edgehostname object containing edgehostname details
        """
        if contractId == 'optional' and groupId == 'optional':
            #update code to fetch group and contract info
            pass
        else:
            edgehostnameUrl = 'https://' + self.access_hostname + '/papi/v0/edgehostnames/?contractId=' + contractId + '&groupId=' + groupId
            edgehostnameUrl = self.formUrl(edgehostnameUrl)

            edgehostnameResponse = session.get(edgehostnameUrl)
        return edgehostnameResponse

    def listProperties(self,session,contractId='optional',groupId='optional'):
        """
        Function to fetch all properties

        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object
        contractId : contractId
            corresponding contractId
        groupId : groupId
            corresponding groupId
        Returns
        -------
        propertiesList : property List object
        """
        if contractId == 'optional' and groupId == 'optional':
            #update code to fetch group and contract info
            pass
        else:
            propertiesListUrl = 'https://' + self.access_hostname + '/papi/v1/properties?contractId=' + contractId + '&groupId=' + groupId
            propertiesListUrl = self.formUrl(propertiesListUrl)

            propertiesListResponse = session.get(propertiesListUrl)
        return propertiesListResponse


    def listHostnames(self,session,propertyId,version,contractId,groupId):
        """
        Function to fetch all properties

        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object
        contractId : contractId
            corresponding contractId
        groupId : groupId
            corresponding groupId
        Returns
        -------
        hostNameList : hostName List object
        """

        hostnameListUrl = 'https://' + self.access_hostname + '/papi/v1/properties/' + propertyId + '/versions/' + str(version) + '/hostnames'+ '?contractId=' + contractId + '&groupId=' + groupId
        hostnameListUrl = self.formUrl(hostnameListUrl)

        hostnameListResponse = session.get(hostnameListUrl)
        return hostnameListResponse

    def formUrl(self, url):
        """
        Function to form URL
        """
        #This is to ensure accountSwitchKey works for internal users
        if '?' in url:
            self.account_switch_key = self.account_switch_key.translate(self.account_switch_key.maketrans('?','&'))
            url = url + self.account_switch_key
        else:
            #Replace & with ? if there is no query string in URL
            self.account_switch_key = self.account_switch_key.translate(self.account_switch_key.maketrans('&','?'))
            url = url + self.account_switch_key    

        return url        