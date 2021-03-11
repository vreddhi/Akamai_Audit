# Audit

Python script to audits groups and properties. The script can:
- List all groups
- List all properties
- WAF Protection Status


## Installation

Use the package manager(pip3) to install pre-requisites for Ruleupdater.

```bash
pip3 install akamai-edgegrid
pip3 install configparser
pip3 install requests
pip3 install logging
```

## Usage

```python
python3 Audit.py 

usage: Audit.py [command] [--version]  ...

Akamai CLI for Audit

optional arguments:
  --version       show program's version number and exit

Commands:
  
    help          Show available help
    downloadRule  Download a specific rule in a configuration into json format
    addRule       Add a raw json rule to an existing configuration (before or after and existing rule)
    replaceRule   Replace an existing json rule
    deleteRule    Delete an existing rule)
    getDetail     Retrieves the detailed information about property
    listRules     Retrieves the detailed information about property
    addBehavior   Add a raw json behavior to an existing rule
    deleteBehavior
                  Delete Behavior
```

## To get help on Individual command
```sh
python3 Audit.py help <command>
```

```
python3 RuleUpdater.py help downloadRule
usage: RuleUpdater.py downloadRule --property PROPERTY --version VERSION --ruleName RULENAME [--outputFilename OUTPUTFILENAME] [--edgerc EDGERC] [--section SECTION] [--debug] [--account-key ACCOUNT_KEY]

required arguments:
  --property PROPERTY   Property name
  --version VERSION     version number or the text 'LATEST/PRODUCTION/STAGING' which will fetch the latest version
  --ruleName RULENAME   Rule Name to find

optional arguments:
  --outputFilename OUTPUTFILENAME
                        Filename to be used to save the rule in json format under samplerules folder
  --edgerc EDGERC       Location of the credentials file [$AKAMAI_EDGERC]
  --section SECTION     Section of the credentials file [$AKAMAI_EDGERC_SECTION]
  --debug               DEBUG mode to generate additional logs for troubleshooting
  --account-key ACCOUNT_KEY
                        Account Switch Key

```

- The rule name is the unique identifier. As the rule names can duplicate. The script exits if there are more than 1 rule with same name.
- `addRule` inserts the rule after/before a reference rule. 
- `replaceRule` replaces the rule based on a rulename.
- The name of the rules file to be inserted or replaced is configurable, but the file containing the rule should be placed under `samplerules` folder.


## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[APACHE 2.0](https://www.apache.org/licenses/LICENSE-2.0)
