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

Akamai CLI for Property/hostname(s) Audits

optional arguments:
  --version          show program's version number and exit

Commands:
  
    help             Show available help
    list-groups      List groups
    list-properties  List all the properties
    waf-coverage     List all the properties
    check-hostnames  Check hostnames to be onboarded
    check-cert-expiry
                     Check expiration of certificates
    create-case      Create Akatec Case
```

## To get help on Individual command
```sh
python3 Audit.py help <command>
```




## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[APACHE 2.0](https://www.apache.org/licenses/LICENSE-2.0)
