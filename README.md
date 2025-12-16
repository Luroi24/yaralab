
![Logo](https://github.com/Luroi24/yaralab/blob/main/misc/junimo_pyfa.png)


# PYFA - Portable Yara File Analyzer

PYFA is a portable option to run various yara rules into one or many files statically. PYFA uses docker compose to stay system agnostic in its execution and you can easily test your yara rules from anywhere, anytime.


## Pre requisites

- Have Docker Engine installed on your machine
- Have a python3 version installed with venv

## Getting started

To deploy this project, run the following

- [Optional] Create a virtual environment and activate it. While this isn't fully necessary, it is highly recommended to use an environment to use this tool.
```bash
[Windows]
py -m venv .env
.env/Scripts/activate

[UNIX based]
python3 -m venv .env
source ./.env/bin/activate
```

- Install the necessary Python libraries
```bash
pip install -r requirements.txt
```

- Make sure your Docker engine is up and running before trying to use PYFA

## Usage/Examples

The project will automatically build the images for you, so you don't have to worry about having them already.

### GUI
Using the gui is the easiest option to run this tool. The only thing you have to do is run
```bash
python3 ./gui.py
```
while the environment is active, and you can start using it from the get-go. You can drag and drop files into the window, specify a name for the run, use either compiled rules or get them from the db. If you choose the latter, you can also select one or many of the tags loaded in the DB. You can load more rules using the CLI.

### CLI

To use the CLI version of PYFA, you need to consider the following:
```bash
usage: yaralab.py [-h] -i INPUT [-o OUTPUT] [-gt | --group-by-tags | --no-group-by-tags] [-dn DNAME]
                  [-db | --dataBase | --no-dataBase] [-ldb LOAD_DB] [-t [TAGS ...]]

PYFA: A tool for YARA rule management and analysis.

options:
  -h, --help            show this help message and exit
  -i, --input INPUT     Path to the input file containing YARA rules or signatures.
  -o, --output OUTPUT   Path to the output file where results will be saved.
  -gt, --group-by-tags, --no-group-by-tags  Group output by tags instead of rules.
  -dn, --dName DNAME    Name for the container. Defaulted to "yara_container"
  -db, --dataBase, --no-dataBase    Enable database integration for rule management. Follow with -ldb to load rules into the database or -t to filter rules by tags.
  -ldb, --loadDb LOAD_DB    Load rules into the database from the specified YARA file. Provide the path to the file i.e. "./rules/my_rules.yar"
  -t, --tags [TAGS ...] Tags to filter rules from database. Can specify none (all rules), one tag, or multiple tags.
```
