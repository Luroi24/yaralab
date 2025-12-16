# TODO: Dar la posibilidad de agrupar el output por tags o reglas que hicieron match.

import json
import os
import re
import yara
import argparse
from enum import Enum
from pymongo import MongoClient

# MongoDB connection settings (using Docker Compose service name)
MONGO_HOST = "db"
MONGO_PORT = 27017
MONGO_USER = "yara_user"
MONGO_PASSWORD = "yara_password"
MONGO_DATABASE = "yara_db"

# YARA module imports required for rules that use external modules
YARA_IMPORTS = '''
import "math"
import "console"
import "hash"
import "pe"
import "dotnet"
import "elf"
'''

def parse_args():
    """
    Parse command line arguments for YaraLab tool.
    Returns:
        argparse.Namespace: Parsed command line arguments.
    """

    parser = argparse.ArgumentParser(description="Script to run YARA rules on files in a Docker container.")
    parser.add_argument(
        '-f', '--files',
        type=str,
        required=True,
        help='Name of the folder containing files to be analyzed.'
    )
    parser.add_argument(
        '-gt', '--group-by-tags',
        default=False,
        required=False,
        action=argparse.BooleanOptionalAction,
        help='Group output by tags instead of rules.'
    )
    parser.add_argument(
        '-db', '--use-database',
        default=False,
        required=False,
        action=argparse.BooleanOptionalAction,
        help='Retrieve rules from MongoDB database instead of files.'
    )
    parser.add_argument(
        '-t', '--tags',
        type=str,
        nargs='*',
        required=False,
        default=None,
        help='Tags to filter rules from database. Can specify none (all rules), one tag, or multiple tags.'
    )

    return parser.parse_args()


class GroupMode(Enum):
    BY_RULE = 1
    BY_TAG = 2


class YaraMatcher:
    def __init__(self, rules, group_mode=GroupMode.BY_RULE):
        self.rules = rules
        self.group_mode = group_mode
        self.output_info = {}

    def process_match(self, filename, match):
        if self.group_mode == GroupMode.BY_TAG:
            for tag in match.tags:
                if tag not in self.output_info:
                    self.output_info[tag] = []
                self.output_info[tag].append({
                    "file": filename,
                    "rule": match.rule,
                    "tags": match.tags,
                    "meta": match.meta
                })
        else:
            if match.rule not in self.output_info:
                self.output_info[match.rule] = []
            self.output_info[match.rule].append({
                "file": filename,
                "tags": match.tags,
                "meta": match.meta
            })

    def _run_analyzer(self, filepath: str):
        print(f"Analyzing file: {filepath}")
        filename = os.path.basename(filepath)
        for rule in self.rules:
            matches = rule.match(filepath)
            for match in matches:
                self.process_match(filename, match)
                print(f"Match found: {match.rule} in file {filename}")

    def analyze_files(self, files_dir):
        if os.path.isdir(files_dir):
            for _, _, files in os.walk(files_dir):
                for filename in files:
                    self._run_analyzer(os.path.join(files_dir, filename))
        else:
            self._run_analyzer(files_dir)

    def write_output(self, output_path):
        with open(output_path, "w") as json_file:
            json.dump(self.output_info, json_file)


def get_rules_from_database(tags=None):
    """
    Retrieve YARA rules from MongoDB database.
    
    Args:
        tags: List of tags to filter rules. 
              - None or empty list: get all rules
              - Single tag: get rules with that tag
              - Multiple tags: get rules matching ANY of the tags
    
    Returns:
        list: List of compiled YARA rules
    """
    rules = []
    
    try:
        # Connect to MongoDB
        connection_string = f"mongodb://{MONGO_USER}:{MONGO_PASSWORD}@{MONGO_HOST}:{MONGO_PORT}/{MONGO_DATABASE}?authSource=admin"
        client = MongoClient(connection_string, serverSelectionTimeoutMS=5000)
        db = client[MONGO_DATABASE]
        
        # Verify connection
        client.server_info()
        print(f"Connected to MongoDB database: {MONGO_DATABASE}")
        
        # Build query based on tags (case-insensitive)
        if tags is None or len(tags) == 0:
            # No tags provided - get all rules
            query = {}
            print("Retrieving all rules from database (no tag filter)")
        elif len(tags) == 1:
            # Single tag provided - case-insensitive regex match
            query = {"tags": {"$regex": f"^{tags[0]}$", "$options": "i"}}
            print(f"Retrieving rules with tag: {tags[0]} (case-insensitive)")
        else:
            # Multiple tags provided - match any of them (case-insensitive)
            regex_patterns = [{"$regex": f"^{tag}$", "$options": "i"} for tag in tags]
            query = {"$or": [{"tags": pattern} for pattern in regex_patterns]}
            print(f"Retrieving rules with any of tags: {tags} (case-insensitive)")
        
        # Retrieve rules from database
        cursor = db["rules"].find(query)
        documents = list(cursor)
        
        if not documents:
            print("No rules found matching the specified criteria.")
            client.close()
            return rules
        
        print(f"Retrieved {len(documents)} rules from database.")
        
        # Filter out private rules (they are helper rules that shouldn't produce matches)
        # Private rules typically have "_PRIVATE" suffix or start with "private rule"
        filtered_documents = []
        skipped_private = 0
        for doc in documents:
            rule_name = doc.get('name', '')
            rule_content = doc.get('rule_text') or doc.get('raw_content') or ''
            
            # Skip if it's a private rule (by name convention or content)
            if '_PRIVATE' in rule_name.upper() or rule_content.strip().lower().startswith('private'):
                skipped_private += 1
                continue
            filtered_documents.append(doc)
        
        if skipped_private > 0:
            print(f"Skipped {skipped_private} private rules (helper rules that don't produce matches).")
        
        documents = filtered_documents
        
        # Collect all rule contents to compile together (handles inter-rule dependencies)
        all_rules_content = []
        
        for doc in documents:
            rule_content = None
            
            # Try to get rule_text or raw_content
            if 'rule_text' in doc and doc['rule_text']:
                rule_content = doc['rule_text']
            elif 'raw_content' in doc and doc['raw_content']:
                rule_content = doc['raw_content']
            else:
                print(f"Unable to find 'rule_text' or 'raw_content' for rule '{doc.get('name', 'unknown')}'")
                continue
            
            # Fix malformed rules with empty tags (e.g., "rule NAME :  {" -> "rule NAME {")
            rule_content = re.sub(r'(rule\s+\w+)\s*:\s*\{', r'\1 {', rule_content)
            all_rules_content.append(rule_content)
        
        if all_rules_content:
            try:
                # Compile all rules together to resolve inter-rule dependencies
                full_content = YARA_IMPORTS + "\n" + "\n\n".join(all_rules_content)
                compiled_rules = yara.compile(source=full_content)
                rules.append(compiled_rules)
                print(f"Successfully compiled {len(all_rules_content)} rules together from database.")
            except yara.SyntaxError as e:
                print(f"Syntax error compiling rules together: {e}")
                # Fallback: filter out problematic rules and try again
                print("Filtering out problematic rules...")
                valid_rules_content = []
                
                for i, rule_content in enumerate(all_rules_content):
                    try:
                        # Test compile each rule individually
                        test_content = YARA_IMPORTS + "\n" + rule_content
                        yara.compile(source=test_content)
                        valid_rules_content.append(rule_content)
                    except yara.SyntaxError as e:
                        rule_name = documents[i].get('name', f'unknown_{i}')
                        print(f"Skipping rule '{rule_name}': {e}")
                    except Exception as e:
                        rule_name = documents[i].get('name', f'unknown_{i}')
                        print(f"Skipping rule '{rule_name}': {e}")
                
                # Try to compile valid rules together
                if valid_rules_content:
                    try:
                        full_content = YARA_IMPORTS + "\n" + "\n\n".join(valid_rules_content)
                        compiled_rules = yara.compile(source=full_content)
                        rules.append(compiled_rules)
                        print(f"Successfully compiled {len(valid_rules_content)} valid rules (skipped {len(all_rules_content) - len(valid_rules_content)} problematic rules).")
                    except yara.SyntaxError as e:
                        print(f"Still failing after filtering. Compiling rules individually...")
                        # Last resort: compile each valid rule individually
                        for rule_content in valid_rules_content:
                            try:
                                full_rule_content = YARA_IMPORTS + "\n" + rule_content
                                compiled_rule = yara.compile(source=full_rule_content)
                                rules.append(compiled_rule)
                            except:
                                pass
                        print(f"Compiled {len(rules)} rules individually.")
            except Exception as e:
                print(f"Error compiling rules: {e}")
        
        client.close()
        
    except Exception as e:
        print(f"Failed to retrieve rules from database: {e}")
    
    return rules

def get_rules_from_files():
    """
    Load YARA rules from files in /data/rules/raw directory.
    
    Returns:
        list: List of compiled YARA rules
    """
    rules = []
    for root, dirs, files in os.walk("/data/rules/raw"):
        for filename in files:
            if filename.endswith(".yara") or filename.endswith(".yar"):
                filepath = os.path.join(root, filename)
                try:
                    rule = yara.compile(filepath)
                    rules.append(rule)
                except yara.SyntaxError as e:
                    print(f"Syntax error in {filepath}: {e}")
                except Exception as e:
                    print(f"Error compiling {filepath}: {e}")
    return rules


def main():
    args = parse_args()

    # Get rules either from database or files
    if args.use_database:
        rules = get_rules_from_database(args.tags)
    else:
        rules = get_rules_from_files()

    if not rules:
        print("No rules loaded. Exiting.")
        return

    os.makedirs("./output", exist_ok=True)

    group_mode = GroupMode.BY_TAG if args.group_by_tags else GroupMode.BY_RULE
    matcher = YaraMatcher(rules, group_mode)
    matcher.analyze_files(f"/data/files/{args.files}")
    matcher.write_output("./output/results.json")

if __name__ == "__main__":
    main()