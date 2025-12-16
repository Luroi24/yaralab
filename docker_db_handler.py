from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from bson.objectid import ObjectId
import logging
import re
from pathlib import Path

class MongoDB_Handler:
    """
    A class to handle MongoDB operations (Create, Read, Update, Delete).
    Manages connections and provides CRUD operations for collections.
    """

    def __init__(self, host="localhost", port=27017, username="yara_user", password="yara_password", database="yara_db"):
        """
        Initialize MongoDB handler with connection parameters.
        Args:
            host (str): MongoDB host
            port (int): MongoDB port
            username (str): MongoDB username
            password (str): MongoDB password
            database (str): Database name
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.database = database
        self.client = None
        self.db = None
        self._connect()

    def _connect(self):
        """Establish connection to MongoDB."""
        try:
            connection_string = f"mongodb://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}?authSource=admin"
            self.client = MongoClient(connection_string, serverSelectionTimeoutMS=5000)
            self.db = self.client[self.database]
            # Verify connection
            self.client.server_info()
            logging.info(f"✓ Connected to MongoDB database: {self.database}")
        except Exception as e:
            logging.error(f"✗ Failed to connect to MongoDB: {e}")
            raise

    def close(self):
        """Close MongoDB connection."""
        if self.client:
            self.client.close()
            logging.info("MongoDB connection closed")

    def create_many(self, collection: str, documents: list) -> list:
        """
        Insert multiple documents into a collection.
        Args:
            collection (str): Collection name
            documents (list): List of documents to insert
        Returns:
            list: List of inserted document IDs
        """
        try:
            result = self.db[collection].insert_many(documents)
            logging.info(f"{len(result.inserted_ids)} documents inserted into '{collection}'")
            return [str(id) for id in result.inserted_ids]
        except Exception as e:
            logging.error(f"Failed to insert documents into '{collection}': {e}")
            return []

    def load_rules_from_file(self, rules_path: str = None, collection: str = "rules") -> int:
        """
        Load YARA rules from a file and insert them individually into the database.
        Parses the rules file to extract each rule as a separate document.
        
        Args:
            rules_path (str): Path to the rules file. If None, prompts user.
                            Default prompt value is "remote/rules/raw/yara-rules-full.yar"
            collection (str): Collection name to store rules
        
        Returns:
            int: Number of rules loaded successfully
        """
        try:
            # Prompt for path if not provided
            if rules_path is None:
                default_path = "remote/rules/raw/yara-rules-full.yar"
                user_input = input(f"Enter path to rules file (default: {default_path}): ").strip()
                rules_path = user_input if user_input else default_path

            # Verify file exists
            rules_file = Path(rules_path)
            if not rules_file.exists():
                logging.error(f"Rules file not found: {rules_path}")
                return 0
            
            # Read the entire file
            logging.info(f"Reading rules from: {rules_path}")
            with open(rules_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Parse individual rules using regex
            # Pattern to match: rule NAME : tags { ... }
            rule_pattern = r'rule\s+(\w+)\s*(?::\s*([^\{]+?))?\s*\{((?:[^{}]|(?:\{[^{}]*\}))*)\}'
            matches = re.finditer(rule_pattern, content, re.DOTALL)
            
            rules_to_insert = []
            rule_count = 0
            
            for match in matches:
                rule_name = match.group(1)
                rule_tags = match.group(2).strip() if match.group(2) else ""
                rule_body = match.group(3).strip()
                
                # Parse meta, strings, and condition sections
                meta_dict = self._parse_meta_section(rule_body)
                strings_list = self._parse_strings_section(rule_body)
                condition = self._parse_condition_section(rule_body)
                
                # Create rule document
                tags_list = [tag.strip() for tag in rule_tags.split() if tag.strip()]
                # Build raw_content with proper syntax (no colon if no tags)
                if tags_list:
                    raw_content = f"rule {rule_name} : {rule_tags} {{{rule_body}}}"
                else:
                    raw_content = f"rule {rule_name} {{{rule_body}}}"
                
                rule_doc = {
                    "name": rule_name,
                    "tags": tags_list,
                    "meta": meta_dict,
                    "strings": strings_list,
                    "condition": condition,
                    "raw_content": raw_content
                }
                
                rules_to_insert.append(rule_doc)
                rule_count += 1
                
                # Insert in batches of 1000
                if len(rules_to_insert) >= 1000:
                    self.create_many(collection, rules_to_insert)
                    logging.info(f"Inserted batch of {len(rules_to_insert)} rules...")
                    rules_to_insert = []
            
            # Insert remaining rules
            if rules_to_insert:
                self.create_many(collection, rules_to_insert)
            
            logging.info(f"✓ Successfully loaded {rule_count} rules into '{collection}' collection")
            return rule_count
            
        except Exception as e:
            logging.error(f"✗ Failed to load rules from file: {e}")
            return 0

    def _parse_meta_section(self, rule_body: str) -> dict:
        """
        Extract meta information from rule body.
        
        Args:
            rule_body (str): The rule body content
        
        Returns:
            dict: Dictionary of metadata key-value pairs
        """
        meta_dict = {}
        try:
            # Pattern to match meta section: meta: ... strings:
            meta_match = re.search(r'meta\s*:\s*(.*?)(?=strings\s*:|condition\s*:|$)', rule_body, re.DOTALL)
            if meta_match:
                meta_content = meta_match.group(1)
                # Pattern to match individual meta fields: key = value
                field_pattern = r'(\w+)\s*=\s*["\']?([^"\';\n]+)["\']?(?=\s*(?:\w+\s*=|$))'
                for field_match in re.finditer(field_pattern, meta_content):
                    key = field_match.group(1)
                    value = field_match.group(2).strip()
                    meta_dict[key] = value
        except Exception as e:
            logging.warning(f"Could not parse meta section: {e}")
        
        return meta_dict

    def _parse_strings_section(self, rule_body: str) -> list:
        """
        Extract strings from rule body.
        
        Args:
            rule_body (str): The rule body content
        
        Returns:
            list: List of string definitions
        """
        strings_list = []
        try:
            # Pattern to match strings section
            strings_match = re.search(r'strings\s*:\s*(.*?)(?=condition\s*:|$)', rule_body, re.DOTALL)
            if strings_match:
                strings_content = strings_match.group(1)
                # Pattern to match individual strings: $var = definition
                string_pattern = r'\$(\w+)\s*=\s*([^\n]+)'
                for string_match in re.finditer(string_pattern, strings_content):
                    var_name = string_match.group(1)
                    var_value = string_match.group(2).strip()
                    strings_list.append({"name": var_name, "value": var_value})
        except Exception as e:
            logging.warning(f"Could not parse strings section: {e}")
        
        return strings_list

    def _parse_condition_section(self, rule_body: str) -> str:
        """
        Extract condition from rule body.
        
        Args:
            rule_body (str): The rule body content
        
        Returns:
            str: The condition string
        """
        try:
            # Pattern to match condition section
            condition_match = re.search(r'condition\s*:\s*(.+?)(?=\}|$)', rule_body, re.DOTALL)
            if condition_match:
                return condition_match.group(1).strip()
        except Exception as e:
            logging.warning(f"Could not parse condition section: {e}")
        
        return ""
    
    def get_distinct(self, collection:str = "rules", field: str = "tags") -> list:
        """
        Get distinct values for a specified field in a collection. Default is 'tags' field in 'rules' collection.
        Args:
            collection (str): Collection name
            field (str): Field name to get distinct values for
        Returns:
            list: List of distinct values
        """
        try:
            distinct_values = self.db[collection].distinct(field)
            logging.info(f"Retrieved {len(distinct_values)} distinct values for field '{field}' in collection '{collection}'")
            return distinct_values
        except Exception as e:
            logging.error(f"Failed to get distinct values for field '{field}' in collection '{collection}': {e}")
            return []