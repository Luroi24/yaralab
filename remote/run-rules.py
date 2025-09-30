# TODO: Dar la posibilidad de agrupar el output por tags o reglas que hicieron match.

import json
import os
import yara
import argparse
from enum import Enum

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
        '-l', '--label',
        type=str,
        required=False,
        help='Label for the yara rules to be processed. If not provided, all rules will be processed.'
    )
    parser.add_argument(
        '-gt', '--group-by-tags',
        default=False,
        required=False,
        action=argparse.BooleanOptionalAction,
        help='Group output by tags instead of rules.'
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
            self._run_analyzer([files_dir])

    def write_output(self, output_path):
        with open(output_path, "w") as json_file:
            json.dump(self.output_info, json_file)


def main():
    args = parse_args()

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

    os.makedirs("./output", exist_ok=True)

    group_mode = GroupMode.BY_TAG if args.group_by_tags else GroupMode.BY_RULE
    matcher = YaraMatcher(rules, group_mode)
    matcher.analyze_files(f"/data/files/{args.files}")
    matcher.write_output("./output/results.json")

if __name__ == "__main__":
    main()