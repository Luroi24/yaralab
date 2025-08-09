import os
import re
from collections import defaultdict

def extract_rules_by_tag(input_file):
    tags_rules = defaultdict(list)

    with open(input_file, 'r') as f:
        lines = f.readlines()

    rule_lines = []
    in_rule = False
    brace_count = 0

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("rule "):
            if in_rule:
                print("Warning: Nested rule found, skipping improper rule.")
                rule_lines = []
            in_rule = True
            brace_count = 0
            rule_lines = [line]
            # Extract tags
            rule_header = line
            tag_match = re.search(r':\s*([^ {]+(?:\s+[^ {]+)*)', line)
            tags = tag_match.group(1).split() if tag_match else ['untagged']

        elif in_rule:
            rule_lines.append(line)
            brace_count += line.count('{') - line.count('}')
            if brace_count <= 0:
                rule = ''.join(rule_lines).strip()
                for tag in tags:
                    tags_rules[tag].append(rule)
                in_rule = False
                rule_lines = []

    return tags_rules


def write_rules_by_tag(tags_rules, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    for tag, rules in tags_rules.items():
        filename = os.path.join(output_dir, f"{tag}.yar")
        with open(filename, 'w') as f:
            for rule in rules:
                f.write(rule + '\n\n')
        print(f"[+] Written {len(rules)} rules to {filename}")


if __name__ == "__main__":
    input_file = "yara-rules-full.yar"  # Change to your file
    output_dir = "../separated_rules"

    tags_rules = extract_rules_by_tag(input_file)
    write_rules_by_tag(tags_rules, output_dir)
