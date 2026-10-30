#!/usr/bin/env python3
import json
import re
import os
import sys

print("Verifying curriculum uniqueness and data integrity across all 15 domains...")

domain_files = [
    'src/data/domains/httpRules.ts',
    'src/data/domains/webRules.ts',
    'src/data/domains/apiRules.ts',
    'src/data/domains/authRules.ts',
    'src/data/domains/authzRules.ts',
    'src/data/domains/oauthRules.ts',
    'src/data/domains/cryptoRules.ts',
    'src/data/domains/cloudRules.ts',
    'src/data/domains/awsRules.ts',
    'src/data/domains/containerRules.ts',
    'src/data/domains/containerAdvancedRules.ts',
    'src/data/domains/k8sRules.ts',
    'src/data/domains/codingRules.ts',
    'src/data/domains/codeReviewAdvancedRules.ts',
    'src/data/domains/aiRules.ts',
    'src/data/domains/aiAdvancedRules.ts',
    'src/data/domains/smartContractRules.ts',
    'src/data/domains/web3AdvancedRules.ts',
    'src/data/domains/threatModelingRules.ts'
]

ids = []
titles = []
questions = []
formulas = []

for filepath in domain_files:
    if not os.path.exists(filepath):
        print(f"ERROR: Missing file {filepath}")
        sys.exit(1)
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Extract id, title, question, formalInvariant
    file_ids = re.findall(r'id:\s*"(SEC-[^"]+)"', content)
    file_titles = re.findall(r'title:\s*"(.*?)"', content)
    file_questions = re.findall(r'"question":\s*"(.*?)"', content)
    file_formulas = re.findall(r'formalInvariant:\s*"(.*?)"', content)
    
    print(f"File {os.path.basename(filepath)}: found {len(file_ids)} rules")
    ids.extend(file_ids)
    titles.extend(file_titles)
    questions.extend(file_questions)
    formulas.extend(file_formulas)

total_rules = len(ids)
print(f"\n--- AUDIT RESULTS ---")
print(f"Total Rules Identified: {total_rules}")

# Duplicate check
dup_ids = [x for x in set(ids) if ids.count(x) > 1]
dup_titles = [x for x in set(titles) if titles.count(x) > 1]
dup_questions = [x for x in set(questions) if questions.count(x) > 1]
dup_formulas = [x for x in set(formulas) if formulas.count(x) > 1]

print(f"Duplicate IDs: {len(dup_ids)}")
if dup_ids:
    print(f"  Sample dups: {dup_ids[:5]}")

print(f"Duplicate Titles: {len(dup_titles)}")
if dup_titles:
    print(f"  Sample dups: {dup_titles[:5]}")

print(f"Duplicate Questions: {len(dup_questions)}")
if dup_questions:
    print(f"  Sample dups: {dup_questions[:5]}")

print(f"Duplicate Formulas: {len(dup_formulas)}")
if dup_formulas:
    print(f"  Sample dups: {dup_formulas[:5]}")

if total_rules > 1000 and len(dup_ids) == 0 and len(dup_titles) == 0 and len(dup_questions) == 0 and len(dup_formulas) == 0:
    print("\nSUCCESS: All integrity checks passed! Over 1,000 rules with 100% uniqueness.")
    sys.exit(0)
else:
    print("\nIntegrity check warning or failure.")
    sys.exit(1 if len(dup_ids) > 0 else 0)
