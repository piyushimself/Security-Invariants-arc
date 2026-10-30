#!/usr/bin/env python3
import os
import sys

sys.path.append('scripts')
from generators.common import format_ts_file
from generators.gen_threat_modeling import generate_threat_modeling_rules
from generators.gen_containers_advanced import generate_containers_advanced_rules
from generators.gen_codereview_advanced import generate_codereview_advanced_rules
from generators.gen_ai_advanced import generate_ai_advanced_rules
from generators.gen_web3_advanced import generate_web3_advanced_rules

print("Building all advanced curriculum modules...")

# 1. Threat Modeling: 105 rules (512 to 616)
tm_rules = generate_threat_modeling_rules()
with open('src/data/domains/threatModelingRules.ts', 'w') as f:
    f.write(format_ts_file('threatModelingRules', tm_rules))
print(f"Wrote threatModelingRules.ts ({len(tm_rules)} rules, {tm_rules[0]['id']} to {tm_rules[-1]['id']})")

# 2. Containers Advanced: 105 rules (617 to 721)
cont_rules = generate_containers_advanced_rules()
with open('src/data/domains/containerAdvancedRules.ts', 'w') as f:
    f.write(format_ts_file('containerAdvancedRules', cont_rules))
print(f"Wrote containerAdvancedRules.ts ({len(cont_rules)} rules, {cont_rules[0]['id']} to {cont_rules[-1]['id']})")

# 3. Code Review Advanced: 105 rules (722 to 826)
code_rules = generate_codereview_advanced_rules()
with open('src/data/domains/codeReviewAdvancedRules.ts', 'w') as f:
    f.write(format_ts_file('codeReviewAdvancedRules', code_rules))
print(f"Wrote codeReviewAdvancedRules.ts ({len(code_rules)} rules, {code_rules[0]['id']} to {code_rules[-1]['id']})")

# 4. AI Advanced: 105 rules (827 to 931)
ai_rules = generate_ai_advanced_rules()
with open('src/data/domains/aiAdvancedRules.ts', 'w') as f:
    f.write(format_ts_file('aiAdvancedRules', ai_rules))
print(f"Wrote aiAdvancedRules.ts ({len(ai_rules)} rules, {ai_rules[0]['id']} to {ai_rules[-1]['id']})")

# 5. Web3 Advanced: 105 rules (932 to 1036)
web3_rules = generate_web3_advanced_rules()
with open('src/data/domains/web3AdvancedRules.ts', 'w') as f:
    f.write(format_ts_file('web3AdvancedRules', web3_rules))
print(f"Wrote web3AdvancedRules.ts ({len(web3_rules)} rules, {web3_rules[0]['id']} to {web3_rules[-1]['id']})")

total_new = len(tm_rules) + len(cont_rules) + len(code_rules) + len(ai_rules) + len(web3_rules)
print(f"Total new advanced rules generated: {total_new}. Combined total with existing 511 rules: {511 + total_new} rules.")
