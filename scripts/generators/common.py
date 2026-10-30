import json

def format_ts_file(variable_name, rules):
    # Produce clean TypeScript code
    content = "import { SecurityInvariant } from '../../types/invariants';\n\n"
    content += f"export const {variable_name}: SecurityInvariant[] = [\n"
    
    rule_blocks = []
    for r in rules:
        block = "  {\n"
        block += f"    ruleNumber: {r['ruleNumber']},\n"
        block += f"    id: {json.dumps(r['id'])},\n"
        block += f"    title: {json.dumps(r['title'])},\n"
        block += f"    domain: {json.dumps(r['domain'])},\n"
        block += f"    domainName: {json.dumps(r['domainName'])},\n"
        block += f"    subdomain: {json.dumps(r['subdomain'])},\n"
        block += f"    difficulty: {json.dumps(r['difficulty'])},\n"
        block += f"    standardType: {json.dumps(r['standardType'])},\n"
        block += f"    standards: {json.dumps(r['standards'])},\n"
        block += f"    formalInvariant: {json.dumps(r['formalInvariant'])},\n"
        
        # symbolBreakdown
        sb_json = json.dumps(r['symbolBreakdown'], indent=6)
        sb_indented = "\n".join("    " + line if i > 0 else line for i, line in enumerate(sb_json.split("\n")))
        block += f"    symbolBreakdown: {sb_indented},\n"
        
        block += f"    plainEnglish: {json.dumps(r['plainEnglish'])},\n"
        block += f"    whyItMatters: {json.dumps(r['whyItMatters'])},\n"
        
        # vulnerableExample
        ve_json = json.dumps(r['vulnerableExample'], indent=6)
        ve_indented = "\n".join("    " + line if i > 0 else line for i, line in enumerate(ve_json.split("\n")))
        block += f"    vulnerableExample: {ve_indented},\n"
        
        # secureExample
        se_json = json.dumps(r['secureExample'], indent=6)
        se_indented = "\n".join("    " + line if i > 0 else line for i, line in enumerate(se_json.split("\n")))
        block += f"    secureExample: {se_indented},\n"
        
        # howToTest
        ht_json = json.dumps(r['howToTest'], indent=6)
        ht_indented = "\n".join("    " + line if i > 0 else line for i, line in enumerate(ht_json.split("\n")))
        block += f"    howToTest: {ht_indented},\n"
        
        # interviewChallenge
        ic_json = json.dumps(r['interviewChallenge'], indent=6)
        ic_indented = "\n".join("    " + line if i > 0 else line for i, line in enumerate(ic_json.split("\n")))
        block += f"    interviewChallenge: {ic_indented},\n"
        
        if 'simulation' in r and r['simulation']:
            sim_json = json.dumps(r['simulation'], indent=6)
            sim_indented = "\n".join("    " + line if i > 0 else line for i, line in enumerate(sim_json.split("\n")))
            block += f"    simulation: {sim_indented}\n"
        else:
            block = block.rstrip(",\n") + "\n"
            
        block += "  }"
        rule_blocks.append(block)
        
    content += ",\n".join(rule_blocks)
    content += "\n];\n"
    return content
