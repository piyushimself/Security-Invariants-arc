#!/usr/bin/env python3
import json
import os
import sys

sys.path.append('scripts')
from generators.common import format_ts_file

# Helper to build a high-fidelity invariant record
def make_invariant(
    rule_num,
    rule_id,
    title,
    domain,
    domain_name,
    subdomain,
    difficulty,
    standard_type,
    standards,
    formal_inv,
    sym_breakdown,
    plain_english,
    why_matters,
    vuln_lang,
    vuln_code,
    vuln_expl,
    sec_lang,
    sec_code,
    sec_expl,
    test_tools,
    test_steps,
    test_cmd,
    scenario,
    question,
    hint,
    sample_answer,
    key_takeaway,
    sim=None
):
    inv = {
        "ruleNumber": rule_num,
        "id": rule_id,
        "title": title,
        "domain": domain,
        "domainName": domain_name,
        "subdomain": subdomain,
        "difficulty": difficulty,
        "standardType": standard_type,
        "standards": standards,
        "formalInvariant": formal_inv,
        "symbolBreakdown": sym_breakdown,
        "plainEnglish": plain_english,
        "whyItMatters": why_matters,
        "vulnerableExample": {
            "language": vuln_lang,
            "code": vuln_code,
            "explanation": vuln_expl
        },
        "secureExample": {
            "language": sec_lang,
            "code": sec_code,
            "explanation": sec_expl
        },
        "howToTest": {
            "tools": test_tools,
            "steps": test_steps,
            "commandExample": test_cmd
        },
        "interviewChallenge": {
            "scenario": scenario,
            "question": question,
            "hint": hint,
            "sampleAnswer": sample_answer,
            "keyTakeaway": key_takeaway
        }
    }
    if sim:
        inv["simulation"] = sim
    return inv

print("Generator helper loaded.")
