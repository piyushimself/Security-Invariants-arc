#!/usr/bin/env python3
import json
import os
import sys

sys.path.append('scripts')
from generators.common import format_ts_file
from generators.gen_web import get_web_rules
from generators.gen_api import get_api_rules
from generators.gen_auth import get_auth_rules
from generators.gen_authz import get_authz_rules
from generators.gen_oauth import get_oauth_rules
from generators.gen_crypto import get_crypto_rules

print("Starting full curriculum generation...")

# First, write out the verified domain files we already have
web_rules = get_web_rules()
with open('src/data/domains/webRules.ts', 'w') as f:
    f.write(format_ts_file('webRules', web_rules))
print(f"Wrote webRules.ts ({len(web_rules)} rules)")

api_rules = get_api_rules()
with open('src/data/domains/apiRules.ts', 'w') as f:
    f.write(format_ts_file('apiRules', api_rules))
print(f"Wrote apiRules.ts ({len(api_rules)} rules)")

auth_rules = get_auth_rules()
with open('src/data/domains/authRules.ts', 'w') as f:
    f.write(format_ts_file('authRules', auth_rules))
print(f"Wrote authRules.ts ({len(auth_rules)} rules)")

authz_rules = get_authz_rules()
with open('src/data/domains/authzRules.ts', 'w') as f:
    f.write(format_ts_file('authzRules', authz_rules))
print(f"Wrote authzRules.ts ({len(authz_rules)} rules)")

oauth_rules = get_oauth_rules()
with open('src/data/domains/oauthRules.ts', 'w') as f:
    f.write(format_ts_file('oauthRules', oauth_rules))
print(f"Wrote oauthRules.ts ({len(oauth_rules)} rules)")

crypto_rules = get_crypto_rules()
with open('src/data/domains/cryptoRules.ts', 'w') as f:
    f.write(format_ts_file('cryptoRules', crypto_rules))
print(f"Wrote cryptoRules.ts ({len(crypto_rules)} rules)")

print("Initial 6 domains written successfully.")
