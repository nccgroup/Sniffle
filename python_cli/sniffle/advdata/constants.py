# Written by Sultan Qasim Khan
# Copyright (c) 2024, NCC Group plc
# Released as open source under GPLv3

import os
from .yaml import decode_yaml

company_identifiers = {}
ad_types = {}
service_uuids16 = {}

def an_relpath(fname):
    return os.path.join(os.path.dirname(__file__), "assigned_numbers", fname)

with open(an_relpath("company_identifiers/company_identifiers.yaml"), 'rb') as f:
    y = decode_yaml(f.read())["company_identifiers"]
    for c in y:
        company_identifiers[c["value"]] = c["name"]

with open(an_relpath("core/ad_types.yaml"), 'rb') as f:
    y = decode_yaml(f.read())["ad_types"]
    for t in y:
        ad_types[t["value"]] = t["name"]

with open(an_relpath("uuids/service_uuids.yaml"), 'rb') as f:
    y = decode_yaml(f.read())["uuids"]
    for u in y:
        service_uuids16[u["uuid"]] = u["name"]
