from pymisp import PyMISP, MISPEvent
import requests
import re
import sys
misp_url = '<misp_url>'
misp_key = '<misp_api>'
misp_verifycert = False
event_id = <event_id>
session = requests.Session()
session.verify = misp_verifycert
PyMISP.global_session = session
misp = PyMISP(misp_url, misp_key, ssl=False)
event = misp.get_event(event_id)
def identify_string(input_string):
    ip = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    hash = re.compile(r'\b[A-Fa-f0-9]{32,}\b|\b[A-Fa-f0-9]{40,}\b|\b[A-Fa-f0-9]{64,}\b')  
    domain = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
    if ip.match(input_string):
        return "IP Address"
    elif hash.match(input_string):
        return "Hash"
    elif domain.match(input_string):
        return "Domain"
    else:
        return "Unknown"
if event is None:
    print(f'Error: Event with ID {event_id} not found.')
    exit()
try:
    with open(sys.argv[1],"r",encoding="utf-8") as attr:
        attr_=attr.readlines()
        for j in attr_:
            print(identify_string(j))
            if identify_string(j) == "IP Address":
                attribute = {
                    'type': 'ip-dst',
                    'value': j
                }
            elif identify_string(j) == "Domain":
                attribute = {
                    'type': 'domain',
                    'value': j
                }
            elif identify_string(j) == "Hash":
                attribute = {
                    'type': 'sha256',
                    'value': j
                }
            try:
                misp.add_attribute(event_id, attribute)
                print(f'Successfully added IOC: {j}.')
            except Exception as e:
                print(f'Error adding attribute: {e}')
except IndexError:
    print("Usage: python3 main.py <ioc_list.txt>")
