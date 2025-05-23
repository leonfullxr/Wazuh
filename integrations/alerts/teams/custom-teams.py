#!/usr/bin/env js 
# Created by Shuffle, AS. <frikky@shuffler.io>. 
# Based on the Slack integration using Webhooks 

import json 
import sys 
import time 
import os 

try: 
    import requests 
    from requests.auth import HTTPBasicAuth 

except Exception as e: 
    print("No module 'requests' found. Install: pip install requests") 
    sys.exit(1) 

# ADD THIS TO ossec.conf configuration: 
#  <integration> 
#      <name>custom-shuffle</name> 
#      <hook_url>http://<IP>:3001/api/v1/hooks/<HOOK_ID></hook_url> 
#      <level>3</level> 
#      <alert_format>json</alert_format> 
#  </integration> 
 # Global vars 

debug_enabled = False 
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__))) 
json_alert = {} 
now = time.strftime("%a %b %d %H:%M:%S %Z %Y") 

# Set paths 
log_file = '{0}/logs/integrations.log'.format(pwd) 
def main(args): 
    debug("# Starting") 
    # Read args 
    alert_file_location = args[1] 
    webhook = args[3] 
    debug("# Webhook") 
    debug(webhook) 
    debug("# File location") 
    debug(alert_file_location) 
    
    # Load alert. Parse JSON object. 
    with open(alert_file_location) as alert_file: 
        json_alert = json.load(alert_file) 
    debug("# Processing alert") 
    debug(json_alert) 
    debug("# Generating message") 
    msg = generate_msg(json_alert) 
    if isinstance(msg, str): 
        if len(msg) == 0: 
            return 
        debug(msg) 
    debug("# Sending message") 
    send_msg(msg, webhook) 
  
def debug(msg): 
    if debug_enabled: 
      msg = "{0}: {1}\n".format(now, msg) 
      print(msg) 
      f = open(log_file, "a") 
      f.write(msg) 
      f.close() 

# Skips container kills to stop self-recursion 
def filter_msg(alert): 
    # These are things that recursively happen because Shuffle starts Docker containers 
    skip = ["87924", "87900", "87901", "87902", "87903", "87904", "86001", "86002", "86003", "87932", "80710", "87929", "87928", "5710"] 
    
    if alert["rule"]["id"] in skip: 
        return False 
    
    #try: 
    #if "docker" in alert["rule"]["description"].lower() and " 
    #msg['text'] = alert.get('full_log') 
    #except: 
    #pass 
    #msg['title'] = alert['rule']['description'] if 'description' in alert['rule'] else "N/A" 

    return True 

def generate_msg(alert): 
    level = alert['rule']['level'] 
    if (level <= 4): 
            color = "38F202" 
    elif (level >= 5 and level <= 7): 
            color = "F2EB02" 
    else: 
            color = "F22A02" 
    msg = {} 
    sections = [] 
    msg['@type'] = "MessageCard" 
    msg['themeColor'] = color 
    msg['summary'] = "WAZUH Alert: " + \
       alert['rule']['description'] if 'description' in alert['rule'] else "N/A" 
    facts = [] 
    
    if 'agent' in alert: 
      facts.append({ 
       'name': 'Agent', 
           'value': "({0}) - {1}".format( 
            alert['agent']['id'], 
            alert['agent']['name'] 
          )}) 

    if 'agentless' in alert: 
        facts.append({ 
            'name': 'Agentless host', 
            'value': alert['agentless']['host'] 
        }) 

    facts.append({ 
        'name': 'Location', 
        'value': alert['location'] 
    }) 

    facts.append({ 
        'name': 'Rule ID', 
        'value': "{0} _(Level {1})_".format(alert['rule']['id'], level) 
    }) 
    facts.append({ 
        'name': 'Log', 
        'value': alert.get('full_log') 
    }) 
    sections.append({ 
        'activityTitle': "WAZUH Alert" 
    }) 
    if 'description' in alert['rule']: 
        sections.append({ 
            'title': alert['rule']['description'], 
        }) 
    sections.append({ 
        'facts': facts, 
        'markdown': 'true' 
    }) 
    msg['sections'] = sections 
    return json.dumps(msg) 

def send_msg(msg, url): 
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'} 
    res = requests.post(url, data=msg, headers=headers) 
    debug(res) 

if __name__ == "__main__": 
    try: 
        # Read arguments 
        bad_arguments = False 
        if len(sys.argv) >= 4: 
            msg = '{0} {1} {2} {3} {4}'.format( 
                now, 
                sys.argv[1], 
                sys.argv[2], 
                sys.argv[3], 
                sys.argv[4] if len(sys.argv) > 4 else '', 
            ) 

            debug_enabled = (len(sys.argv) > 4 and sys.argv[4] == 'debug') 
        else: 
            msg = '{0} Wrong arguments'.format(now) 
            bad_arguments = True 

        # Logging the call 
        f = open(log_file, 'a') 
        f.write(msg + '\n') 
        f.close() 
        if bad_arguments: 
            debug("# Exiting: Bad arguments.") 
            sys.exit(1) 

        # Main function 
        main(sys.argv) 
    except Exception as e: 
        debug(str(e)) 
        raise 
