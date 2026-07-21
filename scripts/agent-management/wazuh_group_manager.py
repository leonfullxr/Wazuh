#!/usr/bin/python3
"""Interactive Wazuh agent group manager.

Uses the Wazuh REST API to create/delete agent groups and add/remove agents
from groups through a simple menu.

Usage:
    WAZUH_API_URL=https://<manager-ip>:55000 \
    WAZUH_API_USER=wazuh-wui \
    WAZUH_API_PASSWORD=<password> \
    ./wazuh_group_manager.py
"""

import json
import logging
import os
from base64 import b64encode

import requests
import urllib3

# Configuration (override via environment variables)
API_USER = os.environ.get("WAZUH_API_USER", "wazuh-wui")
API_PASSWORD = os.environ.get("WAZUH_API_PASSWORD", "wazuh-wui")
BASE_URL = os.environ.get("WAZUH_API_URL", "https://localhost:55000")

# Logging setup
log_file = '/tmp/wazuh_group_manager.log'
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Disable insecure https warnings (self-signed certs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_jwt_token():
    """Authenticates with the Wazuh API and returns the JWT token."""
    login_url = f"{BASE_URL}/security/user/authenticate"
    basic_auth = f"{API_USER}:{API_PASSWORD}".encode()
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Basic {b64encode(basic_auth).decode()}'
    }
    try:
        response = requests.post(login_url, headers=headers, verify=False, timeout=30)
        response.raise_for_status()
        return response.json()['data']['token']
    except requests.exceptions.RequestException as e:
        logger.error(f"Authentication failed: {e}")
        exit(1)
    except (json.JSONDecodeError, KeyError) as e:
        logger.error(f"Error parsing authentication response: {e}")
        exit(1)

def api_request(method, endpoint, token, params=None, data=None):
    """Makes a request to the Wazuh API with JWT authentication."""
    url = f"{BASE_URL}{endpoint}"
    headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}
    response = None
    try:
        response = requests.request(method, url, headers=headers, params=params, json=data, verify=False, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"API request failed for {method} {url}: {e}")
        if response is not None:
            try:
                error_data = response.json()
                logger.error(f"Error details: {json.dumps(error_data, indent=4)}")
            except json.JSONDecodeError:
                logger.error(f"Could not decode error response: {response.text}")
        exit(1)

def create_group(token, group_id):
    """Creates a new Wazuh agent group."""
    endpoint = "/groups"
    payload = {"group_id": group_id}
    response = api_request("POST", endpoint, token, data=payload)
    print(json.dumps(response, indent=4))
    logger.info(f"Group '{group_id}' created successfully.")
    print(f"Group '{group_id}' created successfully.")

def get_groups(token):
    """Retrieves a list of Wazuh agent groups."""
    endpoint = "/groups"
    response = api_request("GET", endpoint, token)
    return [group['name'] for group in response['data']['affected_items']]

def delete_group(token, groups_list):
    """Deletes specified Wazuh agent groups."""
    endpoint = "/groups"
    params = {"groups_list": ",".join(groups_list)}
    response = api_request("DELETE", endpoint, token, params=params)
    print(json.dumps(response, indent=4))
    logger.info(f"Groups '{groups_list}' deleted successfully.")
    print(f"Groups '{groups_list}' deleted successfully.")

def add_agent_to_group(token, agent_ids, group_id):
    """Adds specified agents to a Wazuh agent group."""
    endpoint = "/agents/group"
    params = {"group_id": group_id, "agents_list": ",".join(agent_ids)}
    response = api_request("PUT", endpoint, token, params=params)
    print(json.dumps(response, indent=4))
    logger.info(f"Agents '{agent_ids}' added to group '{group_id}' successfully.")
    print(f"Agents '{agent_ids}' added to group '{group_id}' successfully.")

def remove_agent_from_group(token, agent_ids, group_id):
    """Removes specified agents from a Wazuh agent group."""
    endpoint = "/agents/group"
    params = {"agents_list": ",".join(agent_ids), "group_id": group_id}
    response = api_request("DELETE", endpoint, token, params=params)
    print(json.dumps(response, indent=4))
    logger.info(f"Agents '{agent_ids}' removed from group '{group_id}' successfully.")
    print(f"Agents '{agent_ids}' removed from group '{group_id}' successfully.")

if __name__ == "__main__":
    token = get_jwt_token()

    while True:
        print("\n--- Wazuh Group Management ---")
        print("1. Create Group")
        print("2. Delete Group")
        print("3. Add Agent to Group")
        print("4. Remove Agent from Group")
        print("5. Exit")

        choice = input("Select an option: ")

        if choice == '1':
            print("\n--- Create Wazuh Group ---")
            group_name = input("Enter the name for the new group: ")
            if group_name in ['.', '..'] or not all(c.isalnum() or c in '_-.' for c in group_name) or len(group_name) > 128:
                print("Invalid group name. It can contain a-z, A-Z, 0-9, '_', '-', and '.' (excluding '.' and '..'), and must be <= 128 characters.")
            else:
                create_group(token, group_name)
            break  # Stop after successful operation
        elif choice == '2':
            print("\n--- Delete Wazuh Group ---")
            available_groups = get_groups(token)
            if not available_groups:
                print("No groups found.")
            else:
                print("Available Wazuh Groups:")
                for i, group in enumerate(available_groups):
                    print(f"{i + 1}. {group}")

                groups_to_delete = input("Enter the numbers of the groups to delete (comma-separated), or 'all': ").strip()

                if groups_to_delete.lower() == 'all':
                    confirm = input("Are you sure you want to delete ALL groups? (yes/no): ").lower()
                    if confirm == 'yes':
                        delete_group(token, ['all'])
                    else:
                        print("Deletion of all groups cancelled.")
                else:
                    selected_indices = groups_to_delete.split(',')
                    groups_to_delete_list = []
                    invalid_selection = False
                    for index_str in selected_indices:
                        try:
                            index = int(index_str.strip()) - 1
                            if 0 <= index < len(available_groups):
                                groups_to_delete_list.append(available_groups[index])
                            else:
                                print(f"Invalid selection: {index_str}")
                                invalid_selection = True
                                break
                        except ValueError:
                            print(f"Invalid input: {index_str}")
                            invalid_selection = True
                            break

                    if groups_to_delete_list and not invalid_selection:
                        print(f"Deleting groups: {', '.join(groups_to_delete_list)}")
                        delete_group(token, groups_to_delete_list)
                    elif invalid_selection:
                        print("Please provide valid group numbers.")
                    else:
                        print("No groups selected for deletion.")
            break  # Stop after successful operation
        elif choice == '3':
            print("\n--- Add Agent to Group ---")
            agent_ids_input = input("Enter the agent IDs to add (comma-separated): ").strip()
            agent_ids = [aid.strip() for aid in agent_ids_input.split(',')]
            if not agent_ids:
                print("No agent IDs provided.")
            else:
                available_groups = get_groups(token)
                if not available_groups:
                    print("No groups found.")
                else:
                    print("\nAvailable Wazuh Groups:")
                    for i, group in enumerate(available_groups):
                        print(f"{i + 1}. {group}")
                    group_selection = input("Enter the number of the target group: ").strip()
                    try:
                        group_index = int(group_selection) - 1
                        if 0 <= group_index < len(available_groups):
                            target_group = available_groups[group_index]
                            add_agent_to_group(token, agent_ids, target_group)
                        else:
                            print("Invalid group selection.")
                    except ValueError:
                        print("Invalid input for group selection.")
            break  # Stop after successful operation
        elif choice == '4':
            print("\n--- Remove Agent from Group ---")
            agent_ids_input = input("Enter the agent IDs to remove (comma-separated): ").strip()
            agent_ids = [aid.strip() for aid in agent_ids_input.split(',')]
            if not agent_ids:
                print("No agent IDs provided.")
            else:
                available_groups = get_groups(token)
                if not available_groups:
                    print("No groups found.")
                else:
                    print("\nAvailable Wazuh Groups:")
                    for i, group in enumerate(available_groups):
                        print(f"{i + 1}. {group}")
                    group_selection = input("Enter the number of the group to remove agents from: ").strip()
                    try:
                        group_index = int(group_selection) - 1
                        if 0 <= group_index < len(available_groups):
                            target_group = available_groups[group_index]
                            remove_agent_from_group(token, agent_ids, target_group)
                        else:
                            print("Invalid group selection.")
                    except ValueError:
                        print("Invalid input for group selection.")
            break  # Stop after successful operation
        elif choice == '5':
            print("Exiting.")
            break
        else:
            print("Invalid choice. Please select a valid option.")
