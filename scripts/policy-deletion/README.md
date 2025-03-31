# 30-day deletion policy
As all logs are stored in /var/ossec/logs/alerts|archives/, you have to set up a cronjob to delete them periodically according to your retention policy. For this, you can follow these steps for a 30-day deletion policy as an example:

1. Create a script called cleanup.sh and store it in your manager:
2. Create a cronjob to run this daily:

    ```
    0 2 * * * /path/to/cleanup.sh >/dev/null 2>&1
    ```
    
    - This script will run daily at 2am and delete all log files older than 30 days (in this case).
        

The timeframe can be personalized according the variables in the script according to how long you want to keep the archives for.

For the indexer, you can also create an Index Management Policy:

- Go to **Index Management > Index Policies**
    

- And create the policy as recommended (change dates as needed):
    
    ```
    {
        "policy": {
            "description": "Wazuh index state management for Wazuh to move indices into a cold state after 30 days and delete them after a year.",
            "default_state": "hot",
            "states": [
                {
                    "name": "hot",
                    "actions": [
                        {
                            "replica_count": {
                                "number_of_replicas": 0
                            }
                        }
                    ],
                    "transitions": [
                        {
                            "state_name": "cold",
                            "conditions": {
                                "min_index_age": "30d"
                            }
                        }
                    ]
                },
                {
                    "name": "cold",
                    "actions": [
                        {
                            "read_only": {}
                        }
                    ],
                    "transitions": [
                        {
                            "state_name": "delete",
                            "conditions": {
                                "min_index_age": "365d"
                            }
                        }
                    ]
                },
                {
                    "name": "delete",
                    "actions": [
                        {
                            "delete": {}
                        }
                    ],
                    "transitions": []
                }
            ],
           "ism_template": {
               "index_patterns": ["wazuh-alerts*"],
               "priority": 100
           }
        }
    }
    ```
    

