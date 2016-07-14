# Paloalto-fw
functions to interact with Palo Alto gateways (Tested with Pan-OS 7.1)

July 14 2016:
Initial version uploaded. Following functions included:
* paloalto_rule_move: move a specified security rule to a specific location
* paloalto_rule_findbyname: find all security rules that contain a specified name
* paloalto_rule_add: add new security rules
* paloalto_find_matchingrule: find a rule that matches certain traffic
* paloalto_service_find: find existing service objects that match specific port and protocol
* paloalto_service_add: created new service object
* paloalto_commit: commit changes
* paloalto_rule_delete: delete a specific rule
* paloalto_rule_getdetails: get rule parameters for a specified rule
