import boto3
import json
import ssl
import urllib
import urllib2
import xml.etree.ElementTree as ET
import gzip

def paloalto_rule_move(pa_ip,pa_key,params):
    # Move rule locatoin in security rule base
    # Input: Palo Alto gateway IP, Palo Alto Access Key, and Params
    # Params is a dict with 3 paramaters {'location','rule_name','dst_rule'}
    # Params['location'] values: 'top' and 'bottom' values will move the rule to the absolute top or bottom of rule base), 'before' and 'after' will move the rule to a location relevant to another rule
    # Params['rule_name']: name of the rule to be moved
    # Params['dst_rule']: used when Params['location'] is set, and is used as a reference for where the rule is to be moved
    
    
    # set the context to ignore unverified SSL certificates
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    cmd = "/api/?type=config&action=move&"

    if params['location'] == 'top':
        parameters = {'xpath': "/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/rulebase/security/rules/entry[@name=\'"+params['rule_name']+"\']",'where':"top"}
    elif params['location'] == 'bottom':
        parameters = {'xpath': "/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/rulebase/security/rules/entry[@name=\'"+params['rule_name']+"\']",'where':"bottom"}
    elif params['location'] == 'after':
        parameters = {'xpath': "/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/rulebase/security/rules/entry[@name=\'"+params['rule_name']+"\']",'where':"after",'dst':params['dst_rule']}
    elif params['location'] == 'before':
        parameters = {'xpath': "/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/rulebase/security/rules/entry[@name=\'"+params['rule_name']+"\']",'where':"before",'dst':params['dst_rule']}
         
    url = "https://"+pa_ip+cmd+"Key="+pa_key+"&"+urllib.urlencode(parameters)
    response = urllib2.urlopen(url, context=ctx)
    contents= ET.fromstring(response.read())

def paloalto_rule_findbyname(pa_ip,pa_key,rule_name):  
	# Finds rules in current security policy that have a name which contains 'rule_name'
	# Input: Palo Alto gateway IP, Palo Alto Access Key, and rule name
	# returns a list of matching rule names

	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE

	cmd = "/api/?type=config&action=get&"

	url = "https://"+pa_ip+cmd+"Key="+pa_key+"&"+urllib.urlencode({'xpath':"/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/rulebase/security/rules"})

	response = urllib2.urlopen(url, context=ctx)
	contents= ET.fromstring(response.read())

	result = []
	for i in contents[0][0]:
		if rule_name in i.attrib['name']:
			result.append(i.attrib['name'])

	return result
    
def paloalto_rule_add(pa_ip,pa_key,rule_params):
	# Add a new rule on Palo Alto gateway
	# Input: Palo Alto gateway IP, Palo Alto Access Key, and rule_params
	# rule_params are the parameters to be configured for the new rule. It is a dictionary with the following values:
	# rule_params['name']: name of the rule
	# rule_params['dstZone']: destination zone
	# rule_params['srcZone']: source zone
	# rule_params['srcIP']: list of source IP addresses
	# rule_params['dstIP']: list of destination IP addresses
	# rule_params['application']: application 
	# rule_params['service']: service
	# rule_params['action']: rule action (allow, deny)
	# rule_params['spg']: name of security group profile to be set 
	# Output: returns 'success' or 'fail' depending on the result

	
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    existing_rules = paloalto_rule_findbyname(pa_ip,pa_key,rule_params['name'])
    if len(existing_rules) != 0:
        rule_params['name'] = rule_params['name'] + "-" + str(len(existing_rules)+1)

    rule_source_ip = ""
    rule_destination_ip = ""
    for i in rule_params['srcIP']:
        rule_source_ip = rule_source_ip + "<member>"+i+"</member>"

    for i in rule_params['dstIP']:
        rule_destination_ip = rule_destination_ip + "<member>"+i+"</member>"

	cmd = "/api/?type=config&action=set&"
	parameters = {'xpath':"/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/rulebase/security/rules/entry[@name=\'"+rule_params['name']+"\']",'element':"<to><member>"+rule_params['dstZone']+"</member></to><from><member>"+rule_params['srcZone']+"</member></from><source>"+rule_source_ip+"</source><destination>"+rule_destination_ip+"</destination><application><member>"+rule_params['application']+"</member></application><service><member>"+rule_params['service']+"</member></service><action>"+rule_params['action']+"</action><profile-setting><group><member>"+rule_params['spg']+"</member></group></profile-setting>"}


	url = "https://"+pa_ip+cmd+"Key="+pa_key+"&"+urllib.urlencode(parameters)

	response = urllib2.urlopen(url, context=ctx)


	contents= ET.fromstring(response.read())

	result = 'success'
	return result 

def paloalto_find_matchingrule(pa_ip,pa_key,rule_params):
	# Find if there are existing rules that cover the traffic described by rule_params
	# Input: Palo Alto gateway IP, Palo Alto Access Key, and rule_params
	# rule_params is a dictoinary with the following values
	# rule_params['dstZone']: destination zone
	# rule_params['srcZone']: source zone
	# rule_params['srcIP']: source IP address
	# rule_params['dstIP']: destination IP address
	# rule_params['application']: application 
	# rule_params['dstPort']: destination port
	# rule_params['protocol']: IP protocol type
	# Output: Returns the name of matching rule or "" if no matches were found

	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE

	cmd = "/api/?type=op&"
	
	result = []
	
	if rule_params['protocol'] == 'tcp':
		rule_params['protocol'] = '6'
	elif rule_params['protocol'] == 'udp':
		rule_params['protocol'] = '17'
	elif rule_params['protocol'] == 'icmp':
		rule_params['protocol'] = '1'
	else: # if its not one of the above protocols, we cannot test properly
		return result
	
	if rule_params['dstPort'] == 'any': #we cannot test if destination port is set to 'any'
		return result
	#parse through all source/destination IP combinations
	
	for i in rule_params['srcIP']:
		for j in rule_params['dstIP']:		
			#format IP addresses properly. 
			if i == 'any':
				i = "0.0.0.0" 
			if j == 'any':
				j = "0.0.0.0"
			if "/" in i:
				i = i.split('/')[0]
			if "/" in j:
				j = j.split('/')[0]
			if 'application' in rule_params:
				if rule_params['application'] == 'icmp':
					parameters = {'cmd':"<test><security-policy-match><from>"+rule_params['srcZone']+"</from><to>"+rule_params['dstZone']+"</to><application>"+rule_params['application']+"</application><protocol>"+rule_params['protocol']+"</protocol><destination>"+j+"</destination><source>"+i+"</source></security-policy-match></test>"}
				else:
					parameters = {'cmd':"<test><security-policy-match><from>"+rule_params['srcZone']+"</from><to>"+rule_params['dstZone']+"</to><application>"+rule_params['application']+"</application><protocol>"+rule_params['protocol']+"</protocol><destination-port>"+rule_params['dstPort']+"</destination-port><destination>"+j+"</destination><source>"+i+"</source></security-policy-match></test>"}
			else:
				parameters = {'cmd':"<test><security-policy-match><from>"+rule_params['srcZone']+"</from><to>"+rule_params['dstZone']+"</to><protocol>"+rule_params['protocol']+"</protocol><destination-port>"+rule_params['dstPort']+"</destination-port><destination>"+j+"</destination><source>"+i+"</source></security-policy-match></test>"}
				
			url = "https://"+pa_ip+cmd+"Key="+pa_key+"&"+urllib.urlencode(parameters)
			print "in rulematch function: ",url
			response = urllib2.urlopen(url, context=ctx)
			contents= ET.fromstring(response.read())
			print contents.tag
			print contents.text
			print "contents: ", contents[0][0]
			if (contents[0][0].text != "\n"):
				result.append(contents[0][0][0].text)
	return result

def paloalto_service_find(pa_ip,pa_key,protocol,port):
	# Find if there are service objects that match a certain port and protocol type
	# Input: Palo Alto gateway IP, Palo Alto Access Key, IP protocol type, and port number
	# Output: Returns service object name if found or "" if there are no matches
	
	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE

	cmd = "/api/?type=config&action=get&"
	parameters = {'xpath':"/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/service"}
	url = "https://"+pa_ip+cmd+"Key="+pa_key+"&"+urllib.urlencode(parameters)

	response = urllib2.urlopen(url, context=ctx)
	contents= ET.fromstring(response.read())

	result = ""

	for i in contents[0][0]:
		if i[0][0].tag == protocol:
			for j in i[0][0]:
				if j.tag == 'port' and j.text == port:
					result = i.attrib['name']

	return result

def paloalto_service_add(pa_ip,pa_key,protocol,port):
	# Create a new service object given a port and protocol type (Format of new service object name: "<protocol>_<port#>"
	# Input: Palo Alto gateway IP, Palo Alto Access Key, IP protocol type, and port number
	# Output: Returns service object name created.
	
	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE

	cmd = "/api/?type=config&action=set&"
	parameters = {'xpath': "/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/service/entry[@name=\'"+protocol+"_"+str(port)+"\']/protocol/tcp",'element':"<port>"+str(port)+"</port>"}

	print "https://"+pa_ip+cmd+"Key="+pa_key+"&"+parameters['xpath']
	url = "https://"+pa_ip+cmd+"Key="+pa_key+"&"+urllib.urlencode(parameters)

	response = urllib2.urlopen(url, context=ctx)
	contents= ET.fromstring(response.read())

	return protocol+"_"+str(port)

def paloalto_commit(pa_ip,pa_key):
	# Commit changes to Palo Alto gateway
	# Input: Palo Alto gateway IP, Palo Alto Access Key
	
	cmd = "/api/?type=commit&action=set&"
	url = "https://"+pa_ip+cmd+"Key="+pa_key+"&cmd=<commit></commit>"

	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE

	response = urllib2.urlopen(url, context=ctx)
	print response.code
	contents= ET.fromstring(response.read())
	print contents.tag
	print contents.attrib
	print contents.text

	result = 'success'
	return result
        
def paloalto_rule_delete(pa_ip,pa_key,rule_name):
	# Delete a rule on the Palo Alto gateway that matches the rule_name provided
	# Input: Palo Alto gateway IP, Palo Alto Access Key, and rule_name
	
	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE

	cmd = "/api/?type=config&action=delete&"

	url = "https://"+pa_ip+cmd+"Key="+pa_key+"&"+urllib.urlencode({'xpath':"/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/rulebase/security/rules/entry[@name=\'"+rule_name+"\']"})

	print url    
	response = urllib2.urlopen(url, context=ctx)
	print response.code
	contents= ET.fromstring(response.read())
	print contents.tag
	print contents.attrib
	print contents.text

	result = 'success'
	return result

def paloalto_rule_getdetails(pa_ip,pa_key,rule_name):
	# Return the rule details that match the rule_name provided
	# Input: Palo Alto gateway IP, Palo Alto Access Key, and rule_name
	# Output: dictionary with the following values:
	# 'dstZone': destination zone
	# 'srcZone': source zone
	# 'srcIP': list of source IP addresses
	# 'dstIP': list of destination IP addresses
	# 'application': application name
	# 'service': service object name
	# 'action': rule action
	
	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE

	cmd = "/api/?type=config&action=get&"

	url = "https://"+pa_ip+cmd+"Key="+pa_key+"&"+urllib.urlencode({'xpath':"/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/rulebase/security/rules/entry[@name=\'"+rule_name+"\']"})

	response = urllib2.urlopen(url, context=ctx)
	contents= ET.fromstring(response.read())

	results = {} 
	results['srcIP'] = []
	results['dstIP'] = []
	for i in contents[0][0]:
		if i.tag == 'to':
			results['dstZone']=i[0].text
		elif i.tag == 'from':
			results['srcZone']=i[0].text
		elif i.tag == 'source':
			for j in i:
				results['srcIP'].append(j.text)
		elif i.tag == 'destination':
			for j in i:
				results['dstIP'].append(j.text)
		elif i.tag == 'application':
			results['application']=i[0].text
		elif i.tag == 'service':
			results['service']=i[0].text
		elif i.tag == 'action':
			results['action']=i.text
	#results['name']=rule_name

	return results

