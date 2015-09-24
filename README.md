The content posted here is related to a presentation I gave at the Splunk .conf2015.  This is not, by any stretch of the imagination, a complete and polished app.  I have included Splunk config files to get you started.  The scripts are very bare bones and include no error checking, input validation, etc.  I recommend you have somebody with some scripting skills make them production ready.  If you wish to share more mature versions with me, I will happily provide attribution.

##########  vFeed  ##########
vFeed can be installed with git.  In my setup, I installed it in /opt/vFeed by running:
	cd /opt
	git clone https://github.com/toolswatch/vFeed
	
To update the database, run:  

	python vfeedcli.py --update
	
The database file is called vfeed.db.  The Splunk DB Connect app expects SQLite databases to have a sqlitedb extension.  So, create a symbolic link:

	ln -s vfeed.db vfeed.sqlitedb
	
Install the DB Connect 1 app in Splunk.  Point Splunk at the path to the vfeed.sqlitedb file.  The config asks for a username, but it's irrelevant.

I have noticed some occasional consistency problems in the data, such as having garbled CVE IDs and a few other things.  I have created a lookup table for virtually every table in vFeed and created a search to dump that table and sanitize the data.  Since vFeed is aggregating and normalizing data from the Internet, it has to work with what it has.  Sometimes the originating data source doesn't include the URL for things like vendor advisories and such.  I have done my best to add URLs to everything that I could.

The lookup tables are updated nightly.

After downloading the Common Information Model app, look at the Vulnerabilities data model.  You will see that the top level search is driven off of a couple of tags.  I recommend modifying the search with something like:

	tag=vulnerabilities tag=report | lookup nessus_cve_lookup nessus OUTPUT cve | mvexpand cve | dedup dest,protocol,dest_port,nessus,cve | lookup nvd_db_lookup cve OUTPUT cvss_base, cvss_impact, cvss_exploit, cvss_access_vector, cvss_authentication, cvss_access_vector, cvss_availability_impact, cvss_integrity_impact, cvss_confidentiality_impact
	
There are also times when the Nessus plugins will have OSVDB or Bugtraq IDs that may be more recent than the data in vFeed.  You may wish for your data model/kvstore searches to also do a lookup on those two IDs and return the CVE ID as something like bugtraq_cve or osvdb_cve.  Then use eval to combine the cve, bugtraq_cve, and osvdb_cve fields, run mvexpand, and dedup the CVE IDs.

The search to correlate Snort IDS events with Nessus might look something like:

	sourcetype=snort | lookup cve_snort_lookup snort OUTPUT cve | mvexpand cve | lookup nessus_results_lookup dest,protocol,dest_port,cve OUTPUT signature | search signature=*
	
##########  Dynamic Scanning  ##########

Create a search that will find all the switches you want to use for dynamic scanning and save them to a lookup table.  

Configure the appropriate scanning policy and scan config for each subnet on each Nessus scanner.  You can use the following curl example to dump the list of scan policies on a scanner (you'll need to login first to get the token):

	# get the token
	curl -k -X POST -H 'Content-Type: application/json' -d '{"username":“nessus","password":“ne55us"}' https://10.10.10.10:8834/session 2>&1 | grep -Po '(?<=\"token\":\")[^\"]+'

	# insert token from above after the "token=" part
	curl -k -H 'X-Cookie: token=f99a30c7d590f07880f27aa913ee705955bcaa7b7d51e041' https://10.10.10.10:8834/scans

In Nessus 5.x, scans are referenced by the UUID.  In Nessus 6.x, they use the "id" to interact with it in the API.

Create a lookup table such as nessus_scanner_config_lookup and set it to a CIDR match type.  If you want to keep everything neatly in one app in Splunk, if you are a SideView Utils user, you can copy the SideView lookup table editor into your app and hard code it to that particular table.

Populate the lookup table with the subnet range to be scanned, the IP/hostname of the scanner, and the ID of the scan to use.  It should look something like:

	dest,"nessus_ip","scan_id"
	"192.168.1.0/24","192.168.1.194",6
	
If you aren't super comfortable with scripting and regex, create another lookup table that contains the IPs/hostnames of all of your scanners.  You can use this list to iterate through your scanners and check the status of your scans.  It is trivial to use sed to strip the header from the lookup table.

You also need to create a lookup table to hold the queue of IP addresses that need to be scanned.  I used nessus_scan_queue_lookup.

Use a simple bash loop to iterate through the list of switches and dump the ARP cache (IPv4) or the address table for IPv6:

	for switch in `cat ../lookups/switches.csv | sed “1d”`;
	do
	  snmpwalk –c public –v 2c $switch ipNetToPhysicalPhysAddress 
	done

You can either choose to write the output to a file and eat it with a file input or you can use something like the Linux "tee" command after the snmpwalk command and just index the output of the script directly.  See examples in the *nix app.  I used "snmp_arp" as the sourcetype for this data.

Create a lookup table to contain the scan status history.  I used nessus_last_scan_lookup as the name.  I like to keep track of the IP address and the hostname if Nessus could resolve it as well as the MAC address.  

Let's say you want to scan your hosts daily.  You need to find all of the IP/MAC addresses that you currently know about from your ARP data and give each a random time in the next 24 hours as the initial "last_scan" time.  The search below looks for Nessus events that indicate a host is being scanned or the event for hostname resolution as well as the snmp_arp events and combines them with the transaction command.  This should give you a combined event with the IP and hostname (Nessus) and IP/MAC address (snmp_arp).  Because of the output from snmpwalk, the MAC address needs to be tweaked with the sed functionality of rex to replace spaces with colons.

	(sourcetype="nessus" AND signature="12053" OR signature="19506") OR sourcetype=snmp_arp | rex field=_raw "(?i)resolves as (?P<hostname>[^$]+)(?=\.)" | rex mode=sed field=dest_mac "s/\s/:/g"| transaction maxspan=1h dest | eval padding=random()/2147483648*86400 | eval last_scan=now()+padding | table last_scan,hostname,dest,dest_mac | outputlookup nessus_last_scan_lookup
	
Now you want to take your snmp_arp events, look up the MAC address in the nessus_last_scan_lookup, and see if the time difference between the event and the last_scan is greater than one day (86400).  If the difference is greater than one day, you need to lookup the scanner IP and scan ID for the subnet the host is on.  You then need to collapse all of the individual events that share the same scanner IP and scan ID into a single event where the "dest" field is multivalued and comma separated.  Those events are then written to the scan queue:

	sourcetype=snmp_arp | rex mode=sed field=dest_mac "s/\s/:/g" | lookup nessus_last_scan_lookup dest_mac OUTPUT last_scan | eval diff=now()-last_scan | search diff>86400 | lookup nessus_scanner_config_lookup dest OUTPUT nessus_ip,scan_id | table dest,nessus_ip,scan_id | mvcombine dest | makemv delim="," dest | outputlookup nessus_scan_queue_lookup

Write a script that will iterate through each line in the scan queue and extract the list of IPs, the scanner IP, and scan ID into variables and use them to launch the scan from the command line:

	for scan in `cat /opt/splunk/etc/apps/vFeed/lookups/nessus_scan_queue_lookup.csv | sed '1d'`; 
		do
			targets = `echo $scan | grep -Po '^\"[^\"]+\"'`
			scanner = `echo $scan | grep -Po '(?<=\",\")\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'`
			scan_id = `echo $scan | grep -Po '(?<=\",)\d+$'`
			
			token = `curl -k -X POST -H 'Content-Type: application/json' -d '{"username":“nessus","password":“ne55us"}' https://$scanner/session 2>&1 | grep -Po '(?<=\"token\":\")[^\"]+'`
			
			curl -k -X POST -H 'X-Cookie: token=$token' -H 'Content-Type: application/json' -d '{"alt_targets": [$targets]}' https://$scanner:8834/scans/$scan_id/launch
		
		done
		
Create a script that will check the status of scan jobs and write that to a file or index it directly using a scripted input:

	scanners=`cat /opt/splunk/etc/apps/vFeed/lookups/nessus_scanners_lookup.csv | sed -e "1d"`
	for host in $scanners;
    do
		echo nessus_ip=\"$host\"
		token=`curl -k -X POST -H 'Content-Type: application/json' -d '{"username":"nessus","password":"ne55us"}' https://$host:8834/session 2>&1 | grep -Po '(?<=\"token\":")[^\"]+'`
		scans=`curl -sk -H 'X-Cookie: token='$token'' https://$host:8834/scans`
		echo $scans >> scan_status.txt
    done 

Create a lookup table to hold the status of scans.  I used nessus_scan_status_lookup.  Create a search that will find all of the completed scans and write the scanner IP and scan_id to the lookup:

	sourcetype=scan_status | rex max_match=100 field=_raw "(?P<scan>\{\"folder_id[^\}]+)" | mvexpand scan | rex field=scan "\"id\":(?P<scan_id>\d+)" | rex field=scan "\"status\":\"(?P<status>\w+)" | search status=completed | table nessus_ip,scan_id | outputlookup nessus_scan_status_lookup

Create a file input that will monitor the "files" directory of the Nessus user you use to launch the scan.  This will be located in /opt/nessus/var/nessus/users/$username$/files.  Have it index anything with a CSV extension.  

Create a script that will iterate through the nessus_scan_status_lookup table, connect to the Nessus scanner, and export the scan to CSV format.  The basic examples above can serve as a guide.  AN example of the API command is:

	curl -k -X POST -H 'X-Cookie: token=f8f0b0821d0ef193d346a2951dbc9e28314bcf232d40e4e7' -H 'Content-Type: application/json' -d '{"format": "csv"} ' https://10.10.10.10:8834/scans/6/export

The CSV file will appear in the user's directory.  Nessus will automatically remove the file after 15 minutes or so, but that is more than enough time for Splunk to index it.  Now your Nessus events are in an easily consumable format in Splunk.

########## Collective Intelligence Framework  ##########

Get CIF from:  https://code.google.com/p/collective-intelligence-framework/ 

If you use version 1, the backend is postgres and easy to integrate into Splunk.  Depending on your environment, you may have to configure postgres to run on something other than the loopback address.

Use the DB connect app to connect to CIF.  You will notice that each type of data has a separate database table for the category of data.  So for IP addresses, there is a table for botnets, scanners, spammers, etc.  Create a database lookup for each table.

I recommend creating a master lookup table for each class of threat intel.  So, you have to combine each database lookup table and assign a cateogry to it.  The search might look like:

	| inputlookup append=t infrastructure_botnet | eval category="botnet" | inputlookup append=t infrastructure_scanner | eval category=if(isnull(category),"scanner",category) | inputlookup append=t infrastructure_phishing | eval category=if(isnull(category),"phishing",category) | etc... | outputlookup infrastructure_threats

Create automatic lookups for your relevant security data

########## SCAP Scanning  ##########
Find it at:  http://www.open-scap.org/

Many Linux flavors can grab it from a public repo.  Some require it to be compiled.

Download XCCDF content from the repositories listed in the presentation.  Index the XML config files that you plan to use.  For the line breaking logic, see the scap-rhel6 sourcetype in the props.conf file that is included.

Extract the fields that you want to keep track of, such as severity, title, description, etc.  These can be extracted easily with a search such as:

	sourcetype=scap-rhel6 Group OR Profile | spath
	
You may want to change the names to be more human readable.  Save the results to a lookup table, using a different lookup table for each policy you want to use in your environment.  

The SCAP content typically has one or more XML files.  You typically need a CPE dictionary and the policy file.  Some policy files will contain multiple profiles, so be sure you are using the one that is right for you.

!!!!!!!!  WARNING:  If you wish to push out the policy and dictionary files with the deployment server, you MUST change the file extension to something other than XML or Splunk won't restart successfully.

The command for running the desktop profile for RHEL5 looks like:
	oscap xccdf eval --profile Desktop --results xccdf-results.xml --cpe cpe-dictionary.xml scap-xccdf.xml

The output looks something like:
	
	Title   Uninstall squid Package
	Rule    uninstall_squid
	Ident   CCE-26977-9
	Result  pass

Either create a scripted input to run oscap or use cron and save the output to a file and index it.  Create an automated lookup that will use the value in the "Rule" field to find the other interesting data in the lookup table and add it to the event.

########## Argus and Sysdig  ##########
Argus can be found at:  http://qosient.com/argus/

You will need to compile the daemon on your sensor box and the clients on whatever box you use to monitor the daemons.  Use the radium client to connect to all of your daemons, dedup flows, etc.  Use the clients to connect to radium.

Create a label file in the format that the ralabel tool can understand.  You can take your IP threat intel lookup tables and use sed to replace the comma with a tab and that should work.  You may have to use sed to remove any quotes if Splunk puts them in there.  

Argus features regex pattern matching.  So, you can use ralabel to connect to radium and dump your flows.  You can use grep to only grab flows that have values in the label field that you are looking for.  Or you can have Splunk route events without a label to the null queue.

Radark will output flows that are scanning darknet addresses, so all of those should be valuable.

Rapolicy, when given a Cisco style ACL, will output flows that violate that policy, so all of those should be valuable.

The ra client has a dnstroke field that will contain the count of keystrokes observed from the destination in an encrypted session.  The ra client has filters, so a filter with dnstroke>0 should catch any suspicious flows.

Sysdig can be found at:  http://www.sysdig.org.

It is installed with git and a quick installation script.  The sysdig command that will grab username, UID, PID, PPID, command line, etc. for network connections is:

	sysdig evt.type=connect and fd.lip!=127.0.0.1 –p”%evt.rawtime.s,%evt.type,%fd.cip,%fd.cport,%fd.sip,%fd.sport,%fd.l4proto,%proc.name,%proc.args,%proc.pid,%proc.ppid,%proc.pname,%user.uid,%user.name”
	
Create a startup script that will have sysdig run in the background, output the data to a file, and index it in Splunk.  You can then use transactions to bind your network data with sysdig, such as:

	sourcetype=argus AND sourcetype=sysdig | transaction maxspan=5m src,dest,protocol,dest_port
	
I hope this was useful.  Please send any questions to craig.merchant@oracle.com

	