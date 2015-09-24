#/usr/bin/bash
unset LD_LIBRARY_PATH

scanners=`cat /opt/splunk/etc/apps/vFeed/lookups/nessus_scanners_lookup.csv | sed -e "1d"`
for host in $scanners;
  do
    echo scanner_ip=\"$host\"
    token=`curl -k -X POST -H 'Content-Type: application/json' -d '{"username":"nessus","password":"nessus"}' https://$host:8834/session 2>&1 | grep -Po '(?<=\"token\":")[^\"]+'`
    scans=`curl -sk -H 'X-Cookie: token='$token'' https://$host:8834/scans`
    echo $scans
  done
