# onvif-audit

onvif-audit will scan a network looking for ONVIF cameras and create an audit log containing

* Camera Make and Model
* Camera Time (to check for Time Sync errors)
* JPEG Snapshot of the camera view

It can be controlled from the Command Line or via a Configuration File

# Command Line
Example to scan a network for all cameras in the range 192.168.1.1 to 192.168.1.254

`
node onvif-audit.js --ipaddress 192.168.1.1-192.168.1.254 --username user --password 1234
`


# Config File
This is a JSON formatted file
An example is shown below which scans the Range of IPs from 1.2.3.20 to 1.2.3.30 and also scans a single address at 11.22.33.44

`
node onvif-audit.js --filename ./camera_list.json
`

cameralist.json contains this....
```
{
	"cameralist": [
		{
			"ipaddress": "1.2.3.20-1.2.3.30",
			"port": "80",
			"username": "service",
			"password": "password",
			"comment": "Bosch"
		},
		{
			"ipaddress": "11.22.33.44",
			"port": "81",
			"username": "admin",
			"password": "password",
			"comment": "HikVision"
		}

}
```

# ONVIF Discovery vrs IP address range scan
ONVIF supports Discovery via WS-Discover protocol. This is great in the local subnet but does not work over routed networks with different IP address ranges.
This is why this tool uses IP address ranges to scan the network
