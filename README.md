# onvif-audit

onvif-audit will scan a network looking for ONVIF cameras and create an audit log folder containing

* Text File which reports the Camera Make and Model and Serial Number and the Camera Time (to check Time Sync Errors)
* JPEG Snapshot of the camera view

# Installation
You can use the pre-compiled packages for Windows, Linux and Mac.
Or checkout the source code and then run `npm install` to fetch the modules and dependencies onvif-audit uses.

# Command Line and Config File Usage
The Audit can be controlled from the Command Line or via a Configuration File

## Command Line
Command Line parameters are used to provide a single IP address or a range of IP addresses to scan, along with Username and Password.
Example to scan a network for all cameras in the range 192.168.1.1 to 192.168.1.254

`
node onvif-audit.js --ipaddress 192.168.1.1-192.168.1.254 --username user --password 1234
`

A full list of commands can be obtained with the -h option
`
node onvif-audit.js -h
`

## Config File
A JSON formatted Configuration File is used to give the Audit tool a list of cameras to scan.
An example is shown below which first scans the range of IPs from 1.2.3.20 to 1.2.3.30 and then scans a single address of 11.22.33.44

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
			"port": "80",
			"username": "admin",
			"password": "password",
			"comment": "HikVision"
		}

}
```

# ONVIF Discovery vrs IP address range scan
ONVIF Audit supports Discovery of devices on the local network with the --scan option.
This is great for scanning the local subnet but does not work over routed networks with different IP address ranges.
This is why this tool also uses IP address ranges to scan the network.

# Building the Binary Executable Version
The npm package called 'pkg' is used to compile the Javascript into a standalone executable for Windows, Mac and Linux. Run ```./node_modules/pkg/lib-es5/bin.js onvif-audit.js```

# Future Plans
a) Use the ONVIF Absolute PTZ Position Command to take a snapshot looking in different directions
b) Record a short video clip using ffmpeg or the node RTSP client called yellowstone

