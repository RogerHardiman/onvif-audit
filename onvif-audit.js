/**
 * (C) Roger Hardiman <opensource@rjh.org.uk>
 * First Release - May 2018
 * Licenced with the MIT Licence
 *
 * Perform a brute force scan of the network looking for ONVIF devices
 * For each device, save the make and model and a snapshot in the audit output folder
 *
 * Can also use ONVIF Discovery to trigger the scan
 *
 * Uses onvif@1 (Onvif / Discovery Promise API)
 */

var IPADDRESS = '192.168.1.1-192.168.1.254', // single address or a range
    PORT = '80',
    USERNAME = 'onvifusername',
    PASSWORD = 'onvifpassword';

var { Onvif, Discovery } = require('onvif');
var args = require('commander');
var fs = require('fs');
var dateTime = require('node-datetime');
var path = require('path');

let start_time = dateTime.create();
let start_time_YYYYMMDDHHMMSS = start_time.format('Y_m_d_H_M_S');

// Show Version
var version = require('./package.json').version;
args.version(version);
args.description('ONVIF Camera Audit');
args.option('-f, --filename <value>', 'Filename of JSON file with IP Address List');
args.option('-i, --ipaddress <value>', 'IP Address (x.x.x.x) or IP Address Range (x.x.x.x-y.y.y.y)');
args.option('-P, --port <value>', 'ONVIF Port. Default 80');
args.option('-u, --username <value>', 'ONVIF Username');
args.option('-p, --password <value>', 'ONVIF Password');
args.option('-s, --scan', 'Discover Network devices on local subnet');
args.option('-x, --xml', 'Log ONVIF SOAP XML messages');
args.option('-o, --outputfolder <value>', 'Output Folder. Default is onvif_audit_report_YYYY_MM_DD_HH_MM_SS');
args.parse(process.argv);

if (!args) {
    args.help();
    process.exit(1);

}

if (!args.filename && !args.ipaddress && !args.scan) {
    console.log('Requires either a Filename (-f) or an IP Address/IP Range (-i) or a Scan (-s)');
    console.log('Use -h for details');
    process.exit(1);
}

let outputfolder = 'onvif_audit_report_' + start_time_YYYYMMDDHHMMSS;
if (args.outputfolder) {
    outputfolder = args.outputfolder;
}

try {
    if (fs.existsSync(outputfolder) === false) {
        fs.mkdirSync(outputfolder);
    }
} catch (e) {
    console.log('Unable to create output folder')
    process.exit(1)
}


if (args.ipaddress) {
    // Connection Details and IP Address supplied in the Command Line
    IPADDRESS = args.ipaddress;
    if (args.port) PORT = args.port;
    if (args.username) USERNAME = args.username;
    if (args.password) PASSWORD = args.password;


    // Perform an Audit of all the cameras in the IP address Range
    perform_audit(IPADDRESS, PORT, USERNAME, PASSWORD, outputfolder);
}

if (args.filename) {
    // Connection details supplied in a .JSON file
    let contents = fs.readFileSync(args.filename);
    let file = JSON.parse(contents);

    if (file.cameralist && file.cameralist.length > 0) {
        // process each item in the camera list
        //Note - forEach is asynchronous - you don't know when it has completed
        file.cameralist.forEach(function (item) {
            // check IP range start and end
            if (item.ipaddress) IPADDRESS = item.ipaddress;
            if (item.port) PORT = item.port;
            if (item.username) USERNAME = item.username;
            if (item.password) PASSWORD = item.password;

            perform_audit(IPADDRESS, PORT, USERNAME, PASSWORD, outputfolder);
        }
        );
    }
}

if (args.scan) {
    console.log("Probing for 5 seconds");

    let scanResults = [];

    // set up an event handler which is called for each device discovered
    // With resolve:false, Discovery yields the parsed ProbeMatch body (not Onvif instances)
    Discovery.on('device', function (cam, rinfo) {
        const probeMatch = cam && cam.probeMatches && cam.probeMatches.probeMatch;
        if (!probeMatch) return;

        let urn = String(probeMatch.endpointReference && probeMatch.endpointReference.address || '').trim();
        let xaddrs = String(probeMatch.XAddrs || '').trim(); // Axis add whitespace on end. Remove it.
        let scopesRaw = probeMatch.scopes != null ? probeMatch.scopes : probeMatch.Scopes;
        let scopes = typeof scopesRaw === 'string'
            ? scopesRaw.trim().split(/\s+/).filter(Boolean)
            : Array.isArray(scopesRaw) ? scopesRaw : [];

        let hardware = "";
        let name = "";
        for (let i = 0; i < scopes.length; i++) {
            // use decodeUri to conver %20 to ' '
            if (scopes[i].includes('onvif://www.onvif.org/name')) name = decodeURI(scopes[i].substring(27));
            if (scopes[i].includes('onvif://www.onvif.org/hardware')) hardware = decodeURI(scopes[i].substring(31));
        }

        process.stdout.write(".");

        const newItem = {
            rinfo,
            name,
            hardware,
            xaddrs,
            urn,
            scopes
        };
        scanResults.push(newItem);
    })
    Discovery.on('error', function () {
        // ignore discovery errors
    })

    // start the probe
    // resolve=false  means Do not create Onvif objects
    Discovery.probe({ resolve: false }).then(function () {
        // completion callback
        process.stdout.write("\n");

        // sort the Scan Results by IP Address
        scanResults.sort((a, b) => {
            // Check we are matching IPv4 against IPv6. If so sort IPv4 first
            if (a.rinfo.family < b.rinfo.family)
                return -1;
            else if (a.rinfo.family > b.rinfo.family)
                return 1;
            else {
                // A and B are both the same "family" (IPv4 or IPv6)

                if (a.rinfo.family === 'IPv4') {
                    // IPv4 - sort numerically
                    return toLong(a.rinfo.address) - toLong(b.rinfo.address);
                }
                else if (a.rinfo.family === 'IPv6') {
                    // IPv6 - sort by String. Could be improved
                    if (a.rinfo.address < b.rinfo.address) return -1;
                    else if (a.rinfo.address > b.rinfo.address) return 1;
                    else return 0;
                }
                else {
                    // Unknown IP family
                    return 0;
                }
            }
        });

        for (const item of scanResults) {
            let msg = item.rinfo.address + ' (' + item.name + ') (' + item.hardware + ') (' + item.xaddrs + ') (' + item.urn + ')';
            console.log(msg);
        }
        console.log("Total " + scanResults.length);
    });

}


// program ends here (just functions below)

/** MediaUri.uri from onvif@1 media.getStreamUri / getSnapshotUri (Media2 bridge same shape). */
function media_uri(result) {
    return result?.uri || null;
}

/** Prefer the JS Date attached by onvif@1 getSystemDateAndTime(). */
function format_device_date(got_date) {
    if (!got_date) return got_date;
    if (got_date.dateTime instanceof Date) return got_date.dateTime;
    return got_date;
}

function as_array(value) {
    if (!value) return [];
    return Array.isArray(value) ? value : [value];
}

function perform_audit(ip_addresses, port, username, password, outputfolder) {

    let ip_list = [];

    // Valid IP addresses are
    // a) Single address 1.2.3.4
    // b) Range 10.10.10.50-10.10.10.99
    // c) List 1.1.1.1,2.2.2.2,3.3.3.3
    // d) Mixture 1.2.3.4,10.10.10.50-10.10.10.99

    ip_addresses = ip_addresses.split(',');
    for (let i = 0; i < ip_addresses.length; i++) {
        let item = ip_addresses[i];
        if (item.includes('-')) {
            // item contains '-'. Split on the '-'
            let split_str = item.split('-');
            if (split_str.length !== 2) {
                console.log('IP address format incorrect. Should by x.x.x.x-y.y.y.y');
                process.exit(1);
            }
            let ip_start = split_str[0];
            let ip_end = split_str[1];

            let tmp_list = generate_range(ip_start, ip_end);

            // Copy
            for (let x = 0; x < tmp_list.length; x++) ip_list.push(tmp_list[x]);
        }
        else {
            // item does not include a '-' symbol
            ip_list.push(item);
        }
    }


    // console.log('Scanning ' + ip_list.length + ' addresses from ' + ip_list[0] + ' to ' + ip_list[ip_list.length-1]);


    // hide error messages
    console.error = function () { };

    // try each IP address and each Port
    ip_list.forEach(function (ip_entry) {
        audit_camera(ip_entry, port, username, password, outputfolder).catch(function (err) {
            console.log('------------------------------');
            console.log("Cannot connect to " + ip_entry + ":" + port);
            if (err && err.message) console.log(err.message);
            else console.log(err);
            console.log('------------------------------');
        });
    }); // foreach
}

async function audit_camera(ip_entry, port, username, password, outputfolder) {

    console.log("Connecting to " + ip_entry + ':' + port);

    const onvif = new Onvif({
        hostname: ip_entry,
        username: username,
        password: password,
        port: port,
        timeout: 10000
    });

    let xmlLog = [];
    // Log ONVIF XML Messages from the Onvif Library
    if (args.xml) {
        onvif.on("rawRequest", (data) => {
            const msg = `\nTX DATA [${ip_entry}:${port}]: ${data}`;
            xmlLog.push(msg + '\r\n');
            console.log(msg);
        });
        onvif.on("rawResponse", (data) => {

            const msg = `\nRX DATA [${ip_entry}:${port}]: ${data}`;
            xmlLog.push(msg + '\r\n');
            console.log(msg);
        });
    }

    try {
        await onvif.connect();
    } catch (err) {
        console.log('------------------------------');
        console.log("Cannot connect to " + ip_entry + ":" + port);
        // cut the error at \n
        if (err.message) console.log(err.message);
        else console.log(err);
        console.log('------------------------------');
        try { await onvif.close(); } catch (e) { /* ignore */ }
        return;
    }

    let got_date;
    let got_info;
    let got_videosources = [];
    let got_profiles = [];
    let bestProfile = []; // The preferred Profile indexed by Video Source.
    let got_snapshots = []; // JPEG Imag URLs, indexed by Video Source
    let got_livestreams = []; // RTSP URLs, indexed by Video Source

    try {
        try {
            got_date = await onvif.getSystemDateAndTime();
        } catch (err) { /* ignore */ }

        try {
            got_info = await onvif.device.getDeviceInformation();
        } catch (err) { /* ignore */ }

        try {
            got_videosources = as_array(await onvif.media.getVideoSources());
            for (let i = 0; i < got_videosources.length; i++) {
                // create empty placeholders
                bestProfile.push({});
                got_snapshots.push({ videoSourceToken: null, uri: null });
                got_livestreams.push({ tcp: null, udp: null, http: null, multicast: null });
            }
        } catch (err) { /* ignore */ }

        try {
            got_profiles = as_array(await onvif.media.getProfiles());
        } catch (err) { /* ignore */ }

        // Compare VideoSources with Profiles.
        // Get the 'best' ONVIF Profile Token for each Video Source
        for (let src_idx = 0; src_idx < got_videosources.length; src_idx++) {
            const videoSource = got_videosources[src_idx];
            const sourceToken = videoSource.token;

            // Get the 'best' profile for this videoSource token
            // For most cameras we just find the first Profile which has the Video Source Token
            // but Hanwha emit the JPEG Profile first, then H264, then H265. So we have to find the 'best' Profile ourselves.
            // The Best one is the first H265, otherwise the first H264, otherwise the first MPEG4 otherwise the first JPEG stream
            let firstH265 = got_profiles.findIndex(item =>
                item.videoSourceConfiguration && item.videoEncoderConfiguration
                && item.videoSourceConfiguration.sourceToken === sourceToken
                && item.videoEncoderConfiguration.encoding === "H265");
            let firstH264 = got_profiles.findIndex(item =>
                item.videoSourceConfiguration && item.videoEncoderConfiguration
                && item.videoSourceConfiguration.sourceToken === sourceToken
                && item.videoEncoderConfiguration.encoding === "H264");
            let firstMPEG4 = got_profiles.findIndex(item =>
                item.videoSourceConfiguration && item.videoEncoderConfiguration
                && item.videoSourceConfiguration.sourceToken === sourceToken
                && item.videoEncoderConfiguration.encoding === "MPEG4");
            let firstJPEG = got_profiles.findIndex(item =>
                item.videoSourceConfiguration && item.videoEncoderConfiguration
                && item.videoSourceConfiguration.sourceToken === sourceToken
                && item.videoEncoderConfiguration.encoding === "JPEG");
            let firstOther = got_profiles.findIndex(item =>
                item.videoSourceConfiguration && item.videoEncoderConfiguration
                && item.videoSourceConfiguration.sourceToken === sourceToken
            );

            if (firstH265 >= 0) bestProfile[src_idx] = got_profiles[firstH265];
            else if (firstH264 >= 0) bestProfile[src_idx] = got_profiles[firstH264];
            else if (firstMPEG4 >= 0) bestProfile[src_idx] = got_profiles[firstMPEG4];
            else if (firstJPEG >= 0) bestProfile[src_idx] = got_profiles[firstJPEG];
            else bestProfile[src_idx] = got_profiles[firstOther];
        }

        // The ONVIF device may have multiple Video Sources
        // eg 4 channel IP encoder or Panoramic Cameras
        // Grab a JPEG Image from each VideoSource
        for (let src_idx = 0; src_idx < got_videosources.length; src_idx++) {
            const videoSource = got_videosources[src_idx];
            const profile = bestProfile[src_idx];
            if (!profile || !profile.token) continue;

            try {
                const getUri_result = await onvif.media.getSnapshotUri({ profileToken: profile.token });
                const snapshotUri = media_uri(getUri_result);
                if (!snapshotUri) continue;

                got_snapshots[src_idx] = { videoSourceToken: videoSource.token, uri: snapshotUri };

                let filename = outputfolder + path.sep + start_time_YYYYMMDDHHMMSS + '_snapshot_' + ip_entry;
                if (got_videosources.length > 1) {
                    // add _1, _2, _3 etc for cameras with multiple VideoSources
                    filename += '_' + (src_idx + 1);
                }
                filename += '.jpg';

                let uri;
                try {
                    uri = new URL(snapshotUri);
                } catch (e) {
                    continue;
                }

                // handle the case where the camera is behind NAT
                // ONVIF Standard now says use XAddr for camera
                // and ignore the IP address in the Snapshot URI
                uri.hostname = ip_entry;
                if (!uri.port) uri.port = '80';

                // Download snapshot without blocking the rest of the audit report
                const digestRequest = require('request-digest')(username, password);
                digestRequest.request({
                    host: uri.protocol + '//' + uri.hostname,
                    path: uri.pathname + uri.search,
                    port: uri.port,
                    encoding: null, // return data as a Buffer()
                    method: 'GET'
                }, function (error, response, body) {
                    if (error) {
                        // console.log('Error downloading snapshot');
                        // throw error;
                    } else {

                        fs.open(filename, 'w', function (err) {
                            // callback for file opened, or file open error
                            if (err) {
                                console.log('ERROR - cannot create output log file');
                                console.log(err);
                                console.log('');
                                process.exit(1);
                            }
                            fs.appendFile(filename, body, function (err) {
                                if (err) {
                                    console.log('Error writing to file');
                                }
                            });

                        });
                    }
                });
            } catch (err) { /* ignore per-source snapshot failures */ }
        }

        for (let src_idx = 0; src_idx < got_videosources.length; src_idx++) {
            const profile = bestProfile[src_idx];
            if (!profile || !profile.token) continue;
            const profileToken = profile.token;

            try {
                const stream = await onvif.media.getStreamUri({
                    protocol: 'RTSP',
                    stream: 'RTP-Unicast',
                    profileToken: profileToken
                });
                got_livestreams[src_idx].tcp = media_uri(stream);
            } catch (err) { /* ignore */ }

            try {
                const stream = await onvif.media.getStreamUri({
                    protocol: 'UDP',
                    stream: 'RTP-Unicast',
                    profileToken: profileToken
                });
                got_livestreams[src_idx].udp = media_uri(stream);
            } catch (err) { /* ignore */ }

            try {
                const stream = await onvif.media.getStreamUri({
                    protocol: 'HTTP',
                    stream: 'RTP-Unicast',
                    profileToken: profileToken
                });
                got_livestreams[src_idx].http = media_uri(stream);
            } catch (err) { /* ignore */ }

            /* Multicast is optional in Profile S, Mandatory in Profile T but could be disabled */
            try {
                const stream = await onvif.media.getStreamUri({
                    protocol: 'UDP',
                    stream: 'RTP-Multicast',
                    profileToken: profileToken
                });
                got_livestreams[src_idx].multicast = media_uri(stream);
            } catch (err) { /* ignore */ }
        }

        const display_date = format_device_date(got_date);

        console.log('------------------------------');
        console.log('Host: ' + ip_entry + ' Port: ' + port);
        console.log('Date: = ' + display_date);
        console.log('Info: = ' + JSON.stringify(got_info));
        for (let i = 0; i < got_videosources.length; i++) {
            const enc = bestProfile[i] && bestProfile[i].videoEncoderConfiguration;
            let msg = "Video Source " + (i + 1) + ' [' + got_videosources[i].token + ']';
            if (enc && enc.encoding && enc.resolution) {
                msg += ' [' + enc.encoding + ' '
                    + enc.resolution.width + 'x' + enc.resolution.height + ']';
            }

            console.log(msg);

            if (got_snapshots[i].uri != null) {
                console.log('Snapshot URI: =          ' + got_snapshots[i].uri);
            }
            if (got_livestreams[i].tcp != null) {
                console.log('Live TCP Stream: =       ' + got_livestreams[i].tcp);
            }
            if (got_livestreams[i].udp != null) {
                console.log('Live UDP Stream: =       ' + got_livestreams[i].udp);
            }
            if (got_livestreams[i].http != null) {
                console.log('Live HTTP Stream: =      ' + got_livestreams[i].http);
            }
            if (got_livestreams[i].multicast != null) {
                console.log('Live Multicast Stream: = ' + got_livestreams[i].multicast);
            }
            console.log('------------------------------');
        }

        let log_filename = outputfolder + path.sep + start_time_YYYYMMDDHHMMSS + '_camera_report_' + ip_entry + '.txt';
        let log_fd;

        fs.open(log_filename, 'w', function (err, fd) {
            if (err) {
                console.log('ERROR - cannot create output file ' + log_filename);
                console.log(err);
                console.log('');
                process.exit(1);
            }
            log_fd = fd;
            //console.log('Log File Open (' + log_filename + ')');

            // write to log file in the Open callback
            let msg = 'Host:= ' + ip_entry + ' Port:= ' + port + '\r\n';
            if (display_date) {
                msg += 'Date:= ' + display_date + '\r\n';
            } else {
                msg += 'Date:= unknown\r\n';
            }
            if (got_info) {
                msg += 'Manufacturer:= ' + got_info.manufacturer + '\r\n';
                msg += 'Model:= ' + got_info.model + '\r\n';
                msg += 'Firmware Version:= ' + got_info.firmwareVersion + '\r\n';
                msg += 'Serial Number:= ' + got_info.serialNumber + '\r\n';
                msg += 'Hardware ID:= ' + got_info.hardwareId + '\r\n';
            } else {
                msg += 'Manufacturer:= unknown\r\n';
                msg += 'Model:= unknown\r\n';
                msg += 'Firmware Version:= unknown\r\n';
                msg += 'Serial Number:= unknown\r\n';
                msg += 'Hardware ID:= unknown\r\n';
            }
            for (let i = 0; i < got_videosources.length; i++) {
                const enc = bestProfile[i] && bestProfile[i].videoEncoderConfiguration;
                msg += "Video Source " + (i + 1) + ' [' + got_videosources[i].token + ']';
                if (enc && enc.encoding && enc.resolution) {
                    msg += ' [' + enc.encoding + ' '
                        + enc.resolution.width + 'x' + enc.resolution.height + ']';
                }
                msg += '\r\n';

                if (got_snapshots[i].uri != null) {
                    msg += 'Snapshot URL: =          ' + got_snapshots[i].uri + '\r\n';
                }

                if (got_livestreams[i].tcp != null) {
                    msg += 'Live TCP Stream: =       ' + got_livestreams[i].tcp + '\r\n';
                }
                if (got_livestreams[i].udp != null) {
                    msg += 'Live UDP Stream: =       ' + got_livestreams[i].udp + '\r\n';
                }
                if (got_livestreams[i].http != null) {
                    msg += 'Live HTTP Stream: =      ' + got_livestreams[i].http + '\r\n';
                }
                if (got_livestreams[i].multicast != null) {
                    msg += 'Live Multicast Stream: = ' + got_livestreams[i].multicast + '\r\n';
                }
            }
            fs.write(log_fd, msg, function (err) {
                if (err)
                    console.log('Error writing to file');
            });

            msg = "";
            for (const item of xmlLog) {
                msg += item;
            }

            fs.write(log_fd, msg, function (err) {
                if (err)
                    console.log('Error writing to file');
            });
        });

    } finally {
        // Release keep-alive / agents so Node can exit (required in onvif@1)
        try { await onvif.close(); } catch (e) { /* ignore */ }
    }
}

function generate_range(start_ip, end_ip) {
    let start_long = toLong(start_ip);
    let end_long = toLong(end_ip);
    if (start_long > end_long) {
        let tmp = start_long;
        start_long = end_long
        end_long = tmp;
    }
    let range_array = [];
    for (let i = start_long; i <= end_long; i++) {
        range_array.push(fromLong(i));
    }
    return range_array;
}

//toLong taken from NPM package 'ip'
function toLong(ip) {
    let ipl = 0;
    ip.split('.').forEach(function (octet) {
        ipl <<= 8;
        ipl += parseInt(octet);
    });
    return (ipl >>> 0);
}

//fromLong taken from NPM package 'ip'
function fromLong(ipl) {
    return ((ipl >>> 24) + '.' +
        (ipl >> 16 & 255) + '.' +
        (ipl >> 8 & 255) + '.' +
        (ipl & 255));
}
