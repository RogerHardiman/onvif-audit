/**
 * (C) Roger Hardiman <opensource@rjh.org.uk>
 * First Release - May 2018
 * Licenced with the MIT Licence
 *
 * Perform a brute force scan of the network looking for ONVIF devices
 * For each device, save the make and model and a snapshot in the audit folder
 *
 * Can also use ONVIF Discovery to trigger the scan
 */

var IPADDRESS = '192.168.1.1-192.168.1.254', // single address or a range
    PORT = 80,
    USERNAME = 'onvifusername',
    PASSWORD = 'onvifpassword';

var onvif = require('onvif');
var Cam = onvif.Cam;
var flow = require('nimble');
var http = require('http');
var args = require('commander');
var fs = require('fs');
var dateTime = require('node-datetime');
var path = require('path');
var parseString = require('xml2js').parseString;
var stripPrefix = require('xml2js').processors.stripPrefix;



// Show Version
var version = require('./package.json').version;
args.version(version);
args.description('ONVIF Camera Audit');
args.option('-f, --filename <value>', 'Filename of JSON file with IP Address List');
args.option('-i, --ipaddress <value>', 'IP Address (x.x.x.x) or IP Address Range (x.x.x.x-y.y.y.y)');
args.option('-P, --port <value>', 'ONVIF Port. Default 80', parseInt, 80);
args.option('-u, --username <value>', 'ONVIF Username');
args.option('-p, --password <value>', 'ONVIF Password');
args.option('-s, --scan', 'Discover Network devices on local subnet');
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

var time_now = dateTime.create();
var folder = 'onvif_audit_report_' + time_now.format('Y_m_d_H_M_S');

try {
    fs.mkdirSync(folder);
} catch (e) {
}


if (args.ipaddress) {
    // Connection Details and IP Address supplied in the Command Line
    IPADDRESS = args.ipaddress;
    if (args.port) PORT = args.port;
    if (args.username) USERNAME = args.username;
    if (args.password) PASSWORD = args.password;


    // Perform an Audit of all the cameras in the IP address Range
    perform_audit(IPADDRESS, PORT, USERNAME, PASSWORD, folder);
}

if (args.filename) {
    // Connection details supplied in a .JSON file
    var contents = fs.readFileSync(args.filename);
    var file = JSON.parse(contents);

    if (file.cameralist && file.cameralist.length > 0) {
        // process each item in the camera list
        //Note - forEach is asynchronous - you don't know when it has completed
        file.cameralist.forEach(function (item) {
            // check IP range start and end
            if (item.ipaddress) IPADDRESS = item.ipaddress;
            if (item.port) PORT = item.port;
            if (item.username) USERNAME = item.username;
            if (item.password) PASSWORD = item.password;

            perform_audit(IPADDRESS, PORT, USERNAME, PASSWORD, folder);
        }
        );
    }
}

if (args.scan) {
    // set up an event handler which is called for each device discovered
    onvif.Discovery.on('device', function(cam,rinfo,xml){
        // function will be called as soon as NVT responses

        parseString(xml, 
            {
                tagNameProcessors: [ stripPrefix ]   // strip namespace eg tt:Data -> Data
            },
            function (err, result) {
                if (err) return;
                var xaddrs = result['Envelope']['Body'][0]['ProbeMatches'][0]['ProbeMatch'][0]['XAddrs'][0];
                var scopes = result['Envelope']['Body'][0]['ProbeMatches'][0]['ProbeMatch'][0]['Scopes'][0];
                scopes = scopes.split(" ");

                var hardare = "";
                var name = "";
                for (var i = 0; i < scopes.length; i++) {
                    // use decodeUri to conver %20 to ' '
                    if (scopes[i].includes('onvif://www.onvif.org/name')) name = decodeURI(scopes[i].substring(27));
                    if (scopes[i].includes('onvif://www.onvif.org/hardware')) hardware = decodeURI(scopes[i].substring(31));
                }
                // split scopes on Space
                var msg = 'Discovery Reply from ' + rinfo.address + ' (' + name + ') (' + hardware + ')';
                //console.log('%j',result);
                console.log(msg);
            }
        );

    })

    // start the probe
    // resolve=false  means Do not create Cam objects
    onvif.Discovery.probe({resolve: false});
}


// program ends here (just functions below)


function perform_audit(ip_address, port, username, password, folder) {

    var ip_start;
    var ip_end;

    if (ip_address.includes('-')) {
        // split on the '-'
        var split_str = ip_address.split('-');
        if (split_str.length != 2) {
            console.log('IP address format incorrect. Should by x.x.x.x-y.y.y.y');
            process.exit(1);
        }
        ip_start = split_str[0];
        ip_end = split_str[1];
    }
    else {
        // does not include a '-' symbol
        ip_start = ip_address;
        ip_end = ip_address;
    }


    console.log('Scanning IP addresses from ' + ip_start + ' to ' + ip_end);

    var ip_list = generate_range(ip_start, ip_end);

    // hide error messages
    console.error = function () { };

    // try each IP address and each Port
    ip_list.forEach(function (ip_entry) {

        console.log(ip_entry + ':' + port);

        new Cam({
            hostname: ip_entry,
            username: username,
            password: password,
            port: port,
            timeout: 5000
        }, function CamFunc(err) {
            if (err) {
                console.log("Cannot connect to " + err);
                return;
            }

            var cam_obj = this;

            var got_date;
            var got_info;
            var got_snapshots = [];
            var got_live_stream_tcp;
            var got_live_stream_udp;
            var got_live_stream_multicast;
            var got_recordings;

            // Use Nimble to execute each ONVIF function in turn
            // This is used so we can wait on all ONVIF replies before
            // writing to the console
            flow.series([
                function (nimble_callback) {
                    cam_obj.getSystemDateAndTime(function (err, date, xml) {
                        if (!err) got_date = date;
                        nimble_callback();
                    });
                },
                function (nimble_callback) {
                    cam_obj.getDeviceInformation(function (err, info, xml) {
                        if (!err) got_info = info;
                        nimble_callback();
                    });
                },
                function (nimble_callback) {
                    try {
                        // The ONVIF device may have multiple Video Sources
                        // eg 4 channel IP encoder or Panoramic Cameras
                        // Grab a JPEG from each VideoSource
                        // Note. The Nimble Callback is only called once we have ONVIF replies
                        // have been returned
                        var reply_max = cam_obj.activeSources.length;
                        var reply_count = 0;
                        for (var src_idx = 0; src_idx < cam_obj.activeSources.length; src_idx++) {
                            var videoSource = cam_obj.activeSources[src_idx];
                            cam_obj.getSnapshotUri({profileToken: videoSource.profileToken},function (err, getUri_result, xml) {
                                reply_count++;
                                if (!err) got_snapshots.push(getUri_result);

                                var http = require('http');
                                var fs = require('fs');
                                const url = require('url');
                                const request = require('request');

                                if (cam_obj.activeSources.length === 1) {
                                    var filename = folder + path.sep + 'snapshot_' + ip_entry + '.jpg';
                                } else {
                                    // add _1, _2, _3 etc for cameras with multiple VideoSources
                                    var filename = folder + path.sep + 'snapshot_' + ip_entry + '_' + (src_idx+1) + '.jpg';
                                }
                                var uri = url.parse(getUri_result.uri);

                                // handle the case where the camera is behind NAT
                                // ONVIF Standard now says use XAddr for camera
                                // and ignore the IP address in the Snapshot URI
                                uri.host = ip_entry;
                                uri.username = username;
                                uri.password = password;
                                if (!uri.port) uri.port = 80;
                                var modified_uri = uri.href;

                                var filestream = fs.createWriteStream(filename);


                                /* ERROR 1 - Node HTTP client does not support Digest Auth
                                filestream.on('finish', function() {
                                    filestream.close();
                                });
                                var request = http.get(uri, function(response) {
                                    response.pipe(filestream);
                                });
                                */

                                var digestRequest = require('request-digest')(username, password);
                                digestRequest.request({
                                    host: 'http://' + uri.host,
                                    path: uri.path,
                                    port: uri.port,
                                    encoding: null, // return data as a Buffer()
                                    method: 'GET'
                                    //                             headers: {
                                    //                               'Custom-Header': 'OneValue',
                                    //                               'Other-Custom-Header': 'OtherValue'
                                    //                             }
                                }, function (error, response, body) {
                                    if (error) {
                                        console.log('Error downloading snapshot');
                                    //    throw error;
                                    } else {

                                        var snapshot_fd;

                                        fs.open(filename, 'w', function (err, fd) {
                                            // callback for file opened, or file open error
                                            if (err) {
                                                console.log('ERROR - cannot create output file ' + log_filename);
                                                console.log(err);
                                                console.log('');
                                                process.exit(1);
                                            }
                                            snapshot_fd = fd;
                                            fs.appendFile(filename, body, function (err) {
                                                if (err) {
                                                    console.log('Error writing to file');
                                                }
                                            });


                                            //fs.write(snapshot_fd, body, function (err) {
                                            //    if (err)
                                            //        console.log('Error writing to file');
                                            //});
                                            ////fs.closeSync(snapshot_fd);
                                        });
                                    }
                                });

                                /* ERROR 2 - This library did not work with ONVIF cameras
                                request(modified_uri,  {'auth': {
                                    'user': username,
                                    'pass': password,
                                    'sendImmediately': false
                                }}).pipe(filestream);
                                */

                                if (reply_count === reply_max) nimble_callback(); // let 'flow' move on. JPEG GET is still async
                            });
                        }; // end for
                    } catch (err) { nimble_callback(); }
                },
                function (nimble_callback) {
                    try {
                        cam_obj.getStreamUri({
                            protocol: 'RTSP',
                            stream: 'RTP-Unicast'
                        }, function (err, stream, xml) {
                            if (!err) got_live_stream_tcp = stream;
                            nimble_callback();
                        });
                    } catch (err) { nimble_callback(); }
                },
                function (nimble_callback) {
                    try {
                        cam_obj.getStreamUri({
                            protocol: 'UDP',
                            stream: 'RTP-Unicast'
                        }, function (err, stream, xml) {
                            if (!err) got_live_stream_udp = stream;
                            nimble_callback();
                        });
                    } catch (err) { nimble_callback(); }
                },
                /* Multicast is optional in Profile S, Mandatory in Profile T
                but could be disabled
                function (nimble_callback) {
                    try {
                        cam_obj.getStreamUri({
                            protocol: 'UDP',
                            stream: 'RTP-Multicast'
                        }, function (err, stream, xml) {
                            if (!err) got_live_stream_multicast = stream;
                            nimble_callback();
                        });
                    } catch (err) { nimble_callback(); }
                },
                */
                function (nimble_callback) {
                    console.log('------------------------------');
                    console.log('Host: ' + ip_entry + ' Port: ' + port);
                    console.log('Date: = ' + got_date);
                    console.log('Info: = ' + JSON.stringify(got_info));
                    if (got_snapshots.length>0) {
                        for (var i = 0; i < got_snapshots.length; i++) {
                            console.log('Snapshot URI: =                ' + got_snapshots[i].uri);
                        }
                    }
                    if (got_live_stream_tcp) {
                        console.log('First Live TCP Stream: =       ' + got_live_stream_tcp.uri);
                    }
                    if (got_live_stream_udp) {
                        console.log('First Live UDP Stream: =       ' + got_live_stream_udp.uri);
                    }
                    if (got_live_stream_multicast) {
                        console.log('First Live Multicast Stream: = ' + got_live_stream_multicast.uri);
                    }
                    console.log('------------------------------');

                    var log_filename = folder + path.sep + 'camera_report_' + ip_entry + '.txt';
                    var log_fd;

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
                        if (got_date) {
                            msg += 'Date:= ' + got_date + '\r\n';
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
                        if (got_live_stream_tcp) {
                            msg += 'First Live TCP Stream: =       ' + got_live_stream_tcp.uri + '\r\n';
                        }
                        if (got_live_stream_udp) {
                            msg += 'First Live UDP Stream: =       ' + got_live_stream_udp.uri + '\r\n';
                        }
                        fs.write(log_fd, msg, function (err) {
                            if (err)
                                console.log('Error writing to file');
                        });

                    });




                    nimble_callback();
                },

            ]); // end flow

        });
    }); // foreach
}

function generate_range(start_ip, end_ip) {
    var start_long = toLong(start_ip);
    var end_long = toLong(end_ip);
    if (start_long > end_long) {
        var tmp = start_long;
        start_long = end_long
        end_long = tmp;
    }
    var range_array = [];
    var i;
    for (i = start_long; i <= end_long; i++) {
        range_array.push(fromLong(i));
    }
    return range_array;
}

//toLong taken from NPM package 'ip' 
function toLong(ip) {
    var ipl = 0;
    ip.split('.').forEach(function (octet) {
        ipl <<= 8;
        ipl += parseInt(octet);
    });
    return (ipl >>> 0);
};

//fromLong taken from NPM package 'ip' 
function fromLong(ipl) {
    return ((ipl >>> 24) + '.' +
        (ipl >> 16 & 255) + '.' +
        (ipl >> 8 & 255) + '.' +
        (ipl & 255));
};

