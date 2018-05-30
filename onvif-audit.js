/**
 * (c) Roger Hardiman <opensource@rjh.org.uk>
 * May 2018
 * Licenced with the MIT Licence
 *
 * Perform a brute force scan of the network looking for ONVIF devices
 * For each device, save the make and model and a snapshot in the audit folder
 *
 */

var IPADDRESS = '192.168.1.1-192.168.1.254', // single address or a range
    PORT = 80,
    USERNAME = 'onvifusername',
    PASSWORD = 'onvifpassword';

var Cam = require('onvif').Cam;
var flow = require('nimble');
var http = require('http');
var args = require('commander');


// Show Version
var version = require('./package.json').version;
args.version(version);
args.description('ONVIF Camera Audit');
args.option('-f, --filename <value>', 'IP Address List filename');
args.option('-i, --ipaddress <value>', 'IP Address (x.x.x.x) or IP Address Range (x.x.x.x-y.y.y.y)');
args.option('-P, --port <value>', 'ONVIF Port. Default 80', parseInt, 80);
args.option('-u, --username <value>', 'ONVIF Username');
args.option('-p, --password <value>', 'ONVIF Password');
args.option('--verbose', 'Show verbose log information');
args.option('--nolog', 'Do not write to the log file. Default is to write logs');
args.parse(process.argv);

if (!args) {
    args.help();
    process.exit(1);

}

if (!args.filename && !args.ipaddress) {
    console.log('Requires either a Filename or an IP Address/IP Range');
    process.exit(1);
}

if (args.ip) {
    // Connection Details and IP Address supplied in the Command Line
    IPADDRESS = args.ipaddress;
    if (args.port) PORT = args.port;
    if (args.username) USERNAME = args.username;
    if (args.password) PASSWORD = args.password;


    // Perform an Audit of all the cameras in the IP address Range
    perform_audit(IPADDRESS, PORT, USERNAME, PASSWORD);
}

if (args.filename) {
    // Connection details supplied in a .JSON file
    var file = require(args.filename);

    if (file.cameralist && file.cameralist.length > 0) {
        // process each item in the camera list
        file.cameralist.forEach(function (item) {
            // check IP range start and end
            if (item.ipaddress) IPADDRESS = item.ipaddress;
            if (item.port) PORT = item.port;
            if (item.username) USERNAME = item.username;
            if (item.password) PASSWORD = item.password;

            perform_audit(IPADDRESS, PORT, USERNAME, PASSWORD);
        }
        );
    }
}





function perform_audit(ip_address, port, username, password) {

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
            var got_snapshot;
            var got_live_stream_tcp;
            var got_live_stream_udp;
            var got_live_stream_multicast;
            var got_recordings;

            // Use Nimble to execute each ONVIF function in turn
            // This is used so we can wait on all ONVIF replies before
            // writing to the console
            flow.series([
                function (callback) {
                    cam_obj.getSystemDateAndTime(function (err, date, xml) {
                        if (!err) got_date = date;
                        callback();
                    });
                },
                function (callback) {
                    cam_obj.getDeviceInformation(function (err, info, xml) {
                        if (!err) got_info = info;
                        callback();
                    });
                },
                function (callback) {
                    try {
                        cam_obj.getSnapshotUri({}, function (err, result, xml) {
                            if (!err) got_snapshot = result;

                            
                            var http = require('http');
                            var fs = require('fs');
                            const url = require('url');
                            const request = require('request');

                            var filename = 'snapshot_' + ip_entry + '.jpg';
                            var uri = url.parse(got_snapshot.uri);
                            uri.username = username;
                            uri.password = password;
                            var filestream = fs.createWriteStream(filename);
                            /*
                            filestream.on('finish', function() {
                                filestream.close();
                              });
                            var request = http.get(uri, function(response) {
                                response.pipe(filestream);
                            });
                            */



                            request(got_snapshot.uri,  {'auth': {
                                'user': username,
                                'pass': password,
                                'sendImmediately': false
                              }}).pipe(filestream);

                            callback();
                        });
                    } catch (err) { callback(); }
                },
                /*
                function (callback) {
                    try {
                        cam_obj.getStreamUri({
                            protocol: 'RTSP',
                            stream: 'RTP-Unicast'
                        }, function (err, stream, xml) {
                            if (!err) got_live_stream_tcp = stream;
                            callback();
                        });
                    } catch (err) { callback(); }
                },
                function (callback) {
                    try {
                        cam_obj.getStreamUri({
                            protocol: 'UDP',
                            stream: 'RTP-Unicast'
                        }, function (err, stream, xml) {
                            if (!err) got_live_stream_udp = stream;
                            callback();
                        });
                    } catch (err) { callback(); }
                },
                function (callback) {
                    try {
                        cam_obj.getStreamUri({
                            protocol: 'UDP',
                            stream: 'RTP-Multicast'
                        }, function (err, stream, xml) {
                            if (!err) got_live_stream_multicast = stream;
                            callback();
                        });
                    } catch (err) { callback(); }
                },
                */
                function (callback) {
                    console.log('------------------------------');
                    console.log('Host: ' + ip_entry + ' Port: ' + port);
                    console.log('Date: = ' + got_date);
                    console.log('Info: = ' + JSON.stringify(got_info));
                    if (got_snapshot) {
                        console.log('Snapshot URI: =                ' + got_snapshot.uri);

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
                    callback();
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

