//normalizing functions for parts of a URI
//
// normalizeHost(host)
// normalizeDNSHost(host[, requireMultipleLabels])	//only accepts IP addresses and DNS domain names as valid
// normalizeIPv4(ip)
// normalizeIPv6(ip)
//
// normalizePath(path)
//
//
//URI and email parsing functions
//output of all parsing functions is normalized
//
// parseURI(uri)	//splits a URI into its parts
//
// parseHttp(uri[, requireMultipleLabels])	//splits an http or https scheme URI into its parts
//
// parseMailto(uri)	//splits a mailto scheme URI into its parts
//
// parseQuery(queryString)	//splits a query string into an array of name/value pairs
// parseQuery(queryString, name)	//returns an array of values for the specified name
//
// parseEmailAddress(address)	//splits a single email address into its parts
//
//
//
// fixHyperlink(str[, allowedSchemes[, domain]])	//attempts to fix a URI (if needed) and normalizes it


//This script does not support IPvFuture literal address formats


//general references:
// RFC 3986 "Uniform Resource Identifier (URI): Generic Syntax"   http://tools.ietf.org/html/rfc3986
// How to Obscure Any URL   http://www.pc-help.org/obscure.htm
// RFC 6068 "The 'mailto' URI Scheme"	http://tools.ietf.org/html/rfc6068


(function(){
	
	"use strict";
	
	this.normalizeHost = normalizeHost;
	this.normalizeDNSHost = normalizeDNSHost;
	this.normalizeIPv4 = normalizeIPv4;
	this.normalizeIPv6 = normalizeIPv6;
	this.normalizePath = normalizePath;
	this.parseURI = parseURI;
	this.parseHttp = parseHttp;
	this.parseMailto = parseMailto;
	this.parseQuery = parseQuery;
	this.parseEmailAddress = parseEmailAddress;
	this.fixHyperlink = fixHyperlink;
	
	//****************************************************************
	//**************************** URI *******************************
	//****************************************************************
	
	//normalizes a URI and splits it into its parts
	//returns an object:
	//	.uri			//entire normalized URI
	//	.scheme
	//	.authority		//entire authority; empty string if there isn't one
	//	 .userinfo
	//	 .host
	//	 .port
	//	.path
	//	.query
	//	.fragment
	//returns null if URI is not valid
	//see RFC 3986 http://tools.ietf.org/html/rfc3986
	function parseURI(uri){
		
		var rxp, parts, scheme, authority, userinfo, host, port, path, query, fragment;
		
		if(!uri) return null;
		uri = String(uri);
		
		rxp = /^([a-z][a-z0-9+.-]*):(?:\/\/((?:(?=((?:[a-z0-9-._~!$&'()*+,;=:]|%[0-9A-F]{2})*))(\3)@)?(?=(\[[0-9A-F:.]{2,}\]|(?:[a-z0-9-._~!$&'()*+,;=]|%[0-9A-F]{2})*))\5(?::(?=(\d*))\6)?)(\/(?=((?:[a-z0-9-._~!$&'()*+,;=:@\/]|%[0-9A-F]{2})*))\8)?|(\/?(?!\/)(?=((?:[a-z0-9-._~!$&'()*+,;=:@\/]|%[0-9A-F]{2})*))\10)?)(?:\?(?=((?:[a-z0-9-._~!$&'()*+,;=:@\/?]|%[0-9A-F]{2})*))\11)?(?:#(?=((?:[a-z0-9-._~!$&'()*+,;=:@\/?]|%[0-9A-F]{2})*))\12)?$/i;
		/*composed as follows:
			^
			([a-z][a-z0-9+.-]*):															#1 scheme
			(?:
				\/\/																		it has an authority:
				
				(																			#2 authority
					(?:(?=((?:[a-z0-9-._~!$&'()*+,;=:]|%[0-9A-F]{2})*))(\3)@)?					#4 userinfo
					(?=(\[[0-9A-F:.]{2,}\]|(?:[a-z0-9-._~!$&'()*+,;=]|%[0-9A-F]{2})*))\5		#5 host (loose check to allow for IPv6 addresses)
					(?::(?=(\d*))\6)?															#6 port
				)
				
				(\/(?=((?:[a-z0-9-._~!$&'()*+,;=:@\/]|%[0-9A-F]{2})*))\8)?					#7 path
				
				|																			it doesn't have an authority:
				
				(\/?(?!\/)(?=((?:[a-z0-9-._~!$&'()*+,;=:@\/]|%[0-9A-F]{2})*))\10)?			#9 path
			)
			(?:
				\?(?=((?:[a-z0-9-._~!$&'()*+,;=:@\/?]|%[0-9A-F]{2})*))\11					#11 query string
			)?
			(?:
				#(?=((?:[a-z0-9-._~!$&'()*+,;=:@\/?]|%[0-9A-F]{2})*))\12					#12 fragment
			)?
			$
		*/
		parts = rxp.exec(uri);
		if(!parts) return null;	//invalid URI
		
		scheme = parts[1].toLowerCase();
		authority = parts[2];
		userinfo = parts[4];
		host = parts[5];
		port = parts[6];
		path = normalizePath(parts[7] || parts[9]);
		query = parts[11];
		fragment = parts[12];
		
		if(authority){
			if((host = normalizeHost(host)) === null) return null;	//invalid host
			authority = (userinfo ? userinfo+"@" : "") + host + (port ? ":"+port : "");	//normalize authority
		}
		
		return {
			uri: scheme+":" + (typeof(authority) !== "undefined" ? "//"+authority : "") + path + (query ? "?"+query : "") + (fragment ? "#"+fragment : ""),
			scheme: scheme,
			authority: authority,
				userinfo: userinfo,
				host: host,
				port: port,
			path: path,
			query: query,
			fragment: fragment
		};
		
	};
	
	//splits an http or https scheme URI into its parts
	//returns an object:
	//	.uri			//entire normalized URI
	//	.scheme
	//	.authority		//entire authority
	//	 .userinfo
	//	 .host
	//	 .port
	//	.path
	//	.query
	//	.fragment
	//returns null if URI is not valid or if requireMultipleLabels===true but there is only one
	//requireMultipleLabels: specify whether a domain must consist of multiple labels (e.g., if true, "localhost" would be considered invalid)
	//see RFC 2616 http://tools.ietf.org/html/rfc2616#section-3.2
	function parseHttp(uri, requireMultipleLabels){
		
		uri = parseURI(uri);
		if(!uri) return null;	//invalid URI
		if(!(/^https?$/).test(uri.scheme) || !normalizeDNSHost(uri.host, requireMultipleLabels)) return null;	//not a valid http(s) URI
		
		if(!uri.path){
			uri.path = "/";
			uri.uri = uri.scheme+"://"+uri.authority+"/" + (uri.query ? "?"+uri.query : "") + (uri.fragment ? "#"+uri.fragment : "");
		}
		
		return uri;
		
	};
	
	//converts an obscured host to a more readable one
	//returns null if it's not a valid host
	//see http://www.pc-help.org/obscure.htm
	// and RFC 3986 http://tools.ietf.org/html/rfc3986
	function normalizeHost(host){
		
		var ip;
		
		if(host === "") return "";
		if(!host && host !== 0) return null;
		host = String(host);
		
		if((/^\[[0-9A-F:.]{2,}\]$/i).test(host) && (ip = normalizeIPv6(host.slice(1, -1))) ) return "["+ip+"]";	//it's a valid IPv6 address
		
		if(!(/^(?:[a-z0-9-._~!$&'()*+,;=]|%[0-9A-F]{2})*$/i).test(host)) return null;	//contains invalid characters
		
		//decode letters & numbers
		host = host.replace(/%(3\d|[46][1-9A-F]|[57][0-9A])/ig, function (match, p1){ return String.fromCharCode(parseInt(p1.toUpperCase(), 16)); });
		
		//decode allowed symbols: -._~!$&'()*+,;=
		host = host.replace(/%(2[146-9A-E]|3[BD]|5F|7E)/ig, function (match, p1){ return String.fromCharCode(parseInt(p1.toUpperCase(), 16)); });
		
		if( (ip = normalizeIPv4(host)) ) return ip;	//it's a valid IPv4 address
		
		//make percent encodings upper case; everything else lower case
		host = host.toLowerCase();
		host = host.replace(/%(..)/ig, function (match, p1){ return "%"+p1.toUpperCase(); });
		
		return host;
		
	};
	
	//converts an obscured host to a more readable one; only accepts IP addresses and DNS domain names as valid
	//returns null if it's not valid or if requireMultipleLabels===true but there is only one
	//requireMultipleLabels: specify whether a domain must consist of multiple labels (e.g., if true, "localhost" would be considered invalid)
	//see RFC 3986 http://tools.ietf.org/html/rfc3986
	// and RFC 2181 http://tools.ietf.org/html/rfc2181#section-11
	function normalizeDNSHost(host, requireMultipleLabels){
		
		host = normalizeHost(host);
		if(!host) return null;
		
		if((/[^a-z0-9:\[\].-]/i).test(host)) return null;	//contains invalid characters
		
		if(/^\d+(\.\d+){3}$/.test(host) || host[0] === "[") return host;	//it's an IP address
		
		//it's a domain name
		if(host.length > 255) return null;	//domain name is too long
		if(requireMultipleLabels && (/^(?=([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))\1(?:\.(?=([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))\2)+$/i).test(host))	//require at least two labels
			return host;	//valid domain
		else if((/^(?=([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))\1(?:\.(?=([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))\2)*$/i).test(host))	//allow a single label
			return host;	//valid domain
		
		return null;	//invalid
		
	};
	
	//see http://www.pc-help.org/obscure.htm
	// and http://en.wikipedia.org/wiki/IPv4#Address_representations
	function normalizeIPv4(ip){
		
		var parts, val, dwordToIp, vals, i;
		
		if(!(/^(?=(\d+|0x[0-9A-F]+))\1(?:\.(?=(\d+|0x[0-9A-F]+))\2){0,3}$/i).test(ip)) return null;	//invalid IP address
		
		parts = ip.split(".");
		vals = [];
		for(i=0; i<parts.length; i++){	//for each part
			if((/^0x/i).test(parts[1])){
				val = parseInt(parts[i], 16);	//convert hexadecimal to decimal
			}
			else if(parts[1][0] === "0"){
				val = parseInt(parts[i], 8);	//convert octal to decimal
			}
			else{
				val = 1*parts[i];
			}
			
			//if this is the last part and it's a dword
			//e.g., in an IP of 1192362298 or 71.1179962 or 71.18.314
			if(i === parts.length-1 && i < 3){
				//convert dword to decimal parts
				//e.g., 1179962 becomes 18.1.58
				dwordToIp = [];
				while(i < 4){
					dwordToIp.unshift(val % 256);
					val = (val-dwordToIp[0]) / 256;
					i++;
				}
				vals = vals.concat(dwordToIp);
				break;
			}
			val = val % 256;
			vals.push(val);
		}
		
		return vals.join(".");	//valid IP address
		
	};
	
	//see RFC 4291 http://tools.ietf.org/html/rfc4291
	// and RFC 5952 http://tools.ietf.org/html/rfc5952#section-4
	// and RFC 5952 http://tools.ietf.org/html/rfc5952#section-5
	function normalizeIPv6(ip){
		
		var fieldsLeft, fieldsRight, compacted, resultLeft = [], resultRight = [], i, rxp, m, longest, includesIPv4;
		
		if(!(/^[0-9A-F:.]{2,}$/i).test(ip)) return null;	//invalid IP address
		
		//converts the four 8-bit decimal values of an IPv4 address to the two low-order 16-bit hexadecimal values of an IPv6 address
		//see RFC 4291 http://tools.ietf.org/html/rfc4291#section-2.5.5
		// and RFC 5952 http://tools.ietf.org/html/rfc5952#section-5
		function v4to6(ip){
			ip = ip.split(".");
			return ((ip[0]*256 + ip[1]*1).toString(16) + ":" + (ip[2]*256 + ip[3]*1).toString(16)).toLowerCase();
		}
		
		if(!ip) return null;
		
		ip = ip.toLowerCase().split("::");	//split the IP at "::" (if it's used)
		if(ip.length > 2) return null;	//invalid IP; "::" used multiple times
		
		fieldsLeft = ip[0].split(":");
		compacted = ip.length === 2;
		fieldsRight = compacted ? ip[1].split(":") : null;
		
		if(fieldsLeft.length > 8 || (compacted && fieldsLeft.length + fieldsRight.length > 7)) return null;	//invalid IP; too many fields
		
		if(fieldsLeft[0] !== ""){	//there are fields on the left side of "::", or "::" isn't used
			for(i=0; i<fieldsLeft.length; i++){	//for each field
				if((/^[0-9A-F]{1,4}$/i).test(fieldsLeft[i])){	//valid hex field
					resultLeft.push(fieldsLeft[i]);
				}
				else if(!compacted && i === 6 && fieldsLeft.length === 7 && /^\d+(\.\d+){3}$/.test(fieldsLeft[i]) ){	//last part of entire IP is a ver. 4 IP
					if(/^(0+:){5}(0+|ffff)$/.test(resultLeft.join(":"))){	//well-known prefix that distinguishes an embedded IPv4
						includesIPv4 = true;
						resultLeft.push(normalizeIPv4(fieldsLeft[i]));
					}
					else{	//no recognized prefix for IPv4; convert it to IPv6
						fieldsLeft[i] = v4to6(normalizeIPv4(fieldsLeft[i]));	//convert field to a pair of IPv6 fields
						resultLeft.push(/^[^:]+/.exec(fieldsLeft[i])[0]);
						resultLeft.push(/:(.+)/.exec(fieldsLeft[i])[1]);
					}
				}
				else return null;	//invalid field
			}
		}
		
		if(compacted){	//"::" is used
			if(fieldsRight[0] !== ""){	//there are fields on the right side
				for(i=0; i<fieldsRight.length; i++){	//for each field
					if((/^[0-9A-F]{1,4}$/i).test(fieldsRight[i])){	//valid hex field
						resultRight.push(fieldsRight[i]);
					}
					else if(i === fieldsRight.length-1 && /^\d+(\.\d+){3}$/.test(fieldsRight[i]) ){	//last part of entire IP is a ver. 4 IP
						if(( /^((0+:)*0+)?$/.test(resultLeft.join(":")) && /^((0+:)*(0+|ffff))?$/.test(resultRight.join(":")) ) ||
						 /^(0+:){5}(0+|ffff)$/.test(resultLeft.join(":"))){	//well-known prefix that distinguishes an embedded IPv4
							includesIPv4 = true;
							resultRight.push(normalizeIPv4(fieldsRight[i]));
						}
						else{	//no recognized prefix for IPv4; convert it to IPv6
							fieldsRight[i] = v4to6(normalizeIPv4(fieldsRight[i]));	//convert field to a pair of IPv6 fields
							resultRight.push(/^[^:]+/.exec(fieldsRight[i])[0]);
							resultRight.push(/:(.+)/.exec(fieldsRight[i])[1]);
						}
					}
					else return null;	//invalid field
				}
			}
			
			//replace "::" with the zeroes it represents
			i = (includesIPv4 ? 7 : 8) - (resultLeft.length + resultRight.length);
			for(i; i>0; i--){
				resultLeft.push("0");
			}
		}
		
		if(resultLeft.length+resultRight.length < (includesIPv4 ? 7 : 8)) return null; //invalid IP; too few fields
		
		//combine the resulting fields
		ip = (resultLeft.concat(resultRight).join(":"));
		
		//if it includes an embedded IPv4, make sure the prefix ends with ffff instead of 0
		if(includesIPv4) ip = ip.replace(/^(0+:){6}/, "0:0:0:0:0:ffff:");
		
		//remove leading zeros in fields
		ip = ip.replace(/(^|:)0+([^:.])/g, "$1$2");
		
		//replace longest run of multiple zeros with "::" shortcut
		longest = "";
		rxp = /(?:^|:)((0:)+0)/g;
		while(m = rxp.exec(ip)){
			if(m[1].length > longest.length) longest = m[1];
		}
		if(longest){
			rxp = new RegExp("(^|:)"+longest+"(:|$)");
			ip = ip.replace(rxp, "::");
		}
		
		return ip;
		
	};
	
	//converts an obscured path to a more readable one
	function normalizePath(path){
		
		if(!path && path !== 0) return "";
		
		//decode letters & numbers
		path = path.replace(/%(3\d|[46][1-9A-F]|[57][0-9A])/ig, function (match, p1){ return String.fromCharCode(parseInt(p1.toUpperCase(), 16)); });
		
		//decode allowed symbols: -._~!$&'()*+,;=:@/
		path = path.replace(/%(2[146-9A-F]|3[ABD]|40|5F|7E)/ig, function (match, p1){ return String.fromCharCode(parseInt(p1.toUpperCase(), 16)); });
		
		//make percent encodings upper case
		path = path.replace(/%(..)/ig, function (match, p1){ return "%"+p1.toUpperCase(); });
		
		return path;
		
	};
	
	//parses a query string as a sequence of name/value pairs
	//if no name is specified, returns an array of name/value pairs (each pair is an object {name, value})
	//if a name is specified, returns an array of values with that name
	function parseQuery(queryString, name){
		
		var results = [], pairs, pair, i;
		
		if(!queryString) return [];
		
		pairs = queryString.split("&");
		
		if(!name && name !== 0){	//no name is specified; return all name/value pairs
			for(i=0; i<pairs.length; i++){
				pair = pairs[i].split("=");
				if(pair.length === 1 || pair[0] === "") continue;	//there is no "=" or no name; skip it
				results.push( { name: decodeURIComponent(pair.shift()), value: decodeURIComponent(pair.join("=")) } );	//add the name/value pair to the results
			}
		}
		else{	//a name is specified; only return values for that name
			for(i=0; i<pairs.length; i++){
				pair = pairs[i].split("=");
				if(pair.length === 1 || pair[0] === "") continue;	//there is no "=" or no name; skip it
				if(name != pair.shift()) continue;	//name does not match the one specified; skip it
				results.push( decodeURIComponent(pair.join("=")) );	//add the value to the results
			}
		}
		
		return results;
		
	};
	
	//****************************************************************
	//************************** Mailto ******************************
	//****************************************************************
	
	//splits a mailto scheme URI into its parts
	//returns an object:
	//	.uri		//entire normalized URI
	//	.scheme		//"mailto"
	//	.to			//array of valid email addresses
	//	.cc			//array of valid email addresses
	//	.bcc		//array of valid email addresses
	//	.subject
	//	.body
	//	.headers	//array of other headers besides the above (each header is an object {name, value})
	//returns null if it's not a valid mailto URI or there is no destination
	//only includes valid email addresses; the rest are discarded
	//see RFC 6068 http://tools.ietf.org/html/rfc6068
	function parseMailto(uri){
		
		var parts, headers, i, query = "";
		
		//splits the string at the commas (ignoring commas within quoted strings or comments)
		//only returns valid email addresses
		function splitEmailAddresses(str){
			
			var parts, rxp, c, commentLevel = 0, inQuote = false, parsed, addresses = [];
			
			parts = str.split(",");
			while(parts.length){
				
				rxp = /(?:^|[^\\()"])(?:\\\\)*([()"])/g;
				
				//determine if inside a comment or a quoted string
				while(c = rxp.exec(parts[0])){
					if(!inQuote){
						if(c[1] === "(") commentLevel++;
						else if(c[1] === ")") commentLevel--;
						else inQuote = true;
					}
					else if(c[1] === "\""){
						inQuote = false;
					}
				}
				
				if(inQuote || commentLevel > 0){	//inside a quoted string or a comment
					if(parts[1]){	//if there is another part
						//concatenate the first two parts and try again
						parts[1] = parts[0] + "," + parts[1];
						inQuote = false;
						commentLevel = 0;
					}
					//else there are no more parts; still inside a comment or quoted string; invalid address
				}
				else if(commentLevel === 0){
					parsed = parseEmailAddress(parts[0]);
					if(parsed && !parsed.unrecognizedDomain){	//it's a valid address
						addresses.push(parsed.display ? parsed.full : parsed.simple);
					}
					//else it's an invalid address
				}
				//else there is an extra closing parenthesis; invalid address
				
				parts.shift();
				
			}
			
			return addresses;
			
		}
		
		function encodePart(str){
			return str.replace(/[^a-z0-9-._~!$'()*+,;:@]/ig, function (match){ return "%"+match.charCodeAt(0).toString(16).toUpperCase(); });
		}
		
		uri = parseURI(uri);
		if(!uri || uri.scheme !== "mailto" || uri.authority) return null;	//not a valid mailto URI
		//note: if there is a fragment, it will simply be left out
		
		parts = {
			uri: "",
			scheme: "mailto",
			to: [],
			cc: [],
			bcc: [],
			subject: "",
			body: "",
			headers: []	//other headers besides the above (each header is an object {name, value})
		};
		
		if(uri.path) parts.to = splitEmailAddresses(decodeURIComponent(uri.path));
		else parts.to = [];
		
		headers = parseQuery(uri.query);
		for(i=0; i<headers.length; i++){
			if(headers[i].value === "") continue;
			
			if(headers[i].name === "to") parts.to = parts.to.concat(splitEmailAddresses(headers[i].value));
			else if(headers[i].name === "cc") parts.cc = parts.cc.concat(splitEmailAddresses(headers[i].value));
			else if(headers[i].name === "bcc") parts.bcc = parts.bcc.concat(splitEmailAddresses(headers[i].value));
			else if(headers[i].name === "subject") parts.subject = headers[i].value;
			else if(headers[i].name === "body") parts.body = headers[i].value;
			else parts.headers.push(headers[i]);
		}
		
		if(parts.to.length + parts.cc.length + parts.bcc.length === 0) return null;	//no destination
		
		parts.uri = "mailto:" + encodePart(parts.to.join(","));
		
		if(parts.cc.length){
			if(query) query += "&";
			query += "cc=" + encodePart(parts.cc.join(","));
		}
		if(parts.bcc.length){
			if(query) query += "&";
			query += "bcc=" + encodePart(parts.bcc.join(","));
		}
		if(parts.subject){
			if(query) query += "&";
			query += "subject=" + encodePart(parts.subject);
		}
		if(parts.body){
			if(query) query += "&";
			query += "body=" + encodePart(parts.body);
		}
		if(parts.headers.length){
			for(i=0; i<parts.headers.length; i++){
				if(query) query += "&";
				query += encodePart(parts.headers[i].name) + "=" + encodePart(parts.headers[i].value);
			}
		}
		
		if(query) parts.uri += "?" + query;
		
		return parts;
	};
	
	//normalizes a single email address (mailbox) and splits it into its parts
	//returns an object:
	//	.display	//display name
	//	.local		//local part of the address
	//	.domain		//domain part of the address
	//	.unrecognizedDomain	//true if the domain is something other than a DNS domain, IPv4, IPv4 literal, or IPv6 literal
	//	.simple		//local@domain
	//	.full		//"display name" <local@domain>   if there is a display name
	//				//local@domain   if there is not a display name
	//	.stripped	//same address that was passed to the function, but unfolded and without any comments
	//returns null if it's not a valid address
	//unfolds whitespace and removes comments
	//obsolete syntax is not supported
	//see RFC 5322 http://tools.ietf.org/html/rfc5322
	// and RFC 5321 http://tools.ietf.org/html/rfc5321#section-4.1.3
	// and http://www.addedbytes.com/lab/email-address-validation
	// and http://email.about.com/od/emailbehindthescenes/f/email_case_sens.htm
	function parseEmailAddress(address){
		
		var mailbox = address;
		var rxpAtom, rxpDotAtom, rxpQuotedString, rxpDomainLiteral, nameAddr;
		var m, ret, result = "", temp1, temp2;
		var parts = {};
		
		//remove CFWS from beginning of str (actually just removes comments; surrounding whitespace is preserved)
		function removeComments(str){
			
			var wsp = "", m, inQuote = false, commentLevel = 0;
			
			while(m = /^([\t ]*)\(/.exec(str)){
				
				//save the whitespace
				if(m[1]){
					
					wsp += m[1];
					str = str.slice(m[1].length);
					
				}
				
				//remove comment
				while(m = /[()"\\]/.exec(str)){
					
					if(inQuote){	//inside a quoted string
						if(m[0] === "\""){	//end of quoted string
							inQuote = false;
							str = str.slice(m.index+1);
						}
						else if(m[0] === "\\"){	//quoted pair
							console.log(m[0] === "\\");
							if(!str[m.index+1]){	//end of string; invalid quoted pair
								return null;
							}
							str = str.slice(m.index+2);
						}
						else{
							str = str.slice(m.index+1);
						}
					}
					else if(m[0] === "("){	//beginning of comment
						commentLevel++;
						str = str.slice(m.index+1);
					}
					else if(m[0] === ")"){	//end of comment
						commentLevel--;
						str = str.slice(m.index+1);
					}
					else if(m[0] === "\""){	//beginning of quoted string
						inQuote = true;
						str = str.slice(m.index+1);
					}
					else{	//quoted pair
						if(!str[m.index+1]){	//end of string; invalid quoted pair
							return null;
						}
						str = str.slice(m.index+2);
					}
					
					if(!commentLevel){	//no longer inside a comment
						break;
					}
					
				}
				
				if(inQuote || commentLevel){	//no closing quote or parenthesis
					return null;
				}
				
			}
			
			m = /^[\t ]*/.exec(str);
			wsp += m[0];
			str = str.slice(m[0].length);
			
			return [wsp, str];
			
		}
		
		if(!mailbox) return null;
		
		mailbox = mailbox.replace(/\n([\t ])/g, "$1");	//unfold whitespace
		
		if((/[^\t a-z0-9!#$%&'*+-\/=?\^_`{|}~()<>\[\]:;@\\,."]/i).test(address)) return null;	//contains invalid characters
		
		//remove comments from mailbox (comments can nest, so they have to be stripped manually)
		
		rxpAtom = /^[a-z0-9!#$%&'*+-\/=?\^_`{|}~]+/i;
		rxpDotAtom = /^[a-z0-9!#$%&'*+-\/=?\^_`{|}~]+(?:\.[a-z0-9!#$%&'*+-\/=?\^_`{|}~]+)*/i;
		rxpQuotedString = /^"(?:[\t a-z0-9!#$%&'*+-\/=?\^_`{|}~()<>\[\]:;@,.]*(?:\\[\t a-z0-9!#$%&'*+-\/=?\^_`{|}~()<>\[\]:;@\\,."])*)*"/i;
		rxpDomainLiteral = /^\[[\t a-z0-9!#$%&'*+-\/=?\^_`{|}~()<>:;@,."]*\]/i;
		
		ret = removeComments(mailbox);
		if(!ret) return null;
		result += ret[0];
		mailbox = ret[1];
		
		if(mailbox[0] === "<"){
			nameAddr = true;	//angle brackets are used
			ret = removeComments(mailbox.slice(1));
			if(!ret) return null;
			result += "<"+ret[0];
			mailbox = ret[1];
		}
		
		//get the first block of text
		if(m = rxpDotAtom.exec(mailbox)){
			temp1 = m[0];
			mailbox = mailbox.slice(m[0].length);
		}
		else if(m = rxpQuotedString.exec(mailbox)){
			temp1 = m[0];
			mailbox = mailbox.slice(m[0].length);
		}
		else{
			return null;	//invalid mailbox
		}
		
		ret = removeComments(mailbox);
		if(!ret) return null;
		temp2 = ret[0]
		mailbox = ret[1];
		
		//temp1 = local-part text   OR   display-name text
		//temp2 = WSP after temp1
		
		if(mailbox[0] === "<"){	//temp1 was the display name
			if(nameAddr) return null;	//invalid mailbox; extra "<"
			if(rxpDotAtom.test(temp1) && !rxpAtom.test(temp1)) return null;	//invalid display name
			nameAddr = true;	//angle brackets are used
			
			//add the display name to the result
			ret = removeComments(mailbox.slice(1));
			if(!ret) return null;
			result += temp1+temp2+"<"+ret[0];
			mailbox = ret[1];
			
			parts.display = temp1;
			
			//get the local part
			if(m = rxpAtom.exec(mailbox)){
				temp1 = m[0];
				mailbox = mailbox.slice(m[0].length);
			}
			else if(m = rxpQuotedString.exec(mailbox)){
				temp1 = m[0];
				mailbox = mailbox.slice(m[0].length);
			}
			else{
				return null;	//invalid mailbox
			}
			
			ret = removeComments(mailbox);
			if(!ret) return null;
			temp2 = ret[0];
			mailbox = ret[1];
		}
		else{
			parts.display = "";
		}
		
		//temp1 = local-part text
		//temp2 = WSP after temp1
		
		//add the local part to the result
		result += temp1+temp2;
		
		parts.local = temp1;
		
		//at this point, `result` is one of these:
		//	local-part
		//	"<" local-part
		//	display-name "<" local-part
		
		if(mailbox[0] !== "@") return null;	//invalid address
		
		//add "@" to the result
		ret = removeComments(mailbox.slice(1));
		if(!ret) return null;
		result += "@"+ret[0];
		mailbox = ret[1];
		
		//get the domain and add it to the result
		if(m = rxpDotAtom.exec(mailbox)){
			result += m[0];
			mailbox = mailbox.slice(m[0].length);
			
			parts.domain = m[0];
		}
		else if(m = rxpDomainLiteral.exec(mailbox)){
			result += m[0];
			mailbox = mailbox.slice(m[0].length);
			
			parts.domain = m[0];
		}
		else{
			return null;	//invalid domain
		}
		
		ret = removeComments(mailbox);
		if(!ret) return null;
		result += ret[0];
		mailbox = ret[1];
		
		if(nameAddr){	//angle brackets are used
			if(mailbox[0] !== ">") return null;	//invalid mailbox
			ret = removeComments(mailbox.slice(1));
			if(!ret) return null;
			result += ">"+ret[0];
			mailbox = ret[1];
		}
		
		parts.stripped = result;
		
		//at this point, `result` is one of these:
		//	local-part "@" domain
		//	"<" local-part "@" domain ">"
		//	display-name "<" local-part "@" domain ">"
		
		
		//normalize the display name
		parts.display = parts.display.replace(/\s+/, " ");	//replace blocks of whitespace with a single space
		if(parts.display[0] === "\""){
			parts.display = parts.display.slice(1,-1);	//remove the quotes
			parts.display = parts.display.trim ? parts.display.trim() : parts.display.replace(/^\s+|\s+$/g, "");	//trim
		}
		
		//normalize the local part
		if(parts.local[0] === "\"" && /^[a-z0-9!#$%&'*+-\/=?\^_`{|}~]+(?:\.[a-z0-9!#$%&'*+-\/=?\^_`{|}~]+)*$/i.test(parts.local.slice(1,-1))){
			parts.local = parts.local.slice(1,-1);	//remove quotes if they aren't required
		}
		
		//normalize the domain
		if((/^\[IPv6:/i).test(parts.domain)){	//it's an IPv6 address literal
			if(temp1 = normalizeIPv6(parts.domain.slice(6, -1))){
				parts.domain = "[IPv6:"+temp1+"]";
			}
			else{
				return null;	//invalid IPv6
			}
		}
		else if(parts.domain[0] === "[" && (temp1 = normalizeIPv4(parts.domain.slice(1,-1)))){	//it's an IPv4 address literal
			parts.domain = temp1;
		}
		else if(parts.domain[0] !== "[" && (temp1 = normalizeDNSHost(parts.domain))){	//it's a domain or an IPv4 address
			parts.domain = temp1;
		}
		else{
			parts.unrecognizedDomain = true;
		}
		
		parts.simple = parts.local+"@"+parts.domain;
		if(parts.display){
			parts.full = "\""+parts.display+"\" <"+parts.simple+">";
		}
		else{
			parts.full = parts.simple;
		}
		
		return parts;
		
	};
	
	//****************************************************************
	//*************************** Fixes ******************************
	//****************************************************************
	
	//attempts to fix a URI (if needed) and normalizes it
	// allowedSchemes	a string or array of strings listing accepted schemes; http, https, and mailto by default if none are specified
	// domain			host name (and optionally port) to use if an http/https URI is relative; current page's domain by default
	//if the string does not have a scheme, it will be assumed that it's meant to be that of the current page (e.g., if str is a relative URL)
	//returns null if it can't be fixed or if the allowedSchemes argument is invalid
	function fixHyperlink(str, allowedSchemes, domain){
		
		var scheme, lnk, m, i, j, tmp;
		
		if(!domain && domain !== 0) domain = window.location.host;
		
		if(allowedSchemes && Object.prototype.toString.call(allowedSchemes) === "[object Array]" && allowedSchemes.length){	//allowedSchemes is an array with at least one element
			for(i=0; i<allowedSchemes.length; i++){
				if(typeof(allowedSchemes[i]) !== "string" || !(/^[a-z][a-z0-9+.-]*$/i).test(allowedSchemes[i])){	//invalid scheme
					allowedSchemes.splice(i,1);	//remove it from the array
				}
			}
			if(!allowedSchemes.length){
				return null;	//no valid schemes
			}
		}
		else if(typeof(allowedSchemes) === "string"){	//allowedSchemes is a string
			if(!(/^[a-z][a-z0-9+.-]*$/i).test(allowedSchemes)) return null;	//invalid scheme
			allowedSchemes = [allowedSchemes];	//use it as the only allowed scheme
		}
		else{
			if(!allowedSchemes || !allowedSchemes.length){	//allowed schemes not specified
				allowedSchemes = ["http", "https", "mailto"];	//use default
			}
			else{
				return null;	//allowedSchemes is not valid
			}
		}
		
		//get scheme
		scheme = (/^([a-z][a-z0-9+.-]*):/i).exec(str);
		scheme = scheme ? scheme[1].toLowerCase() : window.location.protocol.slice(0,-1);	//if the string does not include a valid scheme, assume it's meant to be that of the current page
		for(i=0; i<allowedSchemes.length; i++){
			if(scheme === allowedSchemes[i]) break;
		}
		if(!allowedSchemes[i]){	//scheme is not allowed
			//the previous regexp match may have been a DNS host
			if(scheme !== "http" && scheme !== "https" && (/^(?=([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))\1(?:\.(?=([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))\2)*:/i).test(str)){
				scheme = window.location.protocol.slice(0,-1);	//assume the scheme is meant to be that of the current page
				for(i=0; i<allowedSchemes.length; i++){
					if(scheme === allowedSchemes[i]) break;
				}
				if(!allowedSchemes[i]){	//scheme is not allowed
					return null;
				}
			}
			else{
				return null;	//scheme is not allowed
			}
		}
		
		//percent-encode illegal characters
		str = str.replace(/([^a-z0-9-._~!$&'()*+,;=:@\/\[\]%?#])|%(?![0-9A-F]{2})/ig, function (match, p1){
				if(p1) return "%"+p1.charCodeAt(0).toString(16);
				else return "%25";	//percent sign
			});
		i = str.search(/\?/);	//index of first question mark
		j = str.search(/#/);	//index of first number sign
		if(j >= 0 && j < i){	//no query; only a fragment
			str = str.slice(0,j+1) + str.slice(j+1).replace(/#/g, "%23");	//percent-encode illegal number signs
		}
		else if(i >= 0){	//query
			tmp = j >= 0 ? str.slice(j) : "";
			str = str.slice(0,i+1) + str.slice(i+1,j).replace(/\?/g, "%3F");	//percent-encode illegal question marks
			if(tmp){	//fragment
				str = str + "#" + tmp.slice(1).replace(/#/g, "%23");	//percent-encode illegal number signs
			}
		}
		
		//fix & normalize
		if(scheme === "http" || scheme === "https"){
			if(!(new RegExp("^"+scheme+"://", "i")).test(str)){
				if(str[0] === "/"){ 	//path (relative to root)
					lnk = parseHttp(scheme+"://"+domain+str.replace(/\[/g, "%5B").replace(/\]/g, "%5D"));
				}
				else{
					lnk = parseHttp(scheme+"://"+domain+"/"+str.replace(/\[/g, "%5B").replace(/\]/g, "%5D"));
				}
			}
			else{
				lnk = parseHttp(str);
				if(!lnk){
					lnk = parseHttp(str.replace(/\[/g, "%5B").replace(/\]/g, "%5D"));
				}
			}
		}
		else if(scheme === "mailto"){
			lnk = parseMailto(str.replace(/^mailto:\/\//i, "mailto:%2F%2F").replace(/\[/g,"%5B").replace(/\]/g,"%5D"));
		}
		else{
			lnk = parseURI(str.replace(/\[/g,"%5B").replace(/\]/g,"%5D"));
		}
		
		if(!lnk) return null;	//can't be fixed
		return lnk.uri;	//fixed & normalized
	};
	
}).call(this);
