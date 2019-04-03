/**
 * This script does not support IPvFuture literal address formats, nor internationalized domain names (IDNs).
 * 
 * General references:
 *   RFC 3986 "Uniform Resource Identifier (URI): Generic Syntax"   http://tools.ietf.org/html/rfc3986
 *   How to Obscure Any URL   http://www.pc-help.org/obscure.htm
 *   RFC 6068 "The 'mailto' URI Scheme"	  http://tools.ietf.org/html/rfc6068
 */


(function(){
	
	"use strict";
	
	function defineProperty(object, propertyName, value, isWritable, isEnumerable, isConfigurable){
		Object.defineProperty(object, propertyName, { value:value, writable:isWritable, enumerable:isEnumerable, configurable:isConfigurable });
	}
	
	//****************************************************************
	//**************************** URI *******************************
	//****************************************************************
	
	/**
	 * Validates and normalizes a URI, and splits it into its parts.
	 * 
	 * ParseURI(uri)
	 * @param {string} uri
	 * @return {object} - Object containing the URI and its parts. Null if the URI is invalid. The members depend on if the scheme is http, https, mailto, or something else. Possible members:
	 *   {string} .uri - The normalized URI.
	 *   {string} .scheme
	 *   {string} .authority - For non-http/https/mailto URIs. Empty string if there isn't an authority.
	 *   {object} .authority - For http or https URIs. Coerces to a string of the entire authority.
	 *     {string} .authority.userinfo - For http or https URIs.
	 *     {string} .authority.host - Coerces to a string.
	 *       {array} .authority.host.labels - Array of labels within a domain name. Undefined if it's an IP.
	 *       {string} .authority.host.ip - IP address (IPv4 if possible).
	 *       {string} .authority.host.ipv4 - IPv4 version of the IP.
	 *       {string} .authority.host.ipv6 - IPv6 version of the IP.
	 *     {string} .authority.port - For http or https URIs.
	 *   {string} .path - For non-mailto URIs.
	 *   {array} .query - For non-mailto URIs. An array of name/value pairs (each pair is an object {name, value}). Coerces to a string of the entire query.
	 *   {string} .fragment - For non-mailto URIs.
	 *   {array} .to - For mailto URIs. Array of valid email addresses.
	 *   {array} .cc - For mailto URIs. Array of valid email addresses.
	 *   {array} .bcc - For mailto URIs. Array of valid email addresses.
	 *   {string} .subject - For mailto URIs.
	 *   {string} .body - For mailto URIs.
	 *   {array} .headers - For mailto URIs. An array of additional email headers (each header is an object {name, value}).
	 * 
	 * See RFC 3986 http://tools.ietf.org/html/rfc3986
	 */
	function ParseURI(uri){
		
		if(!uri) return null;
		uri = String(uri);
		
		let rxp = /^([a-z][a-z0-9+.-]*):(?:\/\/((?:(?=((?:[a-z0-9-._~!$&'()*+,;=:]|%[0-9A-F]{2})*))(\3)@)?(?=(\[[0-9A-F:.]{2,}\]|(?:[a-z0-9-._~!$&'()*+,;=]|%[0-9A-F]{2})*))\5(?::(?=(\d*))\6)?)(\/(?=((?:[a-z0-9-._~!$&'()*+,;=:@\/]|%[0-9A-F]{2})*))\8)?|(\/?(?!\/)(?=((?:[a-z0-9-._~!$&'()*+,;=:@\/]|%[0-9A-F]{2})*))\10)?)(?:\?(?=((?:[a-z0-9-._~!$&'()*+,;=:@\/?]|%[0-9A-F]{2})*))\11)?(?:#(?=((?:[a-z0-9-._~!$&'()*+,;=:@\/?]|%[0-9A-F]{2})*))\12)?$/i;
		/*Composed as follows:
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
		let parts = rxp.exec(uri);
		if(!parts) return null;	//invalid URI
		
		let scheme = parts[1].toLowerCase(),
			authority = parts[2],
			userinfo = parts[4],
			host = parts[5],
			port = parts[6],
			path = normalizePath(parts[7] || parts[9]),
			query = parts[11],
			fragment = parts[12];
		
		if(authority){
			if((host = normalizeHost(host)) === null) return null;	//invalid host
			authority = (userinfo ? userinfo+"@" : "") + host + (port ? ":"+port : "");	//normalize authority
		}
		
		uri = scheme+":" + (authority !== (void 0) ? "//"+authority : "") + path + (query ? "?"+query : "") + (fragment ? "#"+fragment : "");
		
		let queryObj = parseQuery(query);
		query = queryObj.toString();
		
		if((/^https?$/).test(scheme)){	//it's a URL (http or https)
			
			if(!host) return null;
			host = normalizeDNSHost(host);
			if(!host) return null;
			
			port = port || (scheme === "http" ? "80" : "443");
			authority = (userinfo ? userinfo+"@" : "") + host.host + ((scheme==="http" && port==="80") || (scheme==="https" && port==="443") ? "" : ":"+port);
			path = path || "/";
			
			uri = scheme+"://"+authority + path + (query ? "?"+query : "") + (fragment ? "#"+fragment : "");
			
			let authorityObj = {};
			defineProperty(authorityObj, "toString", function (){ return authority; }, true, false, true);
			authorityObj.userinfo = userinfo;
			authorityObj.host = {};
			defineProperty(authorityObj.host, "toString", function (){ return host.host; }, true, false, true);
			authorityObj.host.labels = host.labels;
			authorityObj.host.ip = host.ip;
			authorityObj.host.ipv4 = host.ipv4;
			authorityObj.host.ipv6 = host.ipv6;
			authorityObj.port = port;
			
			return {
				uri: uri,
				scheme: scheme,
				authority: authorityObj,
				path: path,
				query: queryObj,
				fragment: fragment
			};
			
		}
		else if(scheme === "mailto"){
			
			if(authority || fragment) return null;
			
			return parseMailto({
					uri: uri,
					scheme: scheme,
					path: path,
					query: query
				});
			
		}
		else{
			
			return {
				uri: uri,
				scheme: scheme,
				authority: authority,
				path: path,
				query: queryObj,
				fragment: fragment
			};
			
		}
		
	};
	
	//converts an obscured host to a more readable one
	//returns null if it's not a valid host
	//see http://www.pc-help.org/obscure.htm
	// and RFC 3986 http://tools.ietf.org/html/rfc3986
	function normalizeHost(host){
		
		let ip;
		
		if(host === "") return "";
		host = String(host);
		
		if((/^\[[0-9A-F:.]{2,}\]$/i).test(host) && (ip = normalizeIPv6(host.slice(1, -1))) ) return "["+ip+"]";	//it's a valid IPv6 address
		
		if(!(/^(?:[a-z0-9-._~!$&'()*+,;=]|%[0-9A-F]{2})*$/i).test(host)) return null;	//contains invalid characters
		
		//decode percent encodings of valid characters
		host = host.replace(/%(2[146-9A-E]|3\d|3[BD]|[46][1-9A-F]|[57][0-9A]|5F|7E)/ig, function (match, p1){ return String.fromCharCode(parseInt(p1, 16)); });
		
		if( (ip = normalizeIPv4(host)) ) return ip;	//it's a valid IPv4 address
		
		//make percent encodings upper case; everything else lower case
		host = host.toLowerCase();
		host = host.replace(/%(..)/ig, function (match, p1){ return "%"+p1.toUpperCase(); });
		
		return host;
		
	};
	
	//converts an obscured host to a more readable one; only accepts IP addresses and DNS domain names as valid
	//returns null if it's not valid
	//this does not support internationalized domain names (IDNs) (RFC 3490)
	//see RFC 3986 http://tools.ietf.org/html/rfc3986#section-3.2.2
	// and RFC 2181 http://tools.ietf.org/html/rfc2181#section-11
	// and RFC 1123 https://tools.ietf.org/html/rfc1123#page-13
	// and RFC 3490 https://tools.ietf.org/html/rfc3490
	function normalizeDNSHost(host){
		
		host = normalizeHost(host);
		if(!host) return null;
		
		if((/[^a-z0-9:\[\].-]/i).test(host)) return null;	//contains invalid characters
		
		if(/^\d+(\.\d+){3}$/.test(host))	//it's an IPv4 address
			return { host:host, ip:host, ipv4:host, ipv6:"::ffff:"+v4to6(host) };
		if(host[0] === "["){	//it's an IPv6 address
			let ipv6 = host.slice(1, -1),
				ipv4 = v6to4(ip);
			return { host:(ipv4||host), ip:(ipv4||ipv6), ipv4:ipv4, ipv6:ipv6 };
		}
		
		if(host.length > 255) return null;	//too long for a domain name
		
		if((/^(?=([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))\1(?:\.(?=([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))\2)*$/i).test(host))	//it's a domain name
			return { host:host, labels:host.split(".") };
		
		return null;	//invalid
		
	};
	
	//converts the four 8-bit decimal values of a normalized IPv4 address to the two low-order 16-bit hexadecimal values of an IPv6 address
	//see RFC 4291 http://tools.ietf.org/html/rfc4291#section-2.5.5
	// and RFC 5952 http://tools.ietf.org/html/rfc5952#section-5
	function v4to6(ip){
		ip = ip.split(".");
		return ((ip[0]*256 + ip[1]*1).toString(16) + ":" + (ip[2]*256 + ip[3]*1).toString(16)).toLowerCase();
	}
	
	//converts a normalized IPv6 address to the four 8-bit decimal values of an IPv4 address, or undefined if it can't be converted
	function v6to4(ip){
		if(!/^::ffff:[0-9A-F]+:[0-9A-F]+$/i.test(ip)) return void 0;	//can't be converted to IPv4
		ip = /^::ffff:(.+):(.+)$/i.exec(ip);
		let h = 1*("0x"+ip[1]),
			b = h%256,
			a = (h-b)/256,
			result = a+"."+b+".";
		h = 1*("0x"+ip[2]);
		b = h%256;
		a = (h-b)/256;
		return result += a+"."+b;
	}
	
	//see http://www.pc-help.org/obscure.htm
	// and http://en.wikipedia.org/wiki/IPv4#Address_representations
	function normalizeIPv4(ip){
		
		if(!(/^(?=(\d+|0x[0-9A-F]+))\1(?:\.(?=(\d+|0x[0-9A-F]+))\2){0,3}$/i).test(ip)) return null;	//invalid IP address
		
		let parts = ip.split("."),
			vals = [];
		for(let i=0; i<parts.length; i++){	//for each part
			let val;
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
				let dwordToIp = [];
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
	function normalizeIPv6(ip, keepEmbeddedIPv4){
		
		if(!(/^[0-9A-F:.]{2,}$/i).test(ip)) return null;	//invalid IP address
		
		if(!ip) return null;
		
		ip = ip.toLowerCase().split("::");	//split the IP at "::" (if it's used)
		if(ip.length > 2) return null;	//invalid IP; "::" used multiple times
		
		let fieldsLeft = ip[0].split(":"),
			compacted = ip.length === 2,
			fieldsRight = compacted ? ip[1].split(":") : null,
			resultLeft = [],
			resultRight = [],
			includesIPv4;
		
		if(fieldsLeft.length > 8 || (compacted && fieldsLeft.length + fieldsRight.length > 7)) return null;	//invalid IP; too many fields
		
		if(fieldsLeft[0] !== ""){	//there are fields on the left side of "::", or "::" isn't used
			for(let i=0; i<fieldsLeft.length; i++){	//for each field
				if((/^[0-9A-F]{1,4}$/i).test(fieldsLeft[i])){	//valid hex field
					resultLeft.push(fieldsLeft[i]);
				}
				else if(!compacted && i === 6 && fieldsLeft.length === 7 && /^\d+(\.\d+){3}$/.test(fieldsLeft[i]) ){	//last part of entire IP is a ver. 4 IP
					if(keepEmbeddedIPv4 && /^(0+:){5}(0+|ffff)$/.test(resultLeft.join(":"))){	//well-known prefix that distinguishes an embedded IPv4
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
				for(let i=0; i<fieldsRight.length; i++){	//for each field
					if((/^[0-9A-F]{1,4}$/i).test(fieldsRight[i])){	//valid hex field
						resultRight.push(fieldsRight[i]);
					}
					else if(i === fieldsRight.length-1 && /^\d+(\.\d+){3}$/.test(fieldsRight[i]) ){	//last part of entire IP is a ver. 4 IP
						if(keepEmbeddedIPv4 && ( ( /^((0+:)*0+)?$/.test(resultLeft.join(":")) && /^((0+:)*(0+|ffff))?$/.test(resultRight.join(":")) ) ||
						 /^(0+:){5}(0+|ffff)$/.test(resultLeft.join(":")) )){	//well-known prefix that distinguishes an embedded IPv4
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
			let i = (includesIPv4 ? 7 : 8) - (resultLeft.length + resultRight.length);
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
		let longest = "",
			rxp = /(?:^|:)((0:)+0)/g,
			m;
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
	//returns an array of name/value pairs (each pair is an object {name, value})
	function parseQuery(queryString){
		
		if(!queryString) return [];
		
		let pairs = queryString.split("&"),
			results = [],
			queryObj = {};
		for(let i=0; i<pairs.length; i++){
			let pair = pairs[i].split("=");
			if(pair.length === 1 || pair[0] === ""){	//there is no "=" or no name; skip it
				pairs.splice(i--,1);
				continue;
			}
			results.push( { name: decodeURIComponent(pair.shift()), value: decodeURIComponent(pair.join("=")) } );	//add the name/value pair to the results
		}
		queryString = pairs.join("&");
		
		queryObj.pairs = results;
		defineProperty(queryObj, "toString", function (){ return queryString; }, true, false, true);
		
		return queryObj;
		
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
	function parseMailto(parts){
		
		if(!/^(?:[a-z0-9-._~!$'()*+,:@]|%[0-9A-F]{2})*$/i.test(parts.path) || !/^(?:[a-z0-9-._~!$'()*+,;:@]|%[0-9A-F]{2})*$/i.test(parts.query)){
			return null;	//contains invalid characters
		}
		
		//splits the string at the commas (ignoring commas within quoted strings or comments)
		//only returns valid email addresses
		function splitEmailAddresses(str){
			
			let parts = str.split(","),
				commentLevel = 0,
				inQuote = false,
				addresses = [];
			
			while(parts.length){
				
				//decode percent-encoded characters
				parts[0] = decodeURIComponent(parts[0]);
				
				//determine if inside a comment or a quoted string
				let rxp = /(?:^|[^\\()"])(?:\\\\)*([()"])/g,
					c;
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
				else{
					let parsed = parseEmailAddress(parts[0]);
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
			return encodeURI(str).replace(/[\/?&=#]/g, function (match){ return "%"+match.charCodeAt(0).toString(16).toUpperCase(); });
		}
		
		parts.to = [];
		parts.cc = [];
		parts.bcc = [];
		parts.subject = "";
		parts.body = "";
		parts.headers = [];	//other headers besides the above (each header is an object {name, value})
		
		parts.to = parts.path ? splitEmailAddresses(parts.path) : [];
		
		let headers = parseQuery(parts.query);
		for(let i=0; i<headers.length; i++){
			if(headers[i].value === "") continue;
			
			headers[i].name = decodeURIComponent(headers[i].name);
			if(headers[i].name === "to")
				parts.to = parts.to.concat(splitEmailAddresses(headers[i].value));
			else if(headers[i].name === "cc")
				parts.cc = parts.cc.concat(splitEmailAddresses(headers[i].value));
			else if(headers[i].name === "bcc")
				parts.bcc = parts.bcc.concat(splitEmailAddresses(headers[i].value));
			else if(headers[i].name === "subject")
				parts.subject = decodeURIComponent(headers[i].value);
			else if(headers[i].name === "body")
				parts.body = decodeURIComponent(headers[i].value);
			else{
				headers[i].value = decodeURIComponent(headers[i].value);
				parts.headers.push(headers[i]);
			}
		}
		
		if(parts.to.length + parts.cc.length + parts.bcc.length === 0) return null;	//no destination
		
		parts.uri = "mailto:" + encodePart(parts.to.join(","));
		
		let query = "";
		if(parts.cc.length){
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
	
	/**
	 * Normalizes a single email address (mailbox) and splits it into its parts.
	 * 
	 * ParseURI.parseEmailAddress(address)
	 * @param {string} address - email address or mailbox (e.g., "display name" <local@domain> )
	 * @return {object} - Object containing the mailbox and its parts. Null if it's invalid.
	 *   {string} .full - If there is a display name: "display name" <local@domain>
	 *                    If there isn't: local@domain
	 *   {string} .simple - local@domain
	 *   {string} .display - display name
	 *   {string} .local - Local part of the address.
	 *   {string} .domain - Domain part of the address. This doesn't have to be a DNS domain or IP to be valid.
	 *   {boolean} .unrecognizedDomain - True if the domain is something other than a DNS domain or IP, otherwise undefined.
	 * 
	 * Unfolds whitespace and removes comments.
	 * Obsolete syntax is not supported.
	 * See RFC 5322 http://tools.ietf.org/html/rfc5322
	 *   and RFC 5321 http://tools.ietf.org/html/rfc5321#section-4.1.3
	 *   and RFC 6532 https://tools.ietf.org/html/rfc6532#section-3.2
	 *   and RFC 6854 https://tools.ietf.org/html/rfc6854
	 *   and http://www.addedbytes.com/lab/email-address-validation
	 *   and http://email.about.com/od/emailbehindthescenes/f/email_case_sens.htm
	 */
	function parseEmailAddress(address){
		
		if(!address) return null;
		
		//renaming the variable to avoid confusion with the specs (this function does not parse groups)
		let mailbox = address;
		address = void 0;
		
		if(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(mailbox)) return null;	//invalid characters
		if(/\n[\t ]*(\r?\n|$)|\n[^\t ]/.test(mailbox)) return null;	//invalid FWS
		
		//removes comments & newlines from CFWS at beginning of str
		//returns an array with the leading whitespace and the remaining text
		function trimCFWS(str){
			
			let wsp = "", m, commentLevel = 0;
			
			while(m = /^([\t ]*(?:\r?\n[\t ]+)?)\(/.exec(str)){
				
				wsp += m[1].replace(/\r?\n/g, "");	//save unfolded whitespace
				str = str.slice(m[1].length);
				
				//remove comment
				while(m = /[()\\]/.exec(str)){
					
					if(m[0] === "("){	//beginning of comment
						commentLevel++;
						str = str.slice(m.index+1);
					}
					else if(m[0] === ")"){	//end of comment
						commentLevel--;
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
				
				if(commentLevel){	//no closing parenthesis
					return null;
				}
				
			}
			
			m = /^[\t ]*(?:\r?\n[\t ]+)?/.exec(str);
			wsp += m[0].replace(/\r?\n/g, "");	//save unfolded whitespace
			str = str.slice(m[0].length);
			
			return [wsp, str];
			
		}
		
		//removes newlines from FWS in str
		//returns a string with the remaining whitespace and text
		function stripFWS(str){
			return str.replace(/\r?\n([\t ]+)/g, "$1");
		}
		
		let rxp_wsp = "[\\t ]",
			rxp_fws = "(?:(?:"+rxp_wsp+"*\\r?\\n)?"+rxp_wsp+"+)",
			rxp_atext = "[^\\r\\n\\t \"(),.:;<>@\\[\\\\\\]]",
			rxp_qtext = "[^\\r\\n\\t \"\\\\]",
			rxp_quotedPair = "\\\\[^\\r\\n]",
			rxp_qcontent = "(?:"+rxp_qtext+"|"+rxp_quotedPair+")",
			
			//these may be surrounded by CFWS
			rxpAtom = "(?:"+rxp_atext+"+)",
			//rxpDotAtom = "(?:"+rxp_atext+"+(?:\\."+rxp_atext+"+)*)",
			rxpDotAtom = "(?:"+rxp_atext+"+(?:\\."+rxp_atext+"+)+)",
			rxpQuotedString = "(?:\"(?:"+rxp_fws+"?"+rxp_qcontent+")*"+rxp_fws+"?\")";
			
			//local-part = dot-atom / quoted-string
			//domain = dot-atom / domain-literal
			//addr-spec = local-part "@" domain   //no CFWS allowed around the "@"
			//display-name = 1*( atom / quoted-string )
			//name-addr = [display-name] [CFWS] "<" addr-spec ">" [CFWS]
			//mailbox = name-addr / addr-spec
		
		function newRxp(rxp){ return new RegExp("^"+rxp, "i"); }
		
		let tokens = [];
		
		{
			
			let token,
				trimmed,
				m;
			
			while(mailbox.length){
				
				trimmed = trimCFWS(mailbox);
				if(trimmed[0].length){
					mailbox = trimmed[1];
					token = { type:"wsp", value:trimmed[0] };
					tokens.push(token);
					if(!mailbox.length) break;
				}
				
				token = {};
				if(m = /^[<@>]/.exec(mailbox)){
					token.type = "delimiter";
					mailbox = mailbox.slice(1);
					token.value = m[0];
					tokens.push(token);
				}
				else if(m = newRxp(rxpQuotedString).exec(mailbox)){
					token.type = "quoted-string";
					mailbox = mailbox.slice(m[0].length);
					trimmed = stripFWS(m[0]);
					token.value = trimmed;
					tokens.push(token);
				}
				else if(m = newRxp(rxpDotAtom).exec(mailbox)){
					token.type = "dot-atom";
					mailbox = mailbox.slice(m[0].length);
					token.value = m[0];
					tokens.push(token);
				}
				else if(m = newRxp(rxpAtom).exec(mailbox)){
					token.type = "atom";
					mailbox = mailbox.slice(m[0].length);
					token.value = m[0];
					tokens.push(token);
				}
				else if( (m = /^[a-z0-9:\[\].-]+/i.exec(mailbox)) && (trimmed = normalizeDNSHost(m[0])) ){
					token.type = "domain";
					mailbox = mailbox.slice(m[0].length);
					token.value = trimmed.host;
					tokens.push(token);
				}
				else{
					return null;
				}
				
			}
			
		}
		
		let parts = {};
		
		{
			
			let foundDisplayName = false,
				foundNoDisplayName = false,
				foundAngleBracket = false,
				foundNoAngleBracket = false,
				foundLocalPart = false,
				foundAtSign = false,
				foundDomain = false,
				foundClosingAngleBracket = false,
				i = 0;
			
			while(true){
				
				if(i === tokens.length){
					if(foundDomain && (foundNoAngleBracket || foundClosingAngleBracket)){
						break;
					}
					else{
						return null;
					}
				}
				else if(tokens[i].type === "wsp"){
					if(i === 0 || i === tokens.length-1){
						tokens.splice(i, 1);
					}
					else if((foundLocalPart && !foundAtSign) || (foundAtSign && !foundDomain)){
						return null;	//WSP around "@"
					}
					else{
						tokens[i].value = " ";
						i++;
					}
				}
				else if(!foundDisplayName && !foundNoDisplayName){
					if(tokens[i].type === "quoted-string"){
						tokens[i].value = "\"" + tokens[i].value.slice(1,-1).replace(/[\t ]+/g, " ") + "\"";
						i++;
					}
					else if(tokens[i].type === "atom"){
						i++;
					}
					else if(i === 1 && tokens[i].value === "@"){	//first token was the local part
						foundNoDisplayName = true;
						foundNoAngleBracket = true;
						foundLocalPart = true;
						foundAtSign = true;
						i++;
					}
					else if(i > 0){
						foundDisplayName = true;
					}
					else{
						foundNoDisplayName = true;
					}
				}
				else if(!foundAngleBracket && !foundNoAngleBracket){
					if(tokens[i].value === "<"){
						foundAngleBracket = true;
						i++;
					}
					else if(foundDisplayName){
						return null;
					}
					else{
						foundNoAngleBracket = true;
					}
				}
				else if(!foundLocalPart){
					if(tokens[i].type === "atom" || tokens[i].type === "dot-atom" || tokens[i].type === "quoted-string"){
						foundLocalPart = true;
						i++;
					}
					else{
						return null;
					}
				}
				else if(!foundAtSign){
					if(tokens[i].value === "@"){
						foundAtSign = true;
						i++;
					}
					else{
						return null;
					}
				}
				else if(!foundDomain){
					if(tokens[i].type === "domain"){
						foundDomain = true;
						i++;
					}
					else if( (tokens[i].type === "atom" || tokens[i].type === "dot-atom") && (tokens[i].value = normalizeDNSHost(tokens[i].value)) ){
						tokens[i].value = tokens[i].value.host;
						foundDomain = true;
						i++;
					}
					else{
						return null;
					}
				}
				else if(foundAngleBracket && !foundClosingAngleBracket){
					if(tokens[i].value === ">"){
						foundClosingAngleBracket = true;
						i++
					}
					else{
						return null;
					}
				}
				else{
				//there are characters remaining after the mailbox
					return null;
				}
				
			}
			
			parts.displayName = ""
			if(foundDisplayName){
				let rxp = newRxp(rxpAtom+"(?: "+rxpAtom+")*$");
				while(tokens[0].value !== "<"){
					
					if(tokens[0].type === "quoted-string"){
						let innerText = tokens[0].value.slice(1,-1).replace(/[\t ]+/g, " ");
						if(rxp.test(innerText)){	//inner text of the quoted-string is a sequence of atoms separated by spaces
							//convert the quoted-string to a sequence of atom and WSP tokens
							tokens.splice(0, 1);
							let rxp = new RegExp(rxpAtom, "ig"),
								m, i=0;
							while(m = rxp.exec(innerText)){
								tokens.splice(i, 0, { type:"atom", value:m[0] }, { type:"wsp", value:" " });
								i += 2;
							}
							i--;
							tokens.splice(i, 1);	//remove the last WSP token
						}
					}
					
					parts.displayName += tokens[0].value;
					tokens.shift();
					
				}
				parts.displayName = parts.displayName.trim();
			}
			
			if(foundAngleBracket){
				tokens.shift();
			}
			if(tokens[0].type === "wsp"){
				tokens.shift();
			}
			if(tokens[0].type === "quoted-string"){	//local part is a quoted-string
				if(newRxp(rxpDotAtom+"$").test(tokens[0].value.slice(1,-1))){	//inner text of the quoted-string is a dot-atom
					tokens[0].value = tokens[0].value.slice(1,-1);	//remove the quotes
					//tokens[0].type = "dot-atom";
				}
			}
			parts.localPart = tokens[0].value;
			tokens.shift();
			
			tokens.shift();	//the "@"
			
			parts.domain = tokens[0].value;
			
			//ignore any remaining characters
			
			parts.simple = parts.localPart+"@"+parts.domain;
			
			parts.full = foundDisplayName ? parts.displayName+" <"+parts.simple+">" : parts.simple;
			
		}
		
		return parts;
		
	};
	
	//****************************************************************
	//*************************** Fixes ******************************
	//****************************************************************
	
	//attempts to fix a URI (if needed) and normalizes it
	// allowedSchemes	a string or array of strings listing accepted schemes; if not specified, any scheme is allowed
	// domain			host name (and optionally port) to use if an http/https URI is relative; current page's domain and port by default
	//if the string does not have a scheme, it will be assumed that it's meant to be that of the current page (e.g., if str is a relative URL)
	//returns null if it can't be fixed
	function fixHyperlink(str, allowedSchemes, domain){
		
		let port = "";
		
		if(domain === void 0 && window && window.location && window.location.host){
			domain = window.location.host;
		}
		else{
			domain = normalizeDNSHost(domain.replace(/^([^:]*)((?::\d+)?)$/, function (match, p1, p2){
				port = p2;
				return p1;
			}));
		}
		
		if(allowedSchemes && allowedSchemes instanceof Array){	//allowedSchemes is an array
			for(let i=0; i<allowedSchemes.length; i++){
				if(!(/^[a-z][a-z0-9+.-]*$/i).test(allowedSchemes[i])){	//invalid scheme
					allowedSchemes.splice(i,1);	//remove it from the array
				}
			}
			if(!allowedSchemes.length){
				return null;	//no valid schemes
			}
		}
		else if(allowedSchemes){	//allowedSchemes is a single scheme
			if(!(/^[a-z][a-z0-9+.-]*$/i).test(allowedSchemes)) return null;	//invalid scheme
			allowedSchemes = [allowedSchemes];	//use it as the only allowed scheme
		}
		
		//get scheme
		let scheme = (/^([a-z][a-z0-9+.-]*):/i).exec(str);
		if(scheme){
			scheme = scheme[1].toLowerCase();
			str = str.slice(scheme.length+1);
		}
		else{	//the string does not include a valid scheme
			if(window && window.location && window.location.protocol){
				scheme = window.location.protocol.slice(0,-1);	//assume it's meant to be that of the current page
			}
			else{
				return null;	//unknown scheme
			}
		}
		if(allowedSchemes && allowedSchemes.indexOf(scheme) < 0){	//scheme is not allowed
			return null;
		}
		
		//percent-encode illegal characters
		str = str.replace(/(?:[^a-z0-9-._~!$&'()*+,;=:@\/\[\]%?#]|%(?![0-9A-F]{2}))+/ig, function (match){
				return encodeURIComponent(match);
			});
		let i = str.search(/\?/);	//index of first question mark
		let j = str.search(/#/);	//index of first number sign
		if(j >= 0 && j < i){	//no query; only a fragment
			str = str.slice(0,j+1) + str.slice(j+1).replace(/#/g, "%23");	//percent-encode illegal number signs
		}
		else if(i >= 0){	//query
			let tmp = j >= 0 ? str.slice(j) : "";
			str = str.slice(0,i+1) + str.slice(i+1,j).replace(/\?/g, "%3F");	//percent-encode illegal question marks
			if(tmp){	//fragment
				str = str + "#" + tmp.slice(1).replace(/#/g, "%23");	//percent-encode illegal number signs
			}
		}
		
		//fix & normalize
		let lnk;
		if(scheme === "http" || scheme === "https"){
			if(!(new RegExp("^"+scheme+"://", "i")).test(str)){
				str = str.replace(/\[/g, "%5B").replace(/\]/g, "%5D");
				if(str.substring(0,2) === "//"){ 	//relative to the scheme
					lnk = parseHttp(scheme+"://"+str);
				}
				else if(str[0] === "/" && domain){ 	//path (relative to root)
					lnk = parseHttp(scheme+"://"+domain+port+str);
				}
				else if(domain){
					lnk = parseHttp(scheme+"://"+domain+port+"/"+str);
				}
				else{
					return null;	//invalid domain
				}
			}
			else{
				lnk = parseHttp(str);
				if(!lnk){
					lnk = parseHttp(str.replace(/\[/g, "%5B").replace(/\]/g, "%5D"));
					str = str.substring(scheme.length+3).replace(/^([^/]*)(?:$|(\/.*))/, function (match, p1, p2){
						return p1 + p2.replace(/\[/g, "%5B").replace(/\]/g, "%5D");
					});
					lnk = parseHttp(scheme+"://"+str);
				}
			}
		}
		else if(scheme === "mailto"){
			lnk = parseMailto(str.replace(/\//g, "%2F"));
		}
		else{
			lnk = parseURI(str.replace(/\[/g,"%5B").replace(/\]/g,"%5D"));
		}
		
		if(!lnk) return null;	//can't be fixed
		return lnk.uri;	//fixed & normalized
	};
	
	this.ParseURI = ParseURI;
	this.ParseURI.fixHyperlink = fixHyperlink;
	this.ParseURI.domain = normalizeDNSHost;
	this.ParseURI.emailAddress = parseEmailAddress;
	
}).call(this);
