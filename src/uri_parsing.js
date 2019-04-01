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
			rturn null;	//contains invalid characters
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
				else if(commentLevel === 0){
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
			return encodeURI(str).replace(/[\/?&=#]/g function (match){ return "%"+match.charCodeAt(0).toString(16).toUpperCase(); });
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
	 *   and http://www.addedbytes.com/lab/email-address-validation
	 *   and http://email.about.com/od/emailbehindthescenes/f/email_case_sens.htm
	 */
	function parseEmailAddress(address){
		
		let m;
		
		//remove CFWS from beginning of str (actually just removes comments; surrounding whitespace is preserved)
		function removeComments(str){
			
			let wsp = "", m, inQuote = false, commentLevel = 0;
			
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
		
		let mailbox = address;
		if(!mailbox) return null;
		
		mailbox = mailbox.replace(/\n([\t ])/g, "$1");	//unfold whitespace
		
		if((/[^a-z0-9!#$%&'*+-\/=?\^_`{|}~\t ()<>\[\]:;@,."\\]/i).test(address)) return null;	//contains invalid characters
		
		//remove comments from mailbox (comments can nest, so they have to be stripped manually)
		
		let ret = removeComments(mailbox);
		if(!ret) return null;
		let result = ret[0];
		mailbox = ret[1];
		
		let nameAddr;
		if(mailbox[0] === "<"){
			nameAddr = true;	//angle brackets are used
			ret = removeComments(mailbox.slice(1));
			if(!ret) return null;
			result += "<"+ret[0];
			mailbox = ret[1];
		}
		
		let rxp_atext = "a-z0-9!#$%&'*+-\\/=?\\^_`{|}~",
			rxp_atom = "[" + rxp_atext + "]+",
			rxp_dotAtom = rxp_atom + "(?:\\." + rxp_atom + ")*",
			rxp_qtext = rxp_atext + "\\t ()<>\\[\\]:;@,.",
			rxp_quotedPair = "\\\\[" + rxp_qtext + "\"\\\\]",
			rxp_qcontent = "(?:[" + rxp_qtext + "]|" + rxp_quotedPair + ")",
			rxp_dtext = rxp_atext + "\\t ()<>:;@,.\"",
			rxp_domainLiteral = "\\[[" + rxp_dtext + "]*\\]",
			
			rxpAtomStart = new RegExp("^" + rxp_atom, "i"),
			rxpDotAtomStart = new RegExp("^" + rxp_dotAtom, "i"),
			rxpQuotedStringStart = new RegExp("^\"" + rxp_qcontent + "*", "i"),
			rxpDomainLiteralStart = new RegExp("^" + rxp_domainLiteral, "i"),
			
			rxpDotAtom = new RegExp("^" + rxp_dotAtom + "$", "i"),
			rxpDisplayName = new RegExp("^(?:" + rxp_atom + "|\"" + rxp_qcontent + "*\")+$", "i"),
			
			text, wsp;
		
		//get the first block of text
		if(m = rxpDotAtomStart.exec(mailbox)){
			text = m[0];
			mailbox = mailbox.slice(m[0].length);
		}
		else if(m = rxpQuotedStringStart.exec(mailbox)){
			text = m[0];
			mailbox = mailbox.slice(m[0].length);
		}
		else{
			return null;	//invalid mailbox
		}
		
		ret = removeComments(mailbox);
		if(!ret) return null;
		wsp = ret[0]
		mailbox = ret[1];
		
		
		//At this point:
		//text = local-part text   OR   display-name text
		//wsp = WSP after the text
		
		
		let parts = {};
			
		if(mailbox[0] === "<"){	//`text` was the display name
			if(nameAddr) return null;	//invalid mailbox; extra "<"
			if(!rxpDisplayName.test(text)) return null;	//invalid display name
			nameAddr = true;	//angle brackets are used
			
			//add the display name to the result
			ret = removeComments(mailbox.slice(1));
			if(!ret) return null;
			result += text+wsp+"<"+ret[0];
			mailbox = ret[1];
			
			parts.display = text;
			
			//get the local part
			if(m = rxpAtomStart.exec(mailbox)){
				text = m[0];
				mailbox = mailbox.slice(m[0].length);
			}
			else if(m = rxpQuotedStringStart.exec(mailbox)){
				text = m[0];
				mailbox = mailbox.slice(m[0].length);
			}
			else{
				return null;	//invalid mailbox
			}
			
			ret = removeComments(mailbox);
			if(!ret) return null;
			wsp = ret[0];
			mailbox = ret[1];
		}
		else{
			parts.display = "";
		}
		
		
		//At this point:
		//text = local-part text
		//wsp = WSP after the text
		
		
		//add the local part to the result
		result += text+wsp;
		
		parts.local = text;
		
		
		//At this point, `result` is one of these:
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
		if(m = rxpDotAtomStart.exec(mailbox)){
			result += m[0];
			mailbox = mailbox.slice(m[0].length);
			
			parts.domain = m[0];
		}
		else if(m = rxpDomainLiteralStart.exec(mailbox)){
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
		
		if(mailbox !== "") return null;	//invalid mailbox
		
		
		//At this point, `result` is one of these:
		//	local-part "@" domain
		//	"<" local-part "@" domain ">"
		//	display-name "<" local-part "@" domain ">"
		
		
		//normalize the display name
		parts.display = parts.display.replace(/\s+/, " ");	//replace blocks of whitespace with a single space
		if(parts.display[0] === "\""){
			parts.display = parts.display.slice(1,-1).trim();	//remove the outer quotes
		}
		
		//normalize the local part
		if(parts.local[0] === "\"" && rxpDotAtom.test(parts.local.slice(1,-1))){
			parts.local = parts.local.slice(1,-1);	//remove quotes if they aren't required
		}
		
		//normalize the domain
		if((/^\[IPv6:/i).test(parts.domain)){	//it's an IPv6 address literal
			if(text = normalizeIPv6(parts.domain.slice(6, -1))){
				parts.domain = "[IPv6:"+text+"]";
			}
			else{
				return null;	//invalid IPv6
			}
		}
		else if(parts.domain[0] === "[" && (text = normalizeIPv4(parts.domain.slice(1,-1)))){	//it's an IPv4 address literal
			parts.domain = text;
		}
		else if(parts.domain[0] !== "[" && (text = normalizeDNSHost(parts.domain).host)){	//it's a domain or an IPv4 address
			parts.domain = text;
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
