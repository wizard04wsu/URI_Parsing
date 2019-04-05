/**
 * ParseURI(uri)
 * ParseURI.domain(host)
 * ParseURI.query(queryString)
 * ParseURI.emailAddress(address)
 * ParseURI.fixHyperlink(href)
 * 
 * This script does not support:
 *   - internationalized domain names (IDNs)
 *   - non-ASCII email addresses (see RFC 6530)
 *   - IPvFuture literal address formats
 *   - obsolete syntaxes
 * 
 * General references:
 *   RFC 3986 "Uniform Resource Identifier (URI): Generic Syntax"   https://tools.ietf.org/html/rfc3986
 *   How to Obscure Any URL   http://www.pc-help.org/obscure.htm
 *   RFC 6068 "The 'mailto' URI Scheme"	  https://tools.ietf.org/html/rfc6068
 *   Wikipedia: Email address   https://en.wikipedia.org/wiki/Email_address
 *   RFC 5322 "Internet Message Format"   https://tools.ietf.org/html/rfc5322
 *   RFC 5321 "Simple Mail Transfer Protocol"   https://tools.ietf.org/html/rfc5321#section-4.1.2
 *   RFC 5234 "Augmented BNF for Syntax Specifications: ABNF"   https://tools.ietf.org/html/rfc5234#appendix-B.1
 */


(function(){
	
	"use strict";
	
	let normalizeFragment = normalizeQuery;
	
	function defineProperty(object, propertyName, value, isWritable, isEnumerable, isConfigurable){
		Object.defineProperty(object, propertyName, { value:value, writable:isWritable, enumerable:isEnumerable, configurable:isConfigurable });
	}
	
	/**
	 * Validates and normalizes a URI, and splits it into its parts.
	 * 
	 * ParseURI(uri)
	 * 
	 * @param {string} uri
	 * @return {object} - Object containing the URI and its parts. Null if the URI is invalid. The members depend on if the scheme is http, https, mailto, or something else. Possible members:
	 *   {string} .uri - The normalized URI.
	 *   {string} .scheme
	 *   {string} .authority - For non-http/https/mailto URIs. Empty string if there isn't an authority.
	 *   {object} .authority - For http or https URIs. Coerces to a string of the entire authority.
	 *     {string} .authority.userinfo
	 *     {string} .authority.host - Coerces to a string.
	 *       {array} .authority.host.labels - Array of labels within a domain name. Undefined if it's an IP.
	 *       {string} .authority.host.ip - IP address (IPv4 if possible).
	 *       {string} .authority.host.ipv4 - IPv4 version of the IP.
	 *       {string} .authority.host.ipv6 - IPv6 version of the IP.
	 *     {string} .authority.port
	 *   {string} .path - For non-mailto URIs.
	 *   {array} .query - For non-mailto URIs. An array of decoded name/value pairs (each pair is an object {name, value}). Coerces to a string of the entire query.
	 *   {string} .fragment - For non-mailto URIs.
	 *   {array} .to - For mailto URIs. Array of valid email addresses.
	 *   {array} .cc - For mailto URIs. Array of valid email addresses.
	 *   {array} .bcc - For mailto URIs. Array of valid email addresses.
	 *   {string} .subject - For mailto URIs.
	 *   {string} .body - For mailto URIs.
	 *   {array} .headers - For mailto URIs. An array of additional email headers (each header is an object {name, value}).
	 * 
	 * See: RFC 3986   https://tools.ietf.org/html/rfc3986
	 */
	function ParseURI(uri){
		
		uri = ""+uri;
		
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
		
		/*Characters:
			unreserved: [A-Za-z0-9-._~]
			reserved: gen-delims / sub-delims
			gen-delims: [:\/?#\[\]@]
			sub-delims: [!$&'()*+,;=]
			pct-encoded: %[0-9A-Fa-f]{2}
		*/
		
		let parts = rxp.exec(uri);
		if(!parts) return null;	//invalid URI
		
		let scheme = parts[1].toLowerCase(),
			authority = parts[2],
			userinfo = parts[4],
			host = parts[5],
			port = parts[6],
			path = normalizePath(parts[7] || parts[9]),
			query = normalizeQuery(parts[11]),
			fragment = normalizeFragment(parts[12]);
		
		if(authority){
			if((host = normalizeHost(host)) === null) return null;	//invalid host
			authority = (userinfo ? userinfo+"@" : "") + host + (port ? ":"+port : "");	//normalize authority
		}
		
		uri = scheme+":" + (authority !== (void 0) ? "//"+authority : "") + path + (query ? "?"+query : "") + (fragment ? "#"+fragment : "");
		
		if((/^https?$/).test(scheme)){	//it's a URL (http or https)
			
			if(!host) return null;
			host = normalizeDNSHost(host);
			if(!host) return null;
			
			port = port || (scheme === "http" ? "80" : "443");
			authority = (userinfo ? userinfo+"@" : "") + host.host + ((scheme==="http" && port==="80") || (scheme==="https" && port==="443") ? "" : ":"+port);
			path = path || "/";
			let queryObj = parseQuery(query);
			
			uri = scheme+"://"+authority + path + (query ? "?"+queryObj : "") + (fragment ? "#"+fragment : "");
			
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
					query: parseQuery(query)
				});
			
		}
		else{
			
			return {
				uri: uri,
				scheme: scheme,
				authority: authority,
				path: path,
				query: query,
				fragment: fragment
			};
			
		}
		
	};
	
	/**
	 * Converts an obscured host to a more readable one.
	 * 
	 * @param {string} host
	 * @return {string} - The normalized host. Null if the host is invalid.
	 * 
	 * See: How to Obscure Any URL   http://www.pc-help.org/obscure.htm
	 *      RFC 3986   https://tools.ietf.org/html/rfc3986#section-3.2.2
	 *                 https://tools.ietf.org/html/rfc3986#section-2
	 */
	function normalizeHost(host){
		
		if(host === "") return "";
		if(host === void 0) return null;
		host = ""+host;
		
		let ip;
		
		if((/^\[.*\]$/i).test(host) && (ip = normalizeIPv6(host.slice(1, -1))) ) return "["+ip+"]";	//it's a valid IPv6 address
		
		if(!(/^(?:[0-9a-z!$&'()*+,\-.;=_~]|%[0-9A-F]{2})*$/i).test(host)) return null;	//contains invalid characters
		
		//decode percent encodings of unreserved characters: DIGIT ALPHA -._~
		host = host.replace(/%(2[DE]|3\d|[46][1-9A-F]|[57][0-9A]|5F|7E)/ig, function (match, p1){ return String.fromCharCode(parseInt(p1, 16)); });
		
		if( (ip = normalizeIPv4(host)) ) return ip;	//it's a valid IPv4 address
		
		//make percent encodings upper case; everything else lower case
		host = host.toLowerCase();
		host = host.replace(/%(..)/ig, function (match, p1){ return "%"+p1.toUpperCase(); });
		
		return host;
		
	};
	
	/**
	 * Converts an obscured host to a more readable one. Only DNS domains or IPs are deemed valid.
	 * 
	 * ParseURI.domain(host)
	 * 
	 * @param {string} host
	 * @return {object} - Object containing the host and its parts. Null if the host is invalid. Possible members:
	 *   {string} .host - The normalized domain name or IP.
	 *   {string} .ip
	 *   {string} .ipv4
	 *   {string} .ipv6
	 *   {array} .labels - Array of the domain name's labels.
	 * 
	 * See: RFC 3986   https://tools.ietf.org/html/rfc3986#section-3.2.2
	 *      RFC 2181   https://tools.ietf.org/html/rfc2181#section-11
	 *      RFC 1123   https://tools.ietf.org/html/rfc1123#section-2
	 */
	function normalizeDNSHost(host){
		
		host = normalizeHost(host);
		if(!host) return null;
		
		if((/[^a-z0-9:\[\].-]/i).test(host)) return null;	//contains invalid characters
		
		if(/^\d+(\.\d+){3}$/.test(host)){	//it's an IPv4 address
			return { host:host, ip:host, ipv4:host, ipv6:"::ffff:"+host /*ipv6:"::ffff:"+v4to6(host)*/ };
		}
		if(host[0] === "["){	//it's an IPv6 address
			let ipv6 = host.slice(1, -1),
				ipv4 = v6to4(ip);
			return { host:(ipv4||host), ip:(ipv4||ipv6), ipv4:ipv4, ipv6:ipv6 };
		}
		
		if(host.length > 255) return null;	//too long for a domain name
		
		if((/^(?=([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))\1(?:\.(?=([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))\2)*$/i).test(host)){	//it's a domain name
			return { host:host, labels:host.split(".") };
		}
		
		return null;	//invalid
		
	};
	
	/**
	 * Converts the four 8-bit decimal values of a normalized IPv4 address to the two low-order 16-bit hexadecimal values of an IPv6 address.
	 * 
	 * @param {string} ip - Normalized IPv4 address.
	 * @return {string} - Two 16-bit hexadecimal values representing the IPv4 portion of an IPv6 address.
	 * 
	 * See: RFC 4291   https://tools.ietf.org/html/rfc4291#section-2.5.5
	 */
	function v4to6(ip){
		ip = ip.split(".");
		return ((ip[0]*256 + ip[1]*1).toString(16) + ":" + (ip[2]*256 + ip[3]*1).toString(16)).toLowerCase();
	}
	
	/**
	 * Converts a normalized IPv6 address to the four 8-bit decimal values of an IPv4 address, if possible.
	 * 
	 * @param {string} ip - Normalized IPv6 address.
	 * @return {string} - IPv4 address. Undefined if it can't be converted.
	 * 
	 * See: RFC 4291   https://tools.ietf.org/html/rfc4291#section-2.5.5
	 */
	function v6to4(ip){
		if(!/^::ffff:[0-9A-F]+:[0-9A-F]+$/i.test(ip)) return void 0;	//can't be converted to IPv4
		function hexToDec(hexField){
			let h = 1*("0x"+hexField),
				b = h%256,
				a = (h-b)/256;
			return a+"."+b;
		}
		ip = /^::ffff:(.+):(.+)$/i.exec(ip);
		return hexToDec(ip[1]) + "." + hexToDec(ip[2]);
	}
	
	/**
	 * Normalizes an IPv6 address.
	 * 
	 * @param {string} ip - IPv6 address.
	 * @param {boolean} [useMixedNotation] - Mix hexadecimal and dotted-decimal notations to represent an IPv4-mapped IPv6 address. Default is true (recommended per RFC 5952, section 5).
	 * @return {string} - Normalized IPv6 address. Null if it's invalid.
	 * 
	 * See: How to Obscure Any URL   http://www.pc-help.org/obscure.htm
	 *      Wikipedia: IPv4, Address representations   http://en.wikipedia.org/wiki/IPv4#Address_representations
	 */
	function normalizeIPv4(ip){
		
		if(ip === void 0) return null;
		ip = ""+ip;
		
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
			
			//if this is the last part and it's a dword (unsigned 32-bit integer)
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
	
	/**
	 * Normalizes an IPv6 address.
	 * 
	 * @param {string} ip - IPv6 address.
	 * @param {boolean} useMixedNotation - Mix hexadecimal and dot-decimal notations to represent IPv4-mapped IPv6 addresses. Default is true (recommended per RFC 5952, section 5).
	 * @return {string} - Normalized IPv6 address. Null if it's invalid.
	 * 
	 * See: RFC 4291   https://tools.ietf.org/html/rfc4291
	 *      RFC 5952   https://tools.ietf.org/html/rfc5952#section-4
	 *                 https://tools.ietf.org/html/rfc5952#section-5
	 */
	function normalizeIPv6(ip, useMixedNotation){
		
		if(ip === void 0) return null;
		ip = ""+ip;
		if(useMixedNotation === void 0) useMixedNotation = true;	//default is true
		
		if(!(/^[0-9A-F:.]{2,}$/i).test(ip)) return null;	//invalid IP address
		
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
					if(useMixedNotation && /^(0+:){5}(0+|ffff)$/.test(resultLeft.join(":"))){	//well-known prefix that distinguishes an embedded IPv4
						includesIPv4 = true;
						resultLeft.push(normalizeIPv4(fieldsLeft[i]));
					}
					else{	//no recognized prefix for IPv4, or don't use mixed notation; convert it to IPv6
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
						if(useMixedNotation && ( ( /^((0+:)*0+)?$/.test(resultLeft.join(":")) && /^((0+:)*(0+|ffff))?$/.test(resultRight.join(":")) ) ||
						 /^(0+:){5}(0+|ffff)$/.test(resultLeft.join(":")) )){	//well-known prefix that distinguishes an embedded IPv4
							includesIPv4 = true;
							resultRight.push(normalizeIPv4(fieldsRight[i]));
						}
						else{	//no recognized prefix for IPv4, or don't use mixed notation; convert it to IPv6
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
		
		let v4;
		if(useMixedNotation && !includesIPv4 && (v4 = v6to4(ip))){
			//This is a hexadecimal representation of an IPv4 address. Convert the low-order 32 bits to mixed notation.
			ip = "::ffff:"+v4;
		}
		
		return ip;
		
	};
	
	/**
	 * Converts and obscured path to a more readable one.
	 * 
	 * @param {string} path
	 * @return {string}
	 * 
	 * See: RFC 3986   https://tools.ietf.org/html/rfc3986#section-3.3
	 *                 https://tools.ietf.org/html/rfc3986#section-2.4
	 */
	function normalizePath(path){
		
		if(path === "") return "";
		if(path === void 0) return "";
		path = ""+path;
		
		//decode percent encodings of unreserved characters: DIGIT ALPHA -._~
		path = path.replace(/%(2[DE]|3\d|[46][1-9A-F]|[57][0-9A]|5F|7E)/ig, function (match, p1){ return String.fromCharCode(parseInt(p1, 16)); });
		
		//make percent encodings upper case
		path = path.replace(/%(..)/ig, function (match, p1){ return "%"+p1.toUpperCase(); });
		
		return path;
		
	};
	
	/**
	 * Converts and obscured query string to a more readable one.
	 * 
	 * @param {string} queryString
	 * @return {string}
	 * 
	 * See: RFC 3986   https://tools.ietf.org/html/rfc3986#section-3.4
	 *                 https://tools.ietf.org/html/rfc3986#section-2.4
	 */
	function normalizeQuery(queryString){
		
		if(queryString === void 0) return "";
		queryString = ""+queryString;
		
		//decode percent encodings of unreserved characters: DIGIT ALPHA -._~
		return queryString.replace(/%(2[DE]|3\d|[46][1-9A-F]|[57][0-9A]|5F|7E)/ig, function (match, p1){ return String.fromCharCode(parseInt(p1, 16)); });
		
	}
	
	/**
	 * Parses a query string as a sequence of name/value pairs.
	 * 
	 * ParseURI.query(queryString)
	 * 
	 * @param {string} queryString
	 * @return {array} - Array of name/value pairs (each pair is an object {name, value}). Coerces to a string of the normalized query string.
	 * 
	 * See: RFC 3986   https://tools.ietf.org/html/rfc3986#section-3.4
	 */
	function parseQuery(queryString){
		
		if(queryString === "" || queryString === void 0) return [];
		queryString = ""+queryString;
		
		queryString = normalizeQuery(queryString);
		
		let pairs = queryString.split("&"),
			results = [],
			pair;
		for(let i=0; i<pairs.length; i++){
			pair = pairs[i].split("=");
			if(pair.length <= 1 || pair[0] === ""){	//there is no name or no "="; skip it
				pairs.splice(i--,1);
				continue;
			}
			results.push( { name: decodeURIComponent(pair.shift()), value: decodeURIComponent(pair[0]) } );	//add the name/value pair to the results
		}
		
		defineProperty(results, "toString", function (){ return queryString; }, true, false, true);
		
		return results;
		
	};
	
	/**
	 * Splits a mailto scheme URI into its parts.
	 * 
	 * @param {object} parts - Object containing the URI, scheme, path, and query object.
	 * @return {object} - Object containing the following. Null if the URI is invalid or there is no valid destination.
	 *   {string} uri - normalized URI
	 *   {string} scheme - "mailto"
	 *   {string} path
	 *   {array} to
	 *   {array} cc
	 *   {array} bcc
	 *   {string} subject - Multiple "subject" headers are combined.
	 *   {string} body - Multiple "body" headers are combined.
	 *   {array} headers - Array containing any additional headers (each header is an object {name, value}).
	 * 
	 * Invalid destinations are discarded.
	 * 
	 * See: RFC 6068   https://tools.ietf.org/html/rfc6068
	 */
	function parseMailto(parts){
		
		//splits the string at the commas (ignoring commas within quoted strings or comments)
		//returns an array of valid email addresses
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
		
		{
			
			parts.to = parts.path ? splitEmailAddresses(parts.path) : [];
			
			let headers = parts.query;
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
					parts.subject += decodeURIComponent(headers[i].value);
				else if(headers[i].name === "body")
					parts.body += decodeURIComponent(headers[i].value);
				else{
					headers[i].value = decodeURIComponent(headers[i].value);
					parts.headers.push(headers[i]);
				}
			}
			
			if(parts.to.length + parts.cc.length + parts.bcc.length === 0) return null;	//no destination
			
		}
		
		{
			
			parts.path = encodePart(parts.to.join(","));
			
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
			
			parts.uri = "mailto:" + parts.path + (query ? "?"+query : "");
			
			parts.query = parseQuery(query);
			
		}
		
		return parts;
		
	};
	
	/**
	 * Normalizes a single email address (mailbox) and splits it into its parts.
	 * 
	 * ParseURI.emailAddress(address)
	 * 
	 * @param {string} address - email address or mailbox (mailbox example: "John Doe" <john.doe@example.com> )
	 * @return {object} - Object containing the mailbox and its parts. Null if it's invalid.
	 *   {string} .full - If there is a display name: "display name" <local@domain>
	 *                    If there isn't: local@domain
	 *   {string} .simple - local@domain
	 *   {string} .displayName - display name
	 *   {string} .unescapedDisplayName - display name with any quoted strings unescaped (this is what you would show to a user)
	 *   {string} .localPart - Local part of the address.
	 *   {string} .domain - Domain part of the address. Only DNS domains or IPs are deemed valid.
	 * 
	 * Does not parse groups (e.g., a distribution list).
	 * Unfolds whitespace and removes comments.
	 * Does not consider the 998 character limit per line.
	 * See: RFC 5322   https://tools.ietf.org/html/rfc5322
	 *      RFC 5321   https://tools.ietf.org/html/rfc5321#section-4.1.2
	 *      Wikipedia: Email address   https://en.wikipedia.org/wiki/Email_address
	 */
	function parseEmailAddress(address){
		
		//renaming the variable to avoid confusion with the specs (this function does not parse groups)
		if(address === void 0) return null;
		let mailbox = ""+address;
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
		function stripFWS(str){ return str.replace(/\r?\n([\t ]+)/g, "$1"); }
		
		let rxp_wsp = "[\\t ]",
			rxp_fws = "(?:(?:"+rxp_wsp+"*\\r?\\n)?"+rxp_wsp+"+)",
			rxp_atext = "[!#$%&'*+\\-/0-9=?A-Z^_`a-z{|}~]",
			rxp_qtext = "[!#$%&'()*+,\\-./0-9:;<=>?@A-Z[\\]^_`a-z{|}~]",
			//rxp_quotedPair = "\\\\[\\t !\"#$%&'()*+,\\-./0-9:;<=>?@A-Z[\\\\\\]^_`a-z{|}~]",
			rxp_quotedPair = "\\\\[\\t !-~]",
			rxp_qcontent = "(?:"+rxp_qtext+"|"+rxp_quotedPair+")",
			
			//these may be surrounded by CFWS
			rxpAtom = "(?:"+rxp_atext+"+)",
			rxpDotAtom = "(?:"+rxp_atext+"+(?:\\."+rxp_atext+"+)*)",
			rxpQuotedString = "(?:\"(?:(?:"+rxp_fws+"?"+rxp_qcontent+"+)+"+rxp_fws+"?|"+rxp_fws+")\")";	//see https://www.rfc-editor.org/errata/eid3135
			
			/* local-part = dot-atom / quoted-string
			   domain = dot-atom / domain-literal
			   addr-spec = local-part "@" domain   //no CFWS allowed around the "@"
			   display-name = 1*( atom / quoted-string )
			   name-addr = [display-name] [CFWS] "<" addr-spec ">" [CFWS]
			   mailbox = name-addr / addr-spec
			*/
		
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
					if(newRxp(rxpAtom+"$").test(m[0])){
						token.type = "atom";
					}
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
			
			let rxp_redundantPairs = new RegExp("\\\\("+rxp_qtext+")", "ig");
			
			parts.displayName = "";
			parts.unescapedDisplayName = "";
			if(foundDisplayName){
				let rxp_atomSequence = newRxp(rxpAtom+"(?: "+rxpAtom+")*$");
				while(tokens[0].value !== "<"){
					
					if(tokens[0].type === "quoted-string"){
						let innerText = tokens[0].value.slice(1,-1).replace(rxp_redundantPairs, "$1").replace(/[\t ]+/g, " ");
						if(rxp_atomSequence.test(innerText)){	//inner text of the quoted-string is a sequence of atoms separated by spaces
							parts.displayName += innerText;
							parts.unescapedDisplayName += innerText;
						}
						else{
							parts.displayName += "\""+innerText+"\"";
							parts.unescapedDisplayName += innerText.replace(/\\(.)/g, "$1");
						}
					}
					else{
						parts.displayName += tokens[0].value;
						parts.unescapedDisplayName += tokens[0].value;
					}
					
					tokens.shift();
					
				}
				parts.displayName = parts.displayName.trim();
				parts.unescapedDisplayName = parts.unescapedDisplayName.replace(/ {2,}/g, " ").trim();
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
				}
				else{
					tokens[0].value = tokens[0].value.replace(rxp_redundantPairs, "$1");
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
	
	//attempts to fix a URI (if needed) and normalizes it
	// allowedSchemes	a string or array of strings listing accepted schemes; if not specified, any scheme is allowed
	// domain			host name (and optionally port) to use if an http/https URI is relative; current page's domain and port by default
	//if the string does not have a scheme, it will be assumed that it's meant to be that of the current page (e.g., if str is a relative URL)
	//https://tools.ietf.org/html/rfc3986#section-4.1
	//returns null if it can't be fixed
	function fixHyperlink(href){
		
		let location = (window && window.location) ? window.location : {},
			hyperlink = href,
			parts = {},
			ret;
		
debugger;
		//get scheme
		let scheme = (/^([a-z][a-z0-9+.-]*):/i).exec(href);
		if(scheme){
			scheme = scheme[0].toLowerCase();
			href = href.slice(scheme.length);
		}
		else{
			scheme = location.protocol || "http:";
			if( (ret = ParseURI(scheme+href)) ) return ret.uri;
		}
		parts.scheme = scheme;
		
		if(/^https?:$/.test(scheme)){
			
			if(/^\/\//.test(href)){	//href is relative to the scheme, and should start with the authority
				
				href = href.slice(2);
				parts.userinfo = "";
				parts.host = "";
				parts.port = "";
				
				//get userinfo
				
				ret = /^([^@:\/\[]*)@/.exec(href);
				if(ret){	//userinfo
					parts.userinfo = ret[1];
					//percent-encode illegal characters
					parts.userinfo = parts.userinfo.replace(/(?:[^a-z0-9-._~!$&'()*+,;=:%]|%(?![0-9A-F]{2}))+/ig, function (match){ return encodeURIComponent(match); });
					href = href.slice(ret[0].length);
				}
				
				//get host
				
				ret = /^\[([a-f0-9:.\]]*)\]/i.exec(href);
				if(ret){	//possibly valid IPv6
					ret = normalizeIPv6(ret[1]).host;
					if(ret){	//valid IPv6
						parts.host = "["+ret+"]";
						href = href.slice(ret[0].length);
					}
					else{
						return null;
					}
				}
				else{
					ret = /^([^:\/]*)([:\/]|$)/.exec(href);
					if(ret){	//possible host
						parts.host = normalizeDNSHost(ret[1]).host;
						if(parts.host){	//valid host
							href = href.slice(ret[1].length);
						}
						else{
							return null;
						}
					}
					else{
						return null;
					}
				}
				
				//get port
				
				ret = /^:(\d*)(?=\/|$)/.exec(href);
				if(ret){	//port
					parts.port = ret[1];
					href = href.slice(ret[0].length);
				}
				else if(href[0] === ":"){
					return null;
				}
				
				ret = ParseURI(parts.scheme+"//" + (parts.userinfo?parts.userinfo+"@":"") + parts.host + (parts.port?":"+parts.port:"") + href);
				if(ret) return ret.uri;
				
				//get path
				
				//TODO
				
				//get query
				
				//TODO
				
				//get fragment
				
				//TODO
				
			}
			else if(href[0] === "/"){	//href is relative to the authority
				
				//TODO
				
			}
			else{	//href is relative to the page
				
				//TODO
				
			}
			
		}
		else if(scheme === "mailto:"){
			
			//TODO
			
		}
		else{
			
			//TODO
			
		}
		
		return "TODO";
		
	};
	
	this.ParseURI = ParseURI;
	this.ParseURI.domain = normalizeDNSHost;
	this.ParseURI.query = parseQuery;
	this.ParseURI.emailAddress = parseEmailAddress;
	this.ParseURI.fixHyperlink = fixHyperlink;
	
}).call(this);
