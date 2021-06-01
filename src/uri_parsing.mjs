/*
 * URI(uri)
 * URI.domain(host)
 * URI.resolveRelativePath(path, isPartial)
 * URI.query(queryString)
 * URI.emailAddress(address)
 * URI.fixHyperlink(href)
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
 *   RFC 6068 "The 'mailto' URI Scheme"   https://tools.ietf.org/html/rfc6068
 *   Wikipedia: Email address   https://en.wikipedia.org/wiki/Email_address
 *   RFC 5322 "Internet Message Format"   https://tools.ietf.org/html/rfc5322
 *   RFC 5321 "Simple Mail Transfer Protocol"   https://tools.ietf.org/html/rfc5321#section-4.1.2
 *   RFC 5234 "Augmented BNF for Syntax Specifications: ABNF"   https://tools.ietf.org/html/rfc5234#appendix-B.1
 */

// https://github.com/wizard04wsu/URI_Parsing

/** @module URI */

export { URI as default, fixHyperlink };


/**
 * Object containing a URI and its parts. The members vary depending on the scheme.
 * @typedef {object} ParsedURI
 * @property {string} original - Original URI.
 * @property {string} uri - Normalized URI.
 * @property {string} scheme
 * @property {ParsedURI_authority|undefined} authority
 * @property {string} path
 * @property {string|ParsedURI_query} query
 * @property {string} fragment
 */
/**
 * @typedef {String} ParsedURI_authority
 * @property {string} userinfo
 * @property {string|ParsedURI_host} host
 * @property {string} port
 */
/**
 * @typedef {String} ParsedURI_host
 * @property {Array.<string>|undefined} labels - Labels within a domain name. Undefined if it's an IP.
 * @property {string|undefined} ip - IP address (IPv4 if possible).
 * @property {string|undefined} ipv4 - IPv4 version of the IP.
 * @property {string|undefined} ipv6 - IPv6 version of the IP.
 */
/**
 * @typedef {String} ParsedURI_query
 * @property {Object.<string, string>} pairs - Array of decoded name/value pairs.
 */


/**
 * Creates an object containing the normalized URI and its parts. The members vary depending on the scheme. Null if the URI is invalid.
 * @alias module:URI
 * @param {string} uri
 * @returns {ParsedURI|null}
 */
function URI(uri){
	const parsed = parseURI(uri);
	
	if(parsed === null) return null;
	
	Object.defineProperty(parsed, "toString", {
		writable: true, enumerable: false, configurable: true,
		value: function toString(){ return this.uri; }
	});
	
	return parsed;
}

URI.normalizeHost = normalizeHost;
URI.normalizeDNSHost = normalizeDNSHost;
URI.normalizePath = removeDotSegments;
URI.parseQuery = parseQuery;
URI.parseEmailAddress = parseEmailAddress;


/**
 * Validates and normalizes a URI, and splits it into its parts.
 * @private
 * @param {string} uri
 * @returns {ParsedURI|null} - Object containing the URI and its parts. The members vary depending on the scheme. Null if the URI is invalid.
 * 
 *   {array} .to - For mailto URIs. Array of valid email addresses.
 *   {array} .cc - For mailto URIs. Array of valid email addresses.
 *   {array} .bcc - For mailto URIs. Array of valid email addresses.
 *   {string} .subject - For mailto URIs.
 *   {string} .body - For mailto URIs.
 *   {array} .headers - For mailto URIs. An array of additional email headers (each header is an object {name, value}).
 * 
 * See: RFC 3986   https://tools.ietf.org/html/rfc3986
 */
function parseURI(uri){
	
	if(uri === void 0 || uri === null || uri == "") return null;
	
	const original = uri = ""+uri;
	
	/*Characters:
		unreserved: [A-Za-z0-9-._~]
		reserved: gen-delims / sub-delims
		gen-delims: [:\/?#\[\]@]
		sub-delims: [!$&'()*+,;=]
		pct-encoded: %[0-9A-Fa-f]{2}
	*/
	
	//*** browsers still don't support named capture as of May 2021 ***
	
	//let rxp = /^(?=(?<scheme>[a-z][a-z\d+.-]*))\k<scheme>:(?:\/\/(?<authority>(?:(?=(?<userinfo>(?:[\w-.~!$&'()*+,;=:]|%[\dA-F]{2})*))\k<userinfo>@)?(?=(?<host>\[[\dA-F:.]{2,}\]|(?:[\w-.~!$&'()*+,;=]|%[\dA-F]{2})*))\k<host>(?::(?=(?<port>\d*))\k<port>)?)(?<path1>\/(?=(?<_path1>(?:[\w-.~!$&'()*+,;=:@/]|%[\dA-F]{2})*))\k<_path1>)?|(?<path2>\/?(?!\/)(?=(?<_path2>(?:[\w-.~!$&'()*+,;=:@/]|%[\dA-F]{2})*))\k<_path2>)?)(?:\?(?=(?<query>(?:[\w-.~!$&'()*+,;=:@/?]|%[\dA-F]{2})*))\k<query>)?(?:#(?=(?<fragment>(?:[\w-.~!$&'()*+,;=:@/?]|%[\dA-F]{2})*))\k<fragment>)?$/ui;
	
	/*Composed as follows:
		^
		(?=(?<scheme>[a-z][a-z\d+.-]*))\k<scheme>:													1 scheme
		(?:
			\/\/
			(?<authority>
				(?:
					(?=(?<userinfo>(?:[\w-.~!$&'()*+,;=:]|%[\dA-F]{2})*))\k<userinfo>				3 userinfo
					@
				)?
				(?=(?<host>\[[\dA-F:.]{2,}\]|(?:[\w-.~!$&'()*+,;=]|%[\dA-F]{2})*))\k<host>			4 host (loose check)
				(?:
					:
					(?=(?<port>\d*))\k<port>														5 port
				)?
			)																						2 authority
			(?<path1>\/(?=(?<_path1>(?:[\w-.~!$&'()*+,;=:@/]|%[\dA-F]{2})*))\k<_path1>)?			6 path (after authority)
			
			|
			
			(?<path2>\/?(?!\/)(?=(?<_path2>(?:[\w-.~!$&'()*+,;=:@/]|%[\dA-F]{2})*))\k<_path2>)?		8 path (no authority)
		)
		(?:
			\?
			(?=(?<query>(?:[\w-.~!$&'()*+,;=:@/?]|%[\dA-F]{2})*))\k<query>							10 query
		)?
		(?:
			#
			(?=(?<fragment>(?:[\w-.~!$&'()*+,;=:@/?]|%[\dA-F]{2})*))\k<fragment>					11 fragment
		)?
		$
	*/
	
	/*let parts = rxp.exec(uri);
	if(!parts) return null;	//invalid URI
	parts = parts.groups;
	
	let scheme = parts.scheme.toLowerCase(),
		authority = parts.authority,
		userinfo = parts.userinfo,
		host = parts.host,
		port = parts.port,
		path = normalizePath(parts.path1 || parts.path2),
		query = normalizeQueryOrFragment(parts.query),
		fragment = normalizeQueryOrFragment(parts.fragment);*/
	
	//*** so we'll use numbered capture instead ***
	
	let rxp = /^(?=([a-z][a-z\d+.-]*))\1:(?:\/\/((?:(?=((?:[\w-.~!$&'()*+,;=:]|%[\dA-F]{2})*))\3@)?(?=(\[[\dA-F:.]{2,}\]|(?:[\w-.~!$&'()*+,;=]|%[\dA-F]{2})*))\4(?::(?=(\d*))\5)?)(\/(?=((?:[\w-.~!$&'()*+,;=:@/]|%[\dA-F]{2})*))\7)?|(\/?(?!\/)(?=((?:[\w-.~!$&'()*+,;=:@/]|%[\dA-F]{2})*))\9)?)(?:\?(?=((?:[\w-.~!$&'()*+,;=:@/?]|%[\dA-F]{2})*))\10)?(?:#(?=((?:[\w-.~!$&'()*+,;=:@/?]|%[\dA-F]{2})*))\11)?$/ui;
	
	/*Composed as follows:
		^
		(?=([a-z][a-z\d+.-]*))\1:												1 scheme
		(?:
			\/\/
			(
				(?:
					(?=((?:[\w-.~!$&'()*+,;=:]|%[\dA-F]{2})*))\3				3 userinfo
					@
				)?
				(?=(\[[\dA-F:.]{2,}\]|(?:[\w-.~!$&'()*+,;=]|%[\dA-F]{2})*))\4	4 host (loose check)
				(?:
					:
					(?=(\d*))\5													5 port
				)?
			)																	2 authority
			(\/(?=((?:[\w-.~!$&'()*+,;=:@/]|%[\dA-F]{2})*))\7)?					6 path (after authority)
			
			|
			
			(\/?(?!\/)(?=((?:[\w-.~!$&'()*+,;=:@/]|%[\dA-F]{2})*))\9)?			8 path (no authority)
		)
		(?:
			\?
			(?=((?:[\w-.~!$&'()*+,;=:@/?]|%[\dA-F]{2})*))\10					10 query
		)?
		(?:
			#
			(?=((?:[\w-.~!$&'()*+,;=:@/?]|%[\dA-F]{2})*))\11					11 fragment
		)?
		$
	*/
	
	let parts = rxp.exec(uri);
	if(!parts) return null;	//invalid URI
	
	let scheme = parts[1].toLowerCase(),
		authority = parts[2],
		userinfo = parts[3],
		host = parts[4],
		port = parts[5],
		path = normalizePath(parts[6] || parts[8]),
		query = normalizeQueryOrFragment(parts[10]),
		fragment = normalizeQueryOrFragment(parts[11]);
	
	//*** do some basic normalization and parsing ***
	
	if(authority){
		if((host = normalizeHost(host)) === null) return null;	//invalid host
		authority = (userinfo ? userinfo+"@" : "") + host + (port ? ":"+port : "");
	}
	
	uri = scheme+":" + (authority !== (void 0) ? "//"+authority : "") + path + (query ? "?"+query : "") + (fragment ? "#"+fragment : "");
	
	const parsed = new String(uri);
	parsed.orginail = original;
	parsed.uri = uri;
	parsed.scheme = scheme;
	if(authority){
		const a = parsed.authority = new String(authority);
		a.userinfo = userinfo;
		a.host = host;
		a.port = port;
	}
	parsed.path = path;
	parsed.query = query;
	parsed.fragment = fragment;
	
	//*** do scheme-specific normalization and parsing, if applicable ***
	
	if(URI.schemeParsers && URI.schemeParsers[scheme] instanceof Function){
		return URI.schemeParsers[scheme](parsed);
	}
	return parsed;
	
};

/**
 * A customizable collection of scheme-specific parsing functions.
 * @static
 * @name schemeParsers
 * @type {object}
 */
Object.defineProperty(URI, "schemeParsers", {
	writable: true, enumerable: false, configurable: true,
	value: {}
});

/**
 * Scheme-specific parser for http URIs
 * @param {ParsedURI} parsed
 * @returns {ParsedURI}
 */
URI.schemeParsers.http = p=>{
	let host = normalizeDNSHost(p.host);
	if(!host) return null;
	
	let port = p.port || "80";
	let authority = (p.userinfo ? p.userinfo+"@" : "") + host + (port==="80" ? "" : ":"+port);
	let path = removeDotSegments(p.path) || "/";
	let query = parseQuery(p.query);
	
	let uri = p.scheme+"://"+authority + path + (query ? "?"+query : "") + (p.fragment ? "#"+p.fragment : "");
	
	let ret = new String(uri);
	ret.uri = uri;
	ret.scheme = p.scheme;
	ret.authority = new String(authority);
	ret.authority.userinfo = p.userinfo;
	ret.authority.host = host;
	ret.authority.port = port;
	ret.path = path;
	ret.query = query;
	ret.fragment = p.fragment;
	return ret;
};

/**
 * Scheme-specific parser for https URIs
 * @param {ParsedURI} parsed
 * @returns {ParsedURI}
 */
URI.schemeParsers.https = p=>{
	let host = normalizeDNSHost(p.host);
	if(!host) return null;
	
	let port = p.port || "443";
	let authority = (p.userinfo ? p.userinfo+"@" : "") + host + (port==="443" ? "" : ":"+port);
	let path = removeDotSegments(p.path) || "/";
	let query = parseQuery(p.query);
	
	let uri = p.scheme+"://"+authority + path + (query ? "?"+query : "") + (p.fragment ? "#"+p.fragment : "");
	
	let ret = new String(uri);
	ret.uri = uri;
	ret.scheme = p.scheme;
	ret.authority = new String(authority);
	ret.authority.userinfo = p.userinfo;
	ret.authority.host = host;
	ret.authority.port = port;
	ret.path = path;
	ret.query = query;
	ret.fragment = p.fragment;
	return ret;
};

/**
 * Scheme-specific parser for mailto URIs
 * @param {ParsedURI} parsed
 * @returns {ParsedURI}
 */
URI.schemeParsers.mailto = p=>{
	if(p.authority) return null;
	
	let uri = p.scheme+":" + p.path + (p.query ? "?"+p.query : "");
	
	let ret = new String(uri);
	ret.uri = uri;
	ret.scheme = p.scheme;
	ret.path = p.path;
	ret.query = parseQuery(p.query);
	return parseMailto(ret);
};

/**
 * Converts an obscured host to a more readable one.
 * @private
 * @param {string} host
 * @param {boolean} useMixedNotation - Mix hexadecimal and dot-decimal notations to represent IPv4-mapped IPv6 addresses. Default is true (recommended per RFC 5952).
 * @return {string} - The normalized host. Null if the host is invalid.
 * 
 * See: How to Obscure Any URL   http://www.pc-help.org/obscure.htm
 *      RFC 3986   https://tools.ietf.org/html/rfc3986#section-3.2.2 - Host
 *                 https://tools.ietf.org/html/rfc3986#section-2 - Characters
 *      RFC 5952   https://tools.ietf.org/html/rfc5952#section-5 - Text Representation of Special Addresses
 */
function normalizeHost(host, useMixedNotation = true){
	
	if(host === void 0) return null;
	if(host === "") return "";
	host = ""+host;
	
	let ip;
	
	if((/^\[[^\]]*\]$/ui).test(host) && (ip = normalizeIPv6(host.slice(1, -1), useMixedNotation)) )
		return "["+ip+"]";	//it's a valid IPv6 address
	
	if(!(/^(?:[0-9a-z!$&'()*+,\-.;=_~]|%[0-9A-F]{2})*$/ui).test(host))
		return null;	//contains invalid characters
	
	//decode percent encodings of unreserved characters: DIGIT ALPHA -._~
	host = host.replace(/%(2[DE]|3\d|[46][1-9A-F]|[57][0-9A]|5F|7E)/uig, function (match, p1){ return String.fromCharCode(parseInt(p1, 16)); });
	
	if( (ip = normalizeIPv4(host)) )
		return ip;	//it's a valid IPv4 address
	
	//make percent encodings upper case; everything else lower case
	host = host.toLowerCase();
	host = host.replace(/%(..)/uig, function (match){ return match.toUpperCase(); });
	
	return host;
	
};

/**
 * Converts an obscured host to a more readable one. Only DNS domains or IPs are deemed valid.
 * @private
 * @param {string} host
 * @param {boolean} useMixedNotation - Mix hexadecimal and dot-decimal notations to represent IPv4-mapped IPv6 addresses. Default is true (recommended per RFC 5952).
 * @return {String} - Value is the host. Attributes include the host and its parts. Null if the host is invalid. Possible attributes:
 *   {string} .host - The normalized domain name or IP.
 *   {string} .ip
 *   {string} .ipv4
 *   {string} .ipv6
 *   {array} .labels - Array of the domain name's labels.
 * 
 * See: RFC 3986   https://tools.ietf.org/html/rfc3986#section-3.2.2
 *      RFC 2181   https://tools.ietf.org/html/rfc2181#section-11
 *      RFC 1123   https://tools.ietf.org/html/rfc1123#section-2
 *      RFC 3696   https://tools.ietf.org/html/rfc3696#section-2
 *      RFC 5952   https://tools.ietf.org/html/rfc5952#section-5 - Text Representation of Special Addresses
 */
function normalizeDNSHost(host, useMixedNotation = true){
	
	host = normalizeHost(host, useMixedNotation);
	if(!host) return null;
	
	if(/[^a-z0-9:\[\].-]/ui.test(host))
		return null;	//contains invalid characters
	
	if(/^\d+(\.\d+){3}$/.test(host)){	//it's an IPv4 address
		let ret = new String(host);
		ret.host = ret.ip = ret.ipv4 = host;
		ret.ipv6 = normalizeIPv6("::ffff:"+host, useMixedNotation);
		return ret;
	}
	if(host[0] === "["){	//it's an IPv6 address
		let ipv6 = host.slice(1, -1),
			ipv4 = v6to4(ipv6),
			ret = new String(ipv4 || host);
		ret.host = host;
		ret.ip = ipv4 || ipv6;
		ret.ipv4 = ipv4;
		ret.ipv6 = ipv6;
		return ret;
	}
	
	if(host.length > 255) return null;	//too long for a domain name
	
	if(/^(?=([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))\1(?:\.(?=([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))\2)*$/i.test(host) && !(/\.\d+$/).test(host)){	//it's a domain name (and per RFC 3696, the TLD isn't all-numeric)
		let ret = new String(host);
		ret.host = host;
		ret.labels = host.split(".");
		return ret;
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
 * @private
 * @param {string} ip - Normalized IPv6 address.
 * @return {string} - IPv4 address. Undefined if it can't be converted.
 * 
 * See: RFC 4291   https://tools.ietf.org/html/rfc4291#section-2.5.5
 */
function v6to4(ip){
	function hexToDec(hexField){
		let h = 1*("0x"+hexField),
			b = h%256,
			a = (h-b)/256;
		return a+"."+b;
	}
	let ret;
	if(ret = /^::ffff:([0-9.]+)$/i.exec(ip)) return ret[1];
	if(ret = /^::ffff:([^:]+):([^:]+)$/i.exec(ip)) return hexToDec(ret[1]) + "." + hexToDec(ret[2]);
	return void 0;	//can't be converted to IPv4
}

/**
 * Normalizes an IPv4 address.
 * @private
 * @param {string} ip - IPv6 address.
 * @param {boolean} [useMixedNotation] - Mix hexadecimal and dotted-decimal notations to represent an IPv4-mapped IPv6 address. Default is true (recommended per RFC 5952, section 5).
 * @return {string} - Normalized IPv6 address. Null if it's invalid.
 * 
 * See: How to Obscure Any URL   http://www.pc-help.org/obscure.htm
 *      RFC 3986   https://tools.ietf.org/html/rfc3986#section-7.4
 *      Wikipedia: IPv4, Address representations   http://en.wikipedia.org/wiki/IPv4#Address_representations
 */
function normalizeIPv4(ip){
	
	if(ip === void 0) return null;
	ip = ""+ip;
	
	if(!(/^(?=(0x[0-9A-F]+|\d+))\1(?:\.(?=(0x[0-9A-F]+|\d+))\2){0,3}$/i).test(ip)) return null;	//invalid IP address
	
	//dword, octal, and hexadecimal numbers aren't valid, but they work in web browsers anyway, so we'll fix them
	let parts = ip.split("."),
		vals = [];
	for(let i=0; i<parts.length; i++){	//for each part
		let val;
		if((/^0x/i).test(parts[i])){
			val = parseInt(parts[i].slice(2), 16);	//convert hexadecimal to decimal
		}
		else if(parts[i][0] === "0"){
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
 * @private
 * @param {string} ip - IPv6 address.
 * @param {boolean} useMixedNotation - Mix hexadecimal and dot-decimal notations to represent IPv4-mapped IPv6 addresses. Default is true (recommended per RFC 5952, section 5).
 * @return {string} - Normalized IPv6 address. Null if it's invalid.
 * 
 * See: RFC 4291   https://tools.ietf.org/html/rfc4291#section-2.5.5
 *      RFC 5952   https://tools.ietf.org/html/rfc5952#section-4
 *                 https://tools.ietf.org/html/rfc5952#section-5
 */
function normalizeIPv6(ip, useMixedNotation = true){
	
	if(ip === void 0) return null;
	ip = ""+ip;
	
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
				fieldsLeft[i] = fieldsLeft[i].replace(/(^|\.)0+(?=\d)/g, "$1");	//remove leading zeroes from IPv4 fields (octals are not acceptable in an IPv6)
				
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
					fieldsRight[i] = fieldsRight[i].replace(/(^|\.)0+(?=\d)/g, "$1");	//remove leading zeroes from IPv4 fields (octals are not acceptable in an IPv6)
					
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
	ip = ip.replace(/(^|:)0+(?=[^:.])/g, "$1");
	
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
 * @private
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
 * Removes dot-segments from a relative reference.
 * @private
 * @param {string} path
 * @return {string}
 * 
 * See: RFC 3986   https://tools.ietf.org/html/rfc3986#section-4.2
 *                 https://tools.ietf.org/html/rfc3986#section-5.2.4
 */
function removeDotSegments(path){
	
	if(path === void 0) return "";
	path = ""+path;
	
	let output = [];
	while(path){
		path = path.replace(/^(\.\.?\/)+/u, "");
		if(/\/\.\.(\/|$)/u.test(path)) output.pop();
		path = path.replace(/\/\.\.?(\/|$)/u, "/").replace(/^\.\.?$/u, "");
		output.push(/^\/?[^\/]*/u.exec(path)[0]);
		path = path.slice(output[output.length-1].length);
	}
	
	return output.join("");
	
}

/**
 * Converts an obscured query string or fragment to a more readable one.
 * @private
 * @param {string} queryOrFragment
 * @return {string}
 * 
 * See: RFC 3986   https://tools.ietf.org/html/rfc3986#section-3.4
 *                 https://tools.ietf.org/html/rfc3986#section-2.4
 */
function normalizeQueryOrFragment(queryOrFragment){
	
	if(queryOrFragment === void 0) return "";
	queryOrFragment = ""+queryOrFragment;
	
	//decode percent encodings of unreserved characters: DIGIT ALPHA -._~
	return queryOrFragment.replace(/%(2[DE]|3\d|[46][1-9A-F]|[57][0-9A]|5F|7E)/ig, (match, p1)=>String.fromCharCode(parseInt(p1, 16)));
	
}

/**
 * Parses a query string as a sequence of name/value pairs.
 * @private
 * @param {string} query
 * @return {String} - The normalized query.
 *   {array} .pairs - Array of name/value pairs (each pair is an object {name, value}).
 * 
 * See: RFC 3986   https://tools.ietf.org/html/rfc3986#section-3.4
 */
function parseQuery(query){
	
	if(query === "" || query === void 0) return [];
	query = ""+query;
	
	query = normalizeQueryOrFragment(query);
	
	let pairs = query.split("&"),
		results = [];
	for(let i=0; i<pairs.length; i++){
		let pair = pairs[i].split("=");
		if(pair[0] === ""){	//there is no name; remove it
			pairs.splice(i--,1);
			continue;
		}
		//if there is no equal sign, the value will be undefined
		
		//add the name/value pair to the results
		results.push( { name: decodeURIComponent(pair[0]), value: decodeURIComponent(pair[1]) } );
	}
	
	query = new String(pairs.join("&"));
	query.pairs = results;
	
	return query;
	
};

/**
 * Splits a mailto scheme URI into its parts.
 * @private
 * @param {object} parts - Object containing the URI, scheme, path, and query object.
 * @return {object} - Object containing the following. Null if the URI is invalid or there is no valid destination.
 *   {string} .uri - normalized URI
 *   {string} .scheme - "mailto"
 *   {string} .path
 *   {String} .query
 *     {array} .query.pairs - Array of name/value pairs (each pair is an object {name, value}).
 *   {array} .to
 *   {array} .cc
 *   {array} .bcc
 *   {string} .subject - Multiple "subject" headers are combined.
 *   {string} .body - Multiple "body" headers are combined.
 *   {array} .headers - Array containing any additional headers (each header is an object {name, value}).
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
		
		let headers = parts.query.pairs || [];
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
 * @private
 * @param {string} address - email address or mailbox (mailbox example: "John Doe" <john.doe@example.com> )
 * @return {object} - Object containing the mailbox and its parts. Null if it's invalid.
 *   {string} .full - If there is a display name: "display name" <local@domain>
 *                    If there isn't: local@domain
 *   {string} .simple - local@domain
 *   {string} .displayName - Display name.
 *   {string} .localPart - Local part of the address.
 *   {string} .domain - Domain part of the address. Only DNS domains or IPs are deemed valid.
 *   {string} .unescapedFull - `.full` with any quoted strings unescaped.
 *   {string} .unescapedSimple - `.simple` with the local part unescaped (if it's a quoted string).
 *   {string} .unescapedDisplayName - `.displayName` with any quoted strings unescaped.
 *   {string} .unescapedLocalPart - `.localPart` unescaped (if it's a quoted string).
 * 
 * Does not parse groups (e.g., a distribution list).
 * Unfolds whitespace and removes comments.
 * Does not consider the 998 character limit per line.
 * See: RFC 5322   https://tools.ietf.org/html/rfc5322
 *      RFC 5321   https://tools.ietf.org/html/rfc5321#section-4.1.2
 *                 https://tools.ietf.org/html/rfc5321#section-2.3.4
 *                 https://tools.ietf.org/html/rfc5321#section-4.5.3.1
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
			else if( (m = /^\[([a-z0-9\-.:]+)\]/i.exec(mailbox)) && (trimmed = normalizeDNSHost(m[0]) || normalizeDNSHost(m[1])) ){
				token.type = "domain-literal";
				mailbox = mailbox.slice(m[0].length);
				token.value = trimmed.host[0]==="[" ? trimmed.host : "["+trimmed.host+"]";
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
			QSACount = 0,
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
			else if(!foundDisplayName && !foundNoDisplayName){
				if(tokens[i].type === "dot-atom"){
					if(QSACount > 0) return null;
					foundNoDisplayName = true;
					foundNoAngleBracket = true;
					foundLocalPart = true;
					i++;
				}
				else if(tokens[i].type === "quoted-string" || tokens[i].type === "atom"){
					QSACount++;
					i++;
				}
				else if(tokens[i].value === "@"){
					if(QSACount > 1) return null;
					foundNoDisplayName = true;
					foundNoAngleBracket = true;
					foundLocalPart = true;
					foundAtSign = true;
					i++;
				}
				else if(tokens[i].type === "wsp"){
					if(tokens[i+1] && tokens[i+1].value === "@") return null;	//WSP before "@"
					i++;
				}
				else if(QSACount > 0){
					foundDisplayName = true;
				}
				else{
					foundNoDisplayName = true;
				}
			}
			else if(tokens[i].type === "wsp"){
				if((foundLocalPart && !foundAtSign) || (foundAtSign && !foundDomain)){
					return null;	//WSP around "@"
				}
				i++;
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
					if(tokens[i].value.length > 64) return null;	//too long
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
				if(tokens[i].type === "domain-literal"){
					if(tokens[i].value.length > 255) return null;	//too long
					foundDomain = true;
					i++;
				}
				else if( (tokens[i].type === "atom" || tokens[i].type === "dot-atom") && (tokens[i].value = normalizeDNSHost(tokens[i].value)) ){
					if(tokens[i].value.ipv4){
						tokens[i].value = "[" + tokens[i].value.ipv4 + "]";	//IPv4 domain-literal
					}
					else{
						tokens[i].value = tokens[i].value.host;
					}
					if(tokens[i].value.length > 255) return null;	//too long
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
					let str = tokens[0].value.replace(rxp_redundantPairs, "$1");
					parts.displayName += str;
					parts.unescapedDisplayName += str.replace(/\\(.)/g, "$1");
				}
				else{
					parts.displayName += tokens[0].value;
					parts.unescapedDisplayName += tokens[0].value;
				}
				
				tokens.shift();
				
			}
			parts.displayName = parts.displayName.replace(/[\t ]+/g, " ").trim();
			parts.unescapedDisplayName = parts.unescapedDisplayName.replace(/[\t ]+/g, " ").trim();
		}
		
		if(foundAngleBracket){
			tokens.shift();
		}
		if(tokens[0].type === "wsp"){
			tokens.shift();
		}
		if(tokens[0].type === "quoted-string"){	//local part is a quoted-string
			tokens[0].value = tokens[0].value.replace(rxp_redundantPairs, "$1");
		}
		parts.localPart = tokens[0].value;
		parts.unescapedLocalPart = parts.localPart.replace(/\\(.)/g, "$1");
		tokens.shift();
		
		tokens.shift();	//the "@"
		
		parts.domain = tokens[0].value;
		
		//ignore any remaining characters
		
		parts.simple = parts.localPart+"@"+parts.domain;
		parts.unescapedSimple = parts.unescapedLocalPart+"@"+parts.domain;
		
		parts.full = foundDisplayName ? parts.displayName+" <"+parts.simple+">" : parts.simple;
		parts.unescapedFull = foundDisplayName ? parts.unescapedDisplayName+" <"+parts.unescapedSimple+">" : parts.unescapedSimple;
		
	}
	
	return parts;
	
};

/**
 * Attempts to fix a URI if it's invalid. It refers to the current page's location if the scheme or authority are missing, and encodes invalid characters.
 * 
 * @param {string} href - URI or relative reference to analyze and fix.
 * @return {object} - Null if the URI can't be fixed. Possible members:
 *   {function} .toString - Returns the fixed and normalized URI as a string.
 *   {string} .uri - Fixed and normalized URI.
 *   {string} .networkPathReference - Relative reference starting with "//" (relative to the scheme).
 *   {string} .absolutePathReference - Relative reference starting with a single "/" (relative to the root).
 *   {string} .relativePathReference - Relative reference not starting with a "/" (relative to the current document).
 *   {string} .sameDocumentReference - The fragment, including the "#".
 * 
 * See: RFC 3986   https://tools.ietf.org/html/rfc3986#section-4.2
 */
function fixHyperlink(href){
	
	if(!href) return null;
	
	let given = href,
		schemeFound,
		authorityFound,
		location = (window && window.location) ? window.location : {},
		parts = {
			scheme: "",	//including the colon
			authority: "",
			userinfo: "",
			host: "",
			port: "",
			//relativePath: "",
			//path: "",
			query: "",
			fragment: ""
			};
	
	let ret = new URI(href);
	if(ret) return valid(ret);	//URI is valid
	
	function valid(parsed){
		let result = new String(parsed.uri),
			qf = (""+parsed.query?"?"+parsed.query:"")+(parsed.fragment?"#"+parsed.fragment:"");
		
		result.uri = parsed.uri;
		if(parsed.authority) result.networkPathReference = "//"+parsed.authority+parsed.path+qf;
		if(parsed.path[0] === "/") result.absolutePathReference = parsed.path+qf;
		if(parts && parts.relativePath !== void 0) result.relativePathReference = parts.relativePath+qf;
		if(parsed.fragment) result.sameDocumentReference = "#"+parsed.fragment;
		
		return result;
	}
	
	function getWindowAuthority(){
		if(!schemeFound && location.hostname){
			parts.userinfo = location.username;
			if(location.password) parts.userinfo += ":"+location.password;
			parts.host = location.hostname;
			parts.port = location.port;
			parts.authority = (parts.userinfo?parts.userinfo+"@":"") + parts.host + (parts.port?":"+parts.port:"");
		}
	}
	
	function getAuthority(href){
		
		let given = href;
		
		function notFound(){
			getWindowAuthority();
			return given;
		}
		
		//get userinfo
		
		let ret = /^([^@:\/\[]*)@/.exec(href);
		if(ret){	//userinfo
			parts.userinfo = ret[1];
			//percent-encode illegal characters
			parts.userinfo = parts.userinfo.replace(/(?:[^a-z0-9-._~!$&'()*+,;=:%]|%(?![0-9A-F]{2}))+/ig, function (match){ return encodeURIComponent(match); });
			href = href.slice(ret[0].length);
		}
		
		//get host
		
		ret = /^\[([a-f0-9:.\]]*)\](?=[:\/?#]|$)/i.exec(href);
		if(ret){	//possibly valid IPv6
			ret = normalizeIPv6(ret[1]);
			if(ret){	//valid IPv6
				parts.host = "["+ret.host+"]";
				href = href.slice(ret[0].length);
			}
			else{
				return notFound();
			}
		}
		else{
			ret = /^([^:\/]*)(?=[:\/?#]|$)/.exec(href);
			if(ret){	//possible host
				let ret2 = normalizeDNSHost(ret[1]);
				if(ret2){	//valid host
					parts.host = ret2.host;
					href = href.slice(ret[0].length);
				}
				else{
					return notFound();
				}
			}
			else{
				return notFound();
			}
		}
		
		//get port
		
		ret = /^:(\d*)(?=[\/?#]|$)/.exec(href);
		if(ret){	//port
			parts.port = ret[1];
			href = href.slice(ret[0].length);
		}
		else if(href[0] === ":"){
			return  notFound();
		}
		
		parts.authority = (parts.userinfo?parts.userinfo+"@":"") + parts.host + (parts.port?":"+parts.port:"");
		authorityFound = true;
		return href;	//valid authority found; return remainder
		
	}
	
	function getPQF(href){
		
		if(!href) return;
		
		//get path
		
		let ret = /^[^?#]*/g.exec(href)[0];
		href = href.slice(ret.length);
		
		//percent-encode illegal characters
		ret = ret.replace(/(?:[^a-z0-9-._~!$&'()*+,;=:@\/%]|%(?![0-9A-F]{2}))+/ig, function (match){ return encodeURIComponent(match); });
		
		let path = normalizePath(ret);
		if(!schemeFound && !authorityFound && path[0] !== "/"){
				parts.relativePath = path;
				if(location.pathname !== void 0) parts.path = location.pathname.replace(/(^|\/)[^\/]*$/, "/"+path);
		}
		else{
			parts.path = path;
		}
		
		//get query
		
		ret = /^(\?[^#]*)?/.exec(href)[0];
		href = href.slice(ret.length);
		
		//percent-encode illegal characters
		ret = ret.slice(1).replace(/(?:[^a-z0-9-._~!$&'()*+,;=:@\/?%]|%(?![0-9A-F]{2}))+/ig, function (match){ return encodeURIComponent(match); });
		
		parts.query = normalizeQueryOrFragment(ret);
		
		//get fragment
		
		if(href){
			//percent-encode illegal characters
			href = href.slice(1).replace(/(?:[^a-z0-9-._~!$&'()*+,;=:@\/?%]|%(?![0-9A-F]{2}))+/ig, function (match){ return encodeURIComponent(match); });
			
			parts.fragment = normalizeQueryOrFragment(href);
		}
		
	}
	
	//get scheme
	let scheme = (/^([a-z][a-z0-9+.-]*):/i).exec(href);
	if(scheme){
		scheme = scheme[0].toLowerCase();
		href = href.slice(scheme.length);
		schemeFound = true;
	}
	else{
		scheme = location.protocol || "http:";
		if( (ret = new URI(scheme+href)) ) return valid(ret);
	}
	parts.scheme = scheme;
	
	if(/^https?:$/.test(scheme)){
		if(/^\/\//.test(href)){	//it has an authority
			href = getAuthority(href.slice(2)) || "/";
		}
		else{
			getWindowAuthority();
		}
		if(!parts.authority) return null;	//can't fix it
	}
	else{
		if(/^\/\//.test(href)){	//it has an authority
			href = getAuthority(href.slice(2));
			if(!parts.authority) return null;	//can't fix it
		}
	}
	
	getPQF(href);	//get path, query, and fragment
	
	if(parts.path === void 0) return null;	//can't fix it
	
	if(/^https?:$/.test(parts.scheme)){
		parts.path = removeDotSegments(parts.path);
		parts.relativePath = removeDotSegments(parts.relativePath, true);
	}
	
	ret = new URI(parts.scheme + (parts.authority ? "//"+parts.authority : "") + parts.path + "?"+parts.query + "#"+parts.fragment);
	if(ret) return valid(ret);	//fixed URI
	
	
	if(!schemeFound && /^[^:\/?#]*:/.test(given)){
	//broken hyperlink is possibly a relative path, with the first segment including a colon
		if(location.scheme){
			getWindowAuthority();
			return fixHyperlink(location.scheme + (parts.authority ? "//"+parts.authority : "") + href);
		}
		else{
			return null;	//can't fix it
		}
	}
	
	return null;	//can't fix it
	
};
