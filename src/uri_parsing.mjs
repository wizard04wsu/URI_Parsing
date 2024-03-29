/*
 * This script does not support:
 *   - internationalized domain names (IDNs)
 *   - non-ASCII email addresses (see RFC 6530)
 *   - IPvFuture literal address formats
 *   - obsolete syntaxes
 * 
 * General references:
 *   RFC 3986 "Uniform Resource Identifier (URI): Generic Syntax"    https://tools.ietf.org/html/rfc3986
 *   How to Obscure Any URL    http://www.pc-help.org/obscure.htm
 *   RFC 6068 "The 'mailto' URI Scheme"    https://tools.ietf.org/html/rfc6068
 *   Wikipedia: Email address    https://en.wikipedia.org/wiki/Email_address
 *   RFC 5322 "Internet Message Format"    https://tools.ietf.org/html/rfc5322
 *   RFC 5321 "Simple Mail Transfer Protocol"    https://tools.ietf.org/html/rfc5321#section-4.1.2
 *   RFC 5234 "Augmented BNF for Syntax Specifications: ABNF"    https://tools.ietf.org/html/rfc5234#appendix-B.1
 *   RFC 5952 "A Recommendation for IPv6 Address Text Representation"    https://tools.ietf.org/html/rfc5952
 */

// https://github.com/wizard04wsu/URI_Parsing

/** @module URI */


/**
 * A String object whose properties are substrings.
 * @extends String
 */
class SegmentedString extends String {
	/**
	 * @constructor
	 * @param {Function} toPrimitive - Returns a primitive string representing the SegmentedString. This function will be used when the SegmentedString must be coerced into a primitive value.
	 * @param {Object} [initialMembers={}] - An object containing the properties that should be attached to the SegmentedString during its construction.
	 */
	constructor(toPrimitive, initialMembers = {}){
		if(typeof toPrimitive !== "function") throw new TypeError("'toPrimitive' must be a function");
		if(initialMembers === void 0) initialMembers = {};
		if(typeof initialMembers !== "object") throw new TypeError("'initialMembers' must be an object");
		
		super();
		
		defineNonEnumerableProperty(this, "toString", function (){ return String(toPrimitive.apply(this)); });
		defineNonEnumerableProperty(this, "valueOf", function (){ return String(toPrimitive.apply(this)); });
		
		for(const prop in initialMembers){
			if(initialMembers.hasOwnProperty(prop))
				this[prop] = initialMembers[prop];
		}
	}
}


/**
 * A URI and its parts. The members vary depending on the scheme.
 * @typedef {string} ParsedURI
 * @property {string} scheme
 * @property {ParsedURI_authority|undefined} authority
 * @property {string} path
 * @property {string|ParsedURI_query} query
 * @property {string} fragment
 */
/**
 * An authority and its applicable parts.
 * @typedef {SegmentedString} ParsedURI_authority
 * @property {string} userinfo
 * @property {ParsedURI_host} host
 * @property {string} port
 */
/**
 * A host (IP address or registered name) and any of its related representations.
 * @typedef {SegmentedString} ParsedURI_host - An IPv4 address, an IP literal in square brackets, or a registered name.
 * @property {string|undefined} name - A registered name.
 * @property {SegmentedString|undefined} ip - An IP address. (IPv4 is preferred, then IPv6 mixed, then IPv6 hex-only. Future versions are not supported.)
 * @property {string|undefined} ip.v4 - IPv4 address.
 * @property {string|undefined} ip.v6mixed - IPv6 address using mixed hexadecimal and dot-decimal notations to represent an IPv4-mapped IPv6 address.
 * @property {string|undefined} ip.v6 - IPv6 address using only hexadecimal notation.
 */
/**
 * A query string and its key/value pairs.
 * @typedef {SegmentedString} ParsedURI_query
 * @property {Array.<object>} pairs - Array of decoded key/value pairs (each pair is an object: {key, value}).
 */

/**
 * A parser specific to a single scheme of URIs. This can modify the ParsedURI object that is passed to it.
 * @typedef {Function} SchemeParser
 * @param {SegmentedString} parsed - The object created by the `parseURI` function. The object may be modified by this function.
 * @returns {boolean} - Truthy if the URI conforms to the scheme, falsy if not.
 */


/**
 * Normalizes a URI, and splits it into its parts. The members vary depending on the scheme.
 * @alias module:URI
 * @param {string} uri
 * @returns {ParsedURI} - The normalized URI and its parts. The members vary depending on the scheme.
 * @throws {URIError} - If the scheme is known and the URI does not conform to it.
 */
function URI(uri){
	
	const parsed = parseURI(uri);
	
	if(URI.schemeParser && URI.schemeParser[parsed.scheme] instanceof Function){
		//there is a scheme-specific parser for this URI's scheme
		
		//do scheme-specific normalization and parsing
		try{
			URI.schemeParser[parsed.scheme](parsed);
		}catch(e){
			if(e instanceof URIError)
				throw new URIError(`the URI does not conform to the ${parsed.scheme} scheme`, { cause: e });
			throw e;
		}
	}
	
	return parsed;
	
}

URI.parse = parseURI;
URI.resolveRelativeReference = resolveRelativeReference;
URI.parseHost = parseHost;
URI.parseQuery = parseQuery;

/**
 * A customizable collection of scheme-specific parsing functions.
 * @static
 * @name schemeParser
 * @type {object}
 */
URI.schemeParser = {
	
	/**
	 * Scheme-specific parser for http URIs
	 * @type {SchemeParser}
	 */
	http(p){
		if(p.scheme !== "http")
			throw new RangeError("scheme does not match");
		if(!p.authority || !p.authority.host)
			throw new URIError("the URI does not include a host");
		if(!p.authority.host.ip && !isDNSDomain(p.authority.host.name))
			throw new URIError("the host is neither an IP address nor a DNS domain name");
		
		p.authority = new SegmentedString(function (){
				let primitive = this.userinfo && ""+this.userinfo ? this.userinfo+"@" : "";
				primitive += this.host;
				primitive += this.port && this.port !== "80" ? ":"+this.port : "";
				return primitive;
			},
			p.authority
		);
		
		p.authority.port = p.authority.port || "80";
		p.path = removeDotSegments(p.path) || "/";
		p.query = parseQuery(p.query);
	},
	
	/**
	 * Scheme-specific parser for https URIs
	 * @type {SchemeParser}
	 */
	https(p){
		if(p.scheme !== "https")
			throw new RangeError("scheme does not match");
		if(!p.authority || !p.authority.host)
			throw new URIError("the URI does not include a host");
		if(!p.authority.host.ip && !isDNSDomain(p.authority.host.name))
			throw new URIError("the host is neither an IP address nor a DNS domain name");
		
		p.authority = new SegmentedString(function (){
				let primitive = this.userinfo && ""+this.userinfo ? this.userinfo+"@" : "";
				primitive += this.host;
				primitive += this.port && this.port !== "443" ? ":"+this.port : "";
				return primitive;
			},
			p.authority
		);
		
		p.authority.port = p.authority.port || "443";
		p.path = removeDotSegments(p.path) || "/";
		p.query = parseQuery(p.query);
	},
	
	/**
	 * Scheme-specific parser for mailto URIs
	 * @type {SchemeParser}
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
	mailto(p){
		if(p.scheme !== "mailto")
			throw new RangeError("scheme does not match");
		if(p.authority)
			throw new URIError("the URI includes an authority");
		
		p.fragment = "";
		p.query = parseQuery(p.query);
		
		p.to = [];
		p.cc = [];
		p.bcc = [];
		p.subject = "";
		p.body = "";
		p.headers = [];	//other headers besides the above (each header is an object {name, value})
		
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
				let rxp = /(?:^|[^\\()"])(?:\\\\)*([()"])/ug,
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
					let parsed = parseMailbox(parts[0]);
					if(parsed){	//it's a valid address
						addresses.push(parsed.displayName ? parsed.full : parsed.simple);
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
		
		//split headers into arrays
		{
			
			p.to = p.path ? splitEmailAddresses(p.path) : [];
			
			let headers = p.query.pairs ? p.query.pairs.map(p=>{return {
				name: decodeURIComponent(p.key),
				value: p.value
			}}) : [];
			for(let i=0; i<headers.length; i++){
				if(headers[i].value === "") continue;
				
				switch(headers[i].name){
					case "to":
						p.to = p.to.concat(splitEmailAddresses(headers[i].value));
					break; case "cc":
						p.cc = p.cc.concat(splitEmailAddresses(headers[i].value));
					break; case "bcc":
						p.bcc = p.bcc.concat(splitEmailAddresses(headers[i].value));
					break; case "subject":
						p.subject += decodeURIComponent(headers[i].value);
					break; case "body":
						p.body += decodeURIComponent(headers[i].value);
					break; default:
						headers[i].value = decodeURIComponent(headers[i].value);
						p.headers.push(headers[i]);
				}
			}
			
			if(p.to.length + p.cc.length + p.bcc.length === 0)
				throw new URIError("the URI does not include a valid destination address");
			
		}
		
		//combine headers into a query string
		{
			
			p.path = encodePart(p.to.join(","));
			
			let query = "";
			if(p.cc.length){
				query += "cc=" + encodePart(p.cc.join(","));
			}
			if(p.bcc.length){
				if(query) query += "&";
				query += "bcc=" + encodePart(p.bcc.join(","));
			}
			if(p.subject){
				if(query) query += "&";
				query += "subject=" + encodePart(p.subject);
			}
			if(p.body){
				if(query) query += "&";
				query += "body=" + encodePart(p.body);
			}
			if(p.headers.length){
				for(let i=0; i<p.headers.length; i++){
					if(query) query += "&";
					query += encodePart(p.headers[i].name) + "=" + encodePart(p.headers[i].value);
				}
			}
			
			p.uri = "mailto:" + p.path + (query ? "?"+query : "");
			
			p.query = parseQuery(query);
			
		}
		
	}
	
};


/**
 * Normalizes a URI, and splits it into its generic parts.
 * @alias module:URI.parse
 * @param {string} uri
 * @returns {ParsedURI} - The normalized URI and its generic parts.
 * @throws {TypeError}
 * @throws {URIError} - If it's not a valid URI.
 * @see [RFC 3986](https://tools.ietf.org/html/rfc3986)
 */
function parseURI(uri){
	
	if(!(typeof uri === "string" || uri instanceof String))
		throw new TypeError("'uri' is not a string");
	
	uri = ""+uri;
	
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
	if(!parts) throw new URIError("'uri' is not a valid URI");
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
	
	let rxp = /^(?=([a-z][a-z\d+.-]*))\1:(?:\/\/((?:(?=((?:[-\w.~!$&'()*+,;=:]|%[\dA-F]{2})*))\3@)?(?=(\[[\dA-F:.]{2,}\]|(?:[-\w.~!$&'()*+,;=]|%[\dA-F]{2})*))\4(?::(?=(\d*))\5)?)(\/(?=((?:[-\w.~!$&'()*+,;=:@/]|%[\dA-F]{2})*))\7)?|(\/?(?!\/)(?=((?:[-\w.~!$&'()*+,;=:@/]|%[\dA-F]{2})*))\9)?)(?:\?(?=((?:[-\w.~!$&'()*+,;=:@/?]|%[\dA-F]{2})*))\10)?(?:#(?=((?:[-\w.~!$&'()*+,;=:@/?]|%[\dA-F]{2})*))\11)?$/ui;
	
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
	if(!parts) throw new URIError("'uri' is not a valid URI");
	
	let scheme = parts[1].toLowerCase(),
		authority = parts[2],
		userinfo = parts[3],
		host = parts[4],
		port = parts[5],
		path = normalizePath(parts[6] || parts[8]),
		query = normalizeQueryOrFragment(parts[10]),
		fragment = normalizeQueryOrFragment(parts[11]);
	
	const parsed = new SegmentedString(function (){
			let primitive = ""+this.scheme+":";
			if(this.authority) primitive += "//"+this.authority;
			primitive += this.path;
			primitive += (this.query && ""+this.query ? "?"+this.query : "");
			primitive += (this.fragment && ""+this.fragment ? "#"+this.fragment : "");
			return primitive;
		},
		{
			scheme: scheme,
			path: path,
			query: query,
			fragment: fragment
		}
	);
	
	if(authority !== void 0){
		//the URI contains an authority (which could be empty)
		
		parsed.authority = new SegmentedString(function (){
				let primitive = this.userinfo && ""+this.userinfo ? this.userinfo+"@" : "";
				primitive += this.host;
				primitive += this.port && ""+this.port ? ":"+this.port : "";
				return primitive;
			},
			{
				userinfo: userinfo,
				host: parseHost(host),
				port: port
			}
		);
	}
	
	return parsed;
	
}

/**
 * Determines the target URI of a relative reference.
 * @alias module:URI.resolveRelativeReference
 * @param {string} relativeReference The relative reference.
 * @param {string} baseURI - The URI that the reference is relative to.
 * @returns {string} - The target URI.
 * @throws {TypeError}
 * @throws {URIError} - If 'baseURI' is not a valid.
 * @see [RFC 3986, section 4.2](https://tools.ietf.org/html/rfc3986#section-4.2)
 * @see [RFC 3986, section 5.2.4](https://tools.ietf.org/html/rfc3986#section-5.2.4)
 */
function resolveRelativeReference(relativeReference, baseURI){
	
	if(!(typeof relativeReference === "string" || relativeReference instanceof String))
		throw new TypeError("'relativeReference' is not a string");
	if(!(typeof baseURI === "string" || baseURI instanceof String))
		throw new TypeError("'baseURI' is not a string");
	
	relativeReference = ""+relativeReference;
	
	try{
		let targetURI = parseURI(relativeReference);
		return targetURI;	//it's already a full URI
	}catch(e){
		if(!(e instanceof URIError)) throw e;
	}
	
	try{
		baseURI = parseURI(baseURI);
	}catch(e){
		if(e instanceof URIError) throw new URIError("'baseURI' is not a valid URI", { cause: e });
		throw e;
	}
	
	if(relativeReference === "") return baseURI;
	
	//build the target URI
	
	//add the base scheme
	let targetURI = ""+baseURI.scheme+":";
	
	if(baseURI.authority && !/^\/\//u.test(relativeReference)){
		//add the base authority
		targetURI += "//"+baseURI.authority;
	}
	
	if(relativeReference[0] !== "/"){
		if(relativeReference[0] === "#"){
			//add the base path
			targetURI += baseURI.path;
			//add the base query
			targetURI += "?"+baseURI.query;
		}
		else if(relativeReference[0] === "?"){
			//add the base path
			targetURI += baseURI.path;
		}
		/*else if(/^([a-z\d+.-]*):/u.test(relativeReference)){
			throw new URIError("the first path segment of 'relativeReference' contains a colon; consider preceding it with './'");
		}*/
		else{
			//add the base path, up to the last "/"
			targetURI += baseURI.path.match(/^(?:[^\/]*\/)*/u)[0];
		}
	}
	
	targetURI += relativeReference;
	
	try{
		return parseURI(targetURI).toString();
	}catch(e){
		if(e instanceof URIError) throw new URIError("the relative reference could not be resolved", { cause: e });
		throw e;
	}
	
}


/**
 * Converts an obscured host to a more readable one, along with related representations.
 * @alias module:URI.parseHost
 * @param {string} host
 * @returns {ParsedURI_host} - The normalized host (IP address or registered name) and related representations.
 * @throws {TypeError}
 * @throws {URIError} - If it's not a valid host.
 * @throws {URIError} - If the IP address literal format is not supported.
 * @see [How to Obscure Any URL](http://www.pc-help.org/obscure.htm)
 * @see [RFC 3986, section 3.2.2](https://tools.ietf.org/html/rfc3986#section-3.2.2) - Host
 * @see [RFC 3986, section 2](https://tools.ietf.org/html/rfc3986#section-2) - Characters
 */
function parseHost(host){
	
	if(!(typeof host === "string" || host instanceof String))
		throw new TypeError("'host' is not a string");
	
	host = ""+host;
	
	let ipv4, ipv6mixed, ipv6;
	
	if((/^\[[^\]]*\]$/ui).test(host)){
		//host is enclosed by square brackets
		
		let ipLiteral = host.slice(1, -1);
		
		if( (ipv6 = normalizeIPv6(ipLiteral, false)) ){
			//it's a valid IPv6 address
			
			ipv4 = v6to4(ipv6);
			if(ipv4){
				ipv6mixed = "::ffff:"+ipv4;
				if(!(/^::ffff:/ui).test(ipv6)){
					ipv6 = "::ffff:"+ipv6.slice(2);
				}
			}
		}
		else if(/^v[\da-f]\.[a-z\d._~!$&'()*+,;=:-]+$/ui.test(ipLiteral)){
			//it's a future version of an IP address literal
			
			throw new URIError(`version ${ipLiteral[1]} of the IP address literal format is not supported`);
		}
		else{
			throw new URIError("invalid IP address literal");
		}
	}
	else if(!(/^(?:[0-9a-z!$&'()*+,\-.;=_~]|%[0-9A-F]{2})*$/ui).test(host)){
		throw new URIError("host contains invalid characters");
	}
	else{
		//decode percent encodings of unreserved characters: DIGIT ALPHA -._~
		host = host.replace(/%(2[DE]|3\d|[46][1-9A-F]|[57][0-9A]|5F|7E)/uig, function (match, p1){
			return String.fromCharCode(parseInt(p1, 16));
		});
		
		if(ipv4 = normalizeIPv4(host)){
			//it's a valid IPv4 address
			
			ipv6mixed = "::ffff:"+ipv4;
			ipv6 = normalizeIPv6(ipv6mixed, false);
		}
		else{
			//it's a valid reserved name
			
			//make percent encodings upper case; everything else lower case
			host = host.toLowerCase().replace(/%../uig, function (match){
				return match.toUpperCase();
			});
		}
	}
	
	let parsed = new SegmentedString(function (){
		return ""+(this.ip || this.name || "");
	});
	
	if(ipv6){
		parsed.ip = new SegmentedString(function (){
				return ""+(this.v4 || this.v6mixed || this.v6 || "");
			},
			{
				v4: ipv4,
				v6mixed: ipv6mixed,
				v6: ipv6
			}
		);
	}
	else{
		parsed.name = host;
	}
	
	return parsed;
	
}

/**
 * Converts the four 8-bit decimal values of a normalized IPv4 address to the two low-order 16-bit hexadecimal values of an IPv6 address.
 * @private
 * @param {string} ip - Normalized IPv4 address.
 * @return {string} - Two 16-bit hexadecimal values representing the IPv4 portion of an IPv6 address.
 * @see [RFC 4291, section 2.5.5](https://tools.ietf.org/html/rfc4291#section-2.5.5)
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
 * @see [RFC 4291, section 2.5.5](https://tools.ietf.org/html/rfc4291#section-2.5.5)
 */
function v6to4(ip){
	function hexToDec(hexField){
		let h = 1*("0x"+hexField),
			b = h%256,
			a = (h-b)/256;
		return a+"."+b;
	}
	
	let ret;
	
	//IPv4-compatible IPV6 addresses (deprecated)
	//IPv4-mapped IPv6 addresses
	if(ret = /^::(?:ffff:)?([0-9.]+)$/ui.exec(ip)) return ret[1];
	if(ret = /^::(?:ffff:)?([^:]+):([^:]+)$/ui.exec(ip)) return hexToDec(ret[1]) + "." + hexToDec(ret[2]);
	
	return void 0;	//can't be converted to IPv4
}

/**
 * Normalizes an IPv4 address.
 * @private
 * @param {string} ip - IPv4 address.
 * @returns {string|undefined} - The normalized IPv4 address. Undefined if it's invalid.
 * @see [How to Obscure Any URL](http://www.pc-help.org/obscure.htm)
 * @see [RFC 3986, section 7.4](https://tools.ietf.org/html/rfc3986#section-7.4)
 * @see [Wikipedia: IPv4, Address representations](http://en.wikipedia.org/wiki/IPv4#Address_representations)
 */
function normalizeIPv4(ip){
	
	if(ip === void 0) return;
	ip = ""+ip;
	
	if(!(/^(?=(0x[0-9A-F]+|\d+))\1(?:\.(?=(0x[0-9A-F]+|\d+))\2){0,3}$/ui).test(ip))
		return;	//invalid IPv4 address
	
	//dword, octal, and hexadecimal numbers aren't valid, but they work in web browsers anyway, so we'll fix them
	let parts = ip.split("."),
		vals = [];
	for(let i=0; i<parts.length; i++){	//for each part
		let val;
		if((/^0x/ui).test(parts[i])){
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
	
}

/**
 * Normalizes an IPv6 address.
 * @private
 * @param {string} ip - IPv6 address.
 * @param {boolean} useMixedNotation - Mix hexadecimal and dot-decimal notations to represent IPv4-mapped IPv6 addresses. Default is true (recommended per [RFC 5952](https://tools.ietf.org/html/rfc5952#section-5)).
 * @returns {string|undefined} - Normalized IPv6 address. Undefined if it's invalid.
 * @see [RFC 4291, section 2.5.5](https://tools.ietf.org/html/rfc4291#section-2.5.5)
 * @see [RFC 5952, section 4](https://tools.ietf.org/html/rfc5952#section-4)
 * @see [RFC 5952, section 5](https://tools.ietf.org/html/rfc5952#section-5)
 */
function normalizeIPv6(ip, useMixedNotation = true){
	
	if(ip === void 0) return;
	ip = ""+ip;
	
	if(!(/^[0-9A-F:.]{2,}$/ui).test(ip))
		return;	//invalid IP address
	
	//split the IP at "::" (if it's used)
	ip = ip.toLowerCase().split("::");
	if(ip.length > 2)
		return;	//invalid IP; "::" used multiple times
	
	let fieldsLeft = ip[0].split(":"),
		compacted = ip.length === 2,
		fieldsRight = compacted ? ip[1].split(":") : [],
		resultLeft = [],
		resultRight = [],
		includesIPv4;
	
	if(fieldsLeft.length > 8 || (compacted && fieldsLeft.length + fieldsRight.length > 7))
		return;	//invalid IP; too many fields
	
	if(fieldsLeft[0] !== ""){
		//there are fields on the left side of "::", or "::" isn't used
		
		//for each field
		for(let i=0; i<fieldsLeft.length; i++){
			if((/^[0-9A-F]{1,4}$/ui).test(fieldsLeft[i])){
				//valid hex field
				
				resultLeft.push(fieldsLeft[i]);
			}
			else if(!compacted && i === 6 && fieldsLeft.length === 7 && /^\d+(\.\d+){3}$/u.test(fieldsLeft[i]) ){
				//last part of entire IP is a ver. 4 IP
				
				//remove leading zeroes from IPv4 fields (octals are not acceptable in an IPv6)
				fieldsLeft[i] = fieldsLeft[i].replace(/(^|\.)0+(?=\d)/ug, "$1");
				
				if(useMixedNotation && /^(0+:){5}(0+|ffff)$/u.test(resultLeft.join(":"))){
					//well-known prefix that distinguishes an embedded IPv4
					
					includesIPv4 = true;
					resultLeft.push(normalizeIPv4(fieldsLeft[i]));
				}
				else{
					//no recognized prefix for IPv4, or don't use mixed notation; convert it to IPv6
					
					//convert field to a pair of IPv6 fields
					fieldsLeft[i] = v4to6(normalizeIPv4(fieldsLeft[i]));
					resultLeft.push(/^[^:]+/u.exec(fieldsLeft[i])[0]);
					resultLeft.push(/:(.+)/u.exec(fieldsLeft[i])[1]);
				}
			}
			else{
				return;	//invalid field
			}
		}
	}
	
	if(compacted){
		//"::" is used
		
		if(fieldsRight[0] !== ""){
			//there are fields on the right side
			
			//for each field
			for(let i=0; i<fieldsRight.length; i++){
				if((/^[0-9A-F]{1,4}$/ui).test(fieldsRight[i])){
					//valid hex field
					
					resultRight.push(fieldsRight[i]);
				}
				else if(i === fieldsRight.length-1 && /^\d+(\.\d+){3}$/u.test(fieldsRight[i]) ){
					//last part of entire IP is a ver. 4 IP
					
					//remove leading zeroes from IPv4 fields (octals are not acceptable in an IPv6)
					fieldsRight[i] = fieldsRight[i].replace(/(^|\.)0+(?=\d)/ug, "$1");
					
					if(useMixedNotation && ( ( /^((0+:)*0+)?$/u.test(resultLeft.join(":")) && /^((0+:)*(0+|ffff))?$/u.test(resultRight.join(":")) ) ||
					 /^(0+:){5}(0+|ffff)$/u.test(resultLeft.join(":")) )){
						//well-known prefix that distinguishes an embedded IPv4
						
						includesIPv4 = true;
						resultRight.push(normalizeIPv4(fieldsRight[i]));
					}
					else{
						//no recognized prefix for IPv4, or don't use mixed notation; convert it to IPv6
						
						//convert field to a pair of IPv6 fields
						fieldsRight[i] = v4to6(normalizeIPv4(fieldsRight[i]));
						resultRight.push(/^[^:]+/u.exec(fieldsRight[i])[0]);
						resultRight.push(/:(.+)/u.exec(fieldsRight[i])[1]);
					}
				}
				else{
					return;	//invalid field
				}
			}
		}
		
		//replace "::" with the zeroes it represents
		let i = (includesIPv4 ? 7 : 8) - (resultLeft.length + resultRight.length);
		for(i; i>0; i--){
			resultLeft.push("0");
		}
	}
	
	if(resultLeft.length+resultRight.length < (includesIPv4 ? 7 : 8))
		return; //invalid IP; too few fields
	
	//combine the resulting fields
	ip = (resultLeft.concat(resultRight).join(":"));
	
	//if it includes an embedded IPv4, make sure the prefix ends with ffff instead of 0
	if(includesIPv4) ip = ip.replace(/^(0+:){6}/u, "0:0:0:0:0:ffff:");
	
	//remove leading zeros in fields
	ip = ip.replace(/(^|:)0+(?=[^:.])/ug, "$1");
	
	//replace longest run of multiple zeros with "::" shortcut
	let longest = "",
		rxp = /(?:^|:)((0:)+0)/ug,
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
		//This is a hexadecimal representation of an IPv4 address.
		
		//Convert the low-order 32 bits to mixed notation.
		ip = "::ffff:"+v4;
	}
	
	return ip;
	
}


/**
 * Converts an obscured path to a more readable one.
 * @private
 * @param {string} path
 * @returns {string}
 * @see [RFC 3986, section 3.3](https://tools.ietf.org/html/rfc3986#section-3.3)
 * @see [RFC 3986, section 2.4](https://tools.ietf.org/html/rfc3986#section-2.4)
 */
function normalizePath(path){
	
	if(path === void 0) return "";
	path = ""+path;
	if(path === "") return "";
	
	//decode percent encodings of unreserved characters: DIGIT ALPHA -._~
	path = path.replace(/%(2[DE]|3\d|[46][1-9A-F]|[57][0-9A]|5F|7E)/uig, function (match, p1){
		return String.fromCharCode(parseInt(p1, 16));
	});
	
	//make percent encodings upper case
	path = path.replace(/%(..)/uig, function (match, p1){
		return "%"+p1.toUpperCase();
	});
	
	return path;
	
}

/**
 * Removes dot-segments from a path.
 * @private
 * @param {string} path
 * @returns {string}
 * @see [RFC 3986, section 4.2](https://tools.ietf.org/html/rfc3986#section-4.2)
 * @see [RFC 3986, section 5.2.4](https://tools.ietf.org/html/rfc3986#section-5.2.4)
 */
function removeDotSegments(path){
	
	if(path === void 0) return "";
	path = ""+path;
	
	//if path is "", ".", or ".."
	if(/^\.{0,2}$/u.test(path))
		return "";
	
	//remove "./" and "../" segments from the beginning of the path
	path = path.replace(/^(\.\.?\/)+/u, "");
	
	//replace "/./" segments with "/"
	path = path.replace(/\/\.(\/|$)/ug, "/");
	
	let output = [];
	while(path){
		if(/^\/\.\.(\/|$)/u.test(path)){
			//path begins with "/../" or path === "/.."
			
			//remove the last segment from the output
			output.pop();
			
			//replace the matched segment with "/"
			path = path.replace(/^\/\.\.(\/|$)/u, "/");
		}
		else{
			//add the next segment to the output
			output.push(/^\/?[^\/]*/u.exec(path)[0]);
			
			//and remove it from path
			path = path.slice(output[output.length-1].length);
		}
	}
	
	return output.join("");
	
}


/**
 * Converts an obscured query string or fragment to a more readable one.
 * @private
 * @param {string} queryOrFragment - Query string or fragment (with or without their leading character).
 * @returns {string}
 * @see [RFC 3986, section 3.4](https://tools.ietf.org/html/rfc3986#section-3.4)
 * @see [RFC 3986, section 2.4](https://tools.ietf.org/html/rfc3986#section-2.4)
 */
function normalizeQueryOrFragment(queryOrFragment){
	
	if(queryOrFragment === void 0) return "";
	queryOrFragment = ""+queryOrFragment;
	
	//decode percent encodings of unreserved characters: DIGIT ALPHA -._~
	return queryOrFragment.replace(
		/%(2[DE]|3\d|[46][1-9A-F]|[57][0-9A]|5F|7E)/ig,
		(match, p1)=>String.fromCharCode(parseInt(p1, 16))
	);
	
}

/**
 * Parses a query string as a sequence of key/value pairs.
 * @alias module:URI.parseQuery
 * @param {string} query - Query string without the leading "?".
 * @param {string} pairSeparator - String separating the key/value pairs. Default is "&".
 * @param {string} keyValueSeparator - String separating a key from its value. Default is "=".
 * @returns {ParsedURI_query} - The normalized query and its key/value pairs.
 * @see [RFC 3986, section 3.4](https://tools.ietf.org/html/rfc3986#section-3.4)
 */
function parseQuery(query, pairSeparator = "&", keyValueSeparator = "="){

	const parsed = new SegmentedString(function (){
			let result = ""
			for(const pair of this.pairs){
				if(result) result += pairSeparator;
				result += encodeURIComponent(pair.key) + keyValueSeparator + encodeURIComponent(pair.value);
			}
			return result;
		},
		{
			pairs: []
		}
	);
	
	if(query === void 0) return parsed;
	query = ""+query;
	if(query === "") return parsed;
	
	
	query = normalizeQueryOrFragment(query);
	
	let pairs = query.split(pairSeparator),
		results = [];
	for(let i=0; i<pairs.length; i++){
		let pair = pairs[i].split(keyValueSeparator);
		if(pair[0] === ""){	//there is no key; remove it
			pairs.splice(i--,1);
			continue;
		}
		//if there is no separator, the value will be an empty string
		
		//add the key/value pair to the results
		results.push( { key: decodeURIComponent(pair[0]), value: decodeURIComponent(pair[1]||"") } );
	}
	
	parsed.pairs = results;
	
	return parsed;
	
}






/**
 * Checks if a registered name conforms to the DNS specification.
 * @private
 * @param {string} regName - A registered name.
 * @return {boolean}
 * @see [RFC 3696, section 2](https://datatracker.ietf.org/doc/html/rfc3696#section-2) - Restrictions on domain (DNS) names
 */
function isDNSDomain(regName){
	return (
		//not longer that 255 characters
		regName.length <= 255
		//valid labels between 1 and 63 characters
		&& /^(?=([a-z\d](?:[a-z\d-]{0,61}[a-z\d])?))\1(?:\.(?=([a-z\d](?:[a-z\d-]{0,61}[a-z\d])?))\2)*\.?$/ui.test(regName)
		//TLD is not all-numeric
		&& !(/(^|\.)\d+\.?$/u).test(regName)
	);
}

/**
 * Converts an obscured host to a more readable one. Only DNS domains or IPs are deemed valid.
 * @private
 * @param {string} host
 * @returns {ParsedURI_host|null} - Value is the host. Attributes include the host and its parts. Null if the host is invalid.
 */
function parseDNSHost(host){
	
	try{
		host = parseHost(host);
		if(host.ip || isDNSDomain(host.name)) return host;
	}catch(e){
		if(e instanceof URIError) return null;
		throw e;
	}
	
}

/**
 * Normalizes a single email address (mailbox) and splits it into its parts.
 * @alias module:URI.parseMailbox
 * @param {string} mailbox - email address or mailbox (mailbox example: "John Doe" <john.doe@example.com> )
 * @return {object} - Object containing the mailbox and its parts. Null if it's invalid.
 *   {string} .full - If there is a display name: "display name" <local@domain>
 *                    If there isn't: local@domain
 *   {string} .simple - local@domain
 *   {string} .displayName - Display name.
 *   {string} .localPart - Local part of the address.
 *   {string} .domain - Domain part of the address. Only DNS domains or IPs are deemed valid.
 * 
 * Does not parse groups (e.g., a distribution list).
 * Unfolds whitespace and removes comments.
 * Does not consider the 998 character limit per line.
 * See: RFC 5322   https://tools.ietf.org/html/rfc5322
 *      RFC 5322 Errata   https://www.rfc-editor.org/errata/eid3135
 *      RFC 5321   https://tools.ietf.org/html/rfc5321#section-4.1.2
 *                 https://tools.ietf.org/html/rfc5321#section-2.3.4
 *                 https://tools.ietf.org/html/rfc5321#section-4.5.3.1
 *      Wikipedia: Email address   https://en.wikipedia.org/wiki/Email_address
 */
function parseMailbox(mailbox){
	
	if(mailbox === void 0) return null;
	mailbox = ""+mailbox;
	
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
	
	const rxp_wsp = "[\\t ]",
		rxp_fws = "(?:(?:"+rxp_wsp+"*\\r?\\n)?"+rxp_wsp+"+)",
		rxp_atext = "[!#$%&'*+\\-/0-9=?A-Z^_`a-z{|}~]",
		rxp_qtext = "[!#$%&'()*+,\\-./0-9:;<=>?@A-Z[\\]^_`a-z{|}~]",
		//rxp_quotedPair = "\\\\[\\t !\"#$%&'()*+,\\-./0-9:;<=>?@A-Z[\\\\\\]^_`a-z{|}~]",
		rxp_quotedPair = "\\\\[\\t !-~]",
		rxp_qcontent = "(?:"+rxp_qtext+"|"+rxp_quotedPair+")",
		
		//these may be surrounded by CFWS
		rxpAtom = "(?:"+rxp_atext+"+)",
		rxpDotAtom = "(?:"+rxp_atext+"+(?:\\."+rxp_atext+"+)*)",
		rxpQuotedString = "(?:\"(?:(?:"+rxp_fws+"?"+rxp_qcontent+"+)+"+rxp_fws+"?|"+rxp_fws+")\")";
		
		/* local-part = dot-atom / quoted-string
		   domain = dot-atom / domain-literal
		   addr-spec = local-part "@" domain   //no CFWS allowed around the "@"
		   display-name = 1*( atom / quoted-string )
		   name-addr = [display-name] [CFWS] "<" addr-spec ">" [CFWS]
		   mailbox = name-addr / addr-spec
		*/
	
	function newRxp(rxp){ return new RegExp("^"+rxp, "i"); }
	
	const rxp_redundantPairs = new RegExp("\\\\("+rxp_qtext+")", "ig");
	
	let tokens = [];
	
	//parse tokens
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
			else if( (m = /^\[([a-z0-9\-.:]+)\]/i.exec(mailbox)) && (trimmed = parseDNSHost(m[0]) || parseDNSHost(m[1])) ){
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
	
	//get the parts
	{
		
		const tempTokens = [];
		let angleBrackets;
		
		function minimizeLocalPart(localPart){
			if(localPart.type === "quoted-string"){
				//remove redundant pairs from the quoted string
				const quoteContent = localPart.value.slice(1,-1).replace(rxp_redundantPairs, "$1");
				
				if(newRxp(rxpDotAtom+"$").test(quoteContent)){
					//quotes are unnecessary since their content is a dot-atom
					return quoteContent;
				}
				return `"${quoteContent}"`;
			}
			return localPart.value;
		}
		
		if(!tokens.length) return null;
		
		//get the display name (optional) and local part
		while(true){
			
			if(tokens[0].type === "dot-atom"){
				parts.localPart = tokens[0].value;
				tokens.shift();
			}
			else if(parts.displayName === void 0){
				while(tokens.length && (tokens[0].type === "quoted-string" || tokens[0].type === "atom" || tokens[0].type === "wsp")){
					tempTokens.push(tokens[0]);
					tokens.shift();
				}
				if(!tokens.length) return null;
				
				if(tokens[0].value === "<"){
					//tempTokens is the display name
					
					let name = "", wsp = "";
					while(tempTokens.length){
						let type = tempTokens[0].type,
							val = tempTokens[0].value;
						tempTokens.shift();
						
						if(type === "wsp"){
							if(!name) continue;
							wsp += val;
						}
						else{
							name += wsp;
							wsp = "";
							
							if(type === "quoted-string"){
								//remove the quotes
								val = val.slice(1, -1);
							}
							
							name += val;
						}
					}
					//unescape characters
					name = name.replace(/\\(.)/g, "$1");
					//escape backslashes and double quotes
					name = name.replace(/([\\"])/g, "\\$1");
					if(!(new RegExp(`^${rxp_atext}*$`)).test(name)){
						//the name includes characters other than atext; add outer quotes
						name = `"${name}"`;
					}
					
					parts.displayName = name;
					
					angleBrackets = true;
					tokens.shift();
					while(tokens.length && tokens[0].type === "wsp"){
						tokens.shift();
					}
					
					continue;
				}
				else if(tokens[0].value === "@"){
					//tempTokens is the local part
					
					if(tempTokens.length !== 1) return null;
					
					parts.localPart = minimizeLocalPart(tempTokens[0]);
				}
				else{
					return null;
				}
			}
			else if(tokens[0].type === "atom" || tokens[0].type === "dot-atom" || tokens[0].type === "quoted-string"){
				parts.localPart = minimizeLocalPart(tokens[0]);
				
				tokens.shift();
			}
			else{
				return null;
			}
			
			break;
		}
		parts.displayName = parts.displayName || "";
		parts.displayName = parts.displayName.replace(/\t/g, " ").replace(/ {2,}/g, " ").replace(/^("?) | {2,}| ("?)$/g, "$1$2");
		
		if(tokens[0].value !== "@") return null;
		tokens.shift();
		if(!tokens.length) return null;
		
		//get the domain
		{
			let host;
			if(tokens[0].type === "domain-literal"){
				if(tokens[0].value.length > 255) return null;	//too long
				parts.domain = tokens[0].value;
				tokens.shift();
			}
			else if( (tokens[0].type === "atom" || tokens[0].type === "dot-atom") && (host = parseDNSHost(tokens[0].value)) ){
				if(host.ip && host.ip.v4){
					tokens[0].value = "[" + host.ip.v4 + "]";	//IPv4 domain-literal
				}
				else{
					tokens[0].value = host.name;
				}
				if(tokens[0].value.length > 255) return null;	//too long
				parts.domain = tokens[0].value;
				tokens.shift();
			}
			else{
				return null;
			}
		}
		
		while(tokens.length && tokens[0].type === "wsp"){
			tokens.shift();
		}
		if(angleBrackets){
			if(!tokens.length || tokens[0].value !== ">") return null;
			tokens.shift();
			while(tokens.length && tokens[0].type === "wsp"){
				tokens.shift();
			}
		}
		if(tokens.length) return null;	//extraneous characters
		
		parts.simple = parts.localPart+"@"+parts.domain;
		
		parts.full = parts.displayName ? parts.displayName+" <"+parts.simple+">" : parts.simple;
		
	}
	
	return parts;
	
}








/* helper functions */

function defineNonEnumerableProperty(object, property, value){
	Object.defineProperty(object, property, {
		writable: true, enumerable: false, configurable: true,
		value: value
	});
}

/* module export */

export { URI as default, SegmentedString, isDNSDomain, parseMailbox };
