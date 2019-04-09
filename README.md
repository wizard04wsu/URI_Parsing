# URI Parsing

JavaScript functions for validating, parsing, and normalizing URIs and email addresses.

This script does not support:
- internationalized domain names (IDNs)
- non-ASCII email addresses
- IPvFuture literal address formats
- obsolete syntaxes

---

**<samp style="background-color:transparent">ParseURI(*uri*)</samp>**

Validates and normalizes a URI, then splits it into its parts. Additional processing is done for *http*, *https*, and *mailto* URIs.

Parameters:
- *uri* &nbsp; {string}

Returns an object containing these members (if found in the URI). Null if the URI is invalid.
- *.uri* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; The normalized URI.
- *.scheme* &nbsp; {string}
- *.authority* &nbsp; {object} &nbsp;&nbsp;&nbsp;&nbsp; May contain these members:
    - *.toString()* &nbsp; {function} &nbsp;&nbsp;&nbsp;&nbsp; Overrides the inherited function. Returns the authority as a string.
    - *.userinfo* &nbsp; {string}
    - *.host* &nbsp; {object} &nbsp;&nbsp;&nbsp;&nbsp; May contain these members:
        - *.toString()* &nbsp; {function} &nbsp;&nbsp;&nbsp;&nbsp; Overrides the inherited function. Returns the host as a string.
        - *.labels* &nbsp; {array} &nbsp;&nbsp;&nbsp;&nbsp; For the *http* and *https* schemes. Array of labels within a domain name. Undefined if it's an IP address.
        - *.ip* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; IP address (IPv4 is possible).
        - *.ipv4* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; IPv4 version of the IP address.
        - *.ipv6* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; IPv6 version of the IP address.
    - *.port* &nbsp; {string}
- *.path* &nbsp; {string}
- *.query* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; For schemes other than *http*, *https*, and *mailto*.
- *.query* &nbsp; {array} &nbsp;&nbsp;&nbsp;&nbsp; For the *http* and *https* schemes. An array of decoded name/value pairs (each pair is an object {name, value}).
    - *.toString()* &nbsp; {function} &nbsp;&nbsp;&nbsp;&nbsp; Overrides the inherited function. Returns the query as a string.
- *.fragment* &nbsp; {string}
- *.to*, *.cc*, *.bcc* &nbsp; {array} &nbsp;&nbsp;&nbsp;&nbsp; For the *mailto* scheme. Arrays of valid email addresses.
- *.subject*, *.body* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; For the *mailto* scheme.
- *.headers* &nbsp; {array} &nbsp;&nbsp;&nbsp;&nbsp; For the *mailto* scheme. An array of additional email headers (each header is an object {name, value}).







**Normalizing functions for parts of a URI**

- **`normalizeHost(host)`**  
  Converts an [obscured host](http://www.pc-help.org/obscure.htm) to a more readable one.  
  Returns `null` if it's not a valid host.

- **`normalizeDNSHost(host[, requireMultipleLabels])`**  
  Converts an obscured host to a more readable one; only accepts IP addresses and DNS domain names as valid.
  
  - `requireMultipleLabels` (optional)  
    Specify whether a domain must consist of multiple labels (e.g., if true, "localhost" would be considered invalid).
  
  Returns `null` if it's not a valid host.

- **`normalizeIPv4(ip)`**  
  Converts an obscured IPv4 to a more readable one.  
  Returns `null` if it's not a valid IPv4.

- **`normalizeIPv6(ip)`**  
  Converts an obscured IPv6 to a more readable one.  
  Returns `null` if it's not a valid IPv6.

- **`normalizePath(path)`**  
  Converts an obscured path to a more readable one.

=====

**URI and email parsing functions**

Output of all parsing functions is normalized.

- **`parseURI(uri)`**	 
  Splits a URI into its parts.  
  Returns an object including the following, or `null` if the URI is not valid.
  - `uri` entire normalized URI
  - `scheme`
  - `authority` entire authority (empty string if there isn't one)
  - `userinfo`
  - `host`
  - `port`
  - `path`
  - `query`
  - `fragment`

- **`parseHttp(uri[, requireMultipleLabels])`**	 
  Splits an http or https scheme URI into its parts.
  
  - `requireMultipleLabels` (optional)  
    Specify whether a domain must consist of multiple labels (e.g., if true, "localhost" would be considered invalid).
  
  Returns an object including the following, or `null` if the URI is not valid.
  - `uri` entire normalized URI
  - `scheme`
  - `authority` entire authority
  - `userinfo`
  - `host`
  - `port`
  - `path`
  - `query`
  - `fragment`

- **`parseMailto(uri)`**  
  Splits a mailto scheme URI into its parts. Invalid email addresses are discarded.  
  Returns an object including the following, or `null` if the URI is not valid or if there is no valid destination.
  - `uri` entire normalized URI
  - `scheme` *mailto*
  - `to` array of valid email addresses
  - `cc` array of valid email addresses
  - `bcc` array of valid email addresses
  - `subject`
  - `body`
  - `headers` array of other headers besides the above (each header is an object `{name, value}`)

- **`parseQuery(queryString[, name])`**  
  Parses a query string as a sequence of name/value pairs.  
  If `name` is not specified, returns an array of name/value pairs (each pair is an object `{name, value}`).  
  If `name` is specified, returns an array of values with that name.

- **`parseEmailAddress(address)`**  
  Splits a single email address into its parts. Unfolds whitespace and removes any comments. Obsolete syntax is not supported.  
  Returns an object including the following, or `null` if the address is not valid.
  - `display` display name
  - `local` local part of the address
  - `domain` domain part of the address
  - `unrecognizedDomain` true if the domain is something other than a DNS domain, IPv4, IPv4 literal, or IPv6 literal
  - `simple` *local@domain*
  - `full` *"display name" \<local@domain\>* if there is a display name, or *local@domain* if not
  - `stripped` same address that was passed to the function, but unfolded and without any comments

=====

**Miscellaneous functions**

- **`fixHyperlink(str[, allowedSchemes[, domain]])`**  
  Attempts to fix a URI (if needed) and normalizes it. If the string does not have a scheme, it will be assumed that it's meant to be that of the current page (e.g., if `str` is a relative URL).
  
  - `allowedSchemes` (optional)  
    A string or array of strings listing accepted schemes; *http*, *https*, and *mailto* by default if none are specified.
  - `domain` (optional)  
    Host name (and optionally port) to use if an http/https URI is relative; current page's domain by default.
  
  Returns `null` if it can't be fixed or if `allowedSchemes` is invalid.

=====

**General references**

- RFC 3986 "Uniform Resource Identifier (URI): Generic Syntax" http://tools.ietf.org/html/rfc3986
- How to Obscure Any URL http://www.pc-help.org/obscure.htm
- RFC 6068 "The 'mailto' URI Scheme" http://tools.ietf.org/html/rfc6068
- RFC 5322 "Internet Message Format" http://tools.ietf.org/html/rfc5322
