# URI Parsing

JavaScript functions for validating, normalizing, and parsing URIs and email addresses.

This script does not support:
- internationalized domain names (IDNs)
- non-ASCII email addresses
- IPvFuture literal address formats
- obsolete syntaxes

---

## URIs

**<samp style="background-color:transparent">ParseURI(*uri*)</samp>**

Validates and normalizes a URI, then splits it into its parts. Additional processing is done for *http*, *https*, and *mailto* URIs.

Parameters:
- *uri* &nbsp; {string}

Returns an object containing the following members (if found in the URI). Null if the URI is invalid.
- *.uri* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; The normalized URI.
- *.scheme* &nbsp; {string}
- *.authority* &nbsp; {object} &nbsp;&nbsp;&nbsp;&nbsp; May contain these members:
    - *.toString()* &nbsp; {function} &nbsp;&nbsp;&nbsp;&nbsp; Overrides the inherited function. Returns the authority as a string.
    - *.userinfo* &nbsp; {string}
    - *.host* &nbsp; {object} &nbsp;&nbsp;&nbsp;&nbsp; May contain these members:
        - *.toString()* &nbsp; {function} &nbsp;&nbsp;&nbsp;&nbsp; Overrides the inherited function. Returns the host as a string.
        - *.labels* &nbsp; {array} &nbsp;&nbsp;&nbsp;&nbsp; For the *http* and *https* schemes. Array of labels within a DNS domain.
        - *.ip* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; IP address (IPv4 if possible).
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

## DNS Domains

**<samp style="background-color:transparent">ParseURI.domain(*host*, *useMixedNotation*)</samp>**

Converts an obscured host to a more readable one. Only DNS domains or IP addresses are deemed valid.

Parameters:
- *host* &nbsp; {string}
- *useMixedNotation* &nbsp; {boolean} &nbsp;&nbsp;&nbsp;&nbsp; Mix hexadecimal and dot-decimal notations to represent IPv4-mapped IPv6 addresses. Default is true.

Returns an object containing the normalized host and its parts. Null if the host is invalid. May contain these members:
- *.host* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; The normalized DNS domain or IP.
- *.ip* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; IP address (IPv4 if possible).
- *.ipv4* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; IPv4 version of the IP address.
- *.ipv6* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; IPv6 version of the IP address.
- *.labels* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; Array of labels within a DNS domain.

## Paths

**<samp style="background-color:transparent">ParseURI.resolveRelativePath(*path*)</samp>**

Minimizes a path by resolving or removing "." and ".." segments.

Parameters:
- *path* &nbsp; {string}
- *isPartial* &nbsp; {boolean} &nbsp;&nbsp;&nbsp;&nbsp; Pass `true` if the path is relative to the current document.

Returns a string containing the minimized path.

## Query Strings

**<samp style="background-color:transparent">ParseURI.query(*queryString*)</samp>**

Normalizes a query string, then splits it into its parts. This expects a query string formatted as if for the *http* scheme.

Parameters:
- *queryString* &nbsp; {string}

Returns an array of decoded name/value pairs (each pair is an object {name, value}). The array's `toString()` method is overridden to return the normalized query as a string.

## Email Addresses

**<samp style="background-color:transparent">ParseURI.emailAddress(*address*)</samp>**

Normalizes a single email address (or mailbox) and splits it into its parts.

Parameters:
- *address* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; Email address or mailbox (mailbox example: <samp>"John Doe" &lt;john.doe@example.com&gt;</samp> ).

Returns an object containing the normalized email address or mailbox and its parts. May contain these members:
- *.full* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; If there is a display name: <samp>"display name" &lt;local@domain&gt;</samp>. If there isn't: <samp>local@domain</samp>.
- *.simple* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; <samp>local@domain</samp>
- *.displayName* &nbsp; {string}
- *.unescapedDisplayName* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; Display name with any quoted strings unescaped. This is what you would show to a user.
- *.localPart* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; Local part of the address (to the left of "@").
- *.domain* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; Domain part of the address. Only DNS domains and IP addresses are deemed valid.

## Hyperlinks

**<samp style="background-color:transparent">ParseURI.fixHyperlink(*href*)</samp>**

Attempts to fix a URI if it's invalid. It refers to the current document's location if the scheme or authority is missing, and encodes invalid characters. This method makes assumptions&mdash;the resulting URI might not be exactly what was intended.

Parameters:
- *href* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; URI or relative reference to analyze and fix.

Returns an object containing the fixed URI and any relative reference versions. Null if it can't be fixed. May contain these members:
- *.uri* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; Fixed and normalized URI.
- *.networkPathReference* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; Relative reference starting with "//" (relative to the scheme).
- *.absolutePathReference* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; Relative reference starting with a single "/" (relative to the path root).
- *.relativePathReference* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; Relative reference not starting with a "/" (relative to the current document).
- *.sameDocumentReference* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; The fragment, including the "#".

---

## General References

- RFC 3986 "Uniform Resource Identifier (URI): Generic Syntax" &nbsp; https://tools.ietf.org/html/rfc3986
- How to Obscure Any URL &nbsp; http://www.pc-help.org/obscure.htm
- RFC 6068 "The 'mailto' URI Scheme" &nbsp; https://tools.ietf.org/html/rfc6068
- Wikipedia: Email address &nbsp; https://en.wikipedia.org/wiki/Email_address
- RFC 5322 "Internet Message Format" &nbsp; https://tools.ietf.org/html/rfc5322
- RFC 5321 "Simple Mail Transfer Protocol" &nbsp; https://tools.ietf.org/html/rfc5321#section-4.1.2
- RFC 5234 "Augmented BNF for Syntax Specifications: ABNF" &nbsp; https://tools.ietf.org/html/rfc5234#appendix-B.1
