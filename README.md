# URI Parsing

JavaScript functions for validating, normalizing, and parsing URIs and email addresses.

This script does not support:
- internationalized domain names (IDNs)
- non-ASCII email addresses
- IPvFuture literal address formats
- obsolete syntaxes

This is a JavaScript module. It can be imported into your script like so: `import URI, {URIError, isDNSDomain, removeDotSegments} from "uri_parsing.mjs"`

[Try it on JSFiddle](https://jsfiddle.net/wizard04/896dmhga/45/)

---

## URIs

**<samp style="background-color:transparent">URI(*uri*)</samp>**

Validates and normalizes a URI, splits it into its parts, and does any [additional processing for defined schemes](#schemeParser).

Parameters:
- *uri* &nbsp; {string}

Returns an object containing the URI and its parts. Throws a [URIError](#urierror) if the URI is invalid.


**<samp style="background-color:transparent">URI.parse(*uri*)</samp>**

Normalizes a URI and splits it into its generic parts.

Parameters:
- *uri* &nbsp; {string}

Returns an object containing the URI's generic parts. The object and the objects it contains have overridden `toString` methods. Throws a [URIError](#urierror) if the URI is invalid.
- *.scheme* &nbsp; {string}
- *.authority* &nbsp; {object}
    - *.userinfo* &nbsp; {string}
    - *.host* &nbsp; {object}
        - *.name* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; - A registered name.
        - *.ip* &nbsp; {object} &nbsp;&nbsp;&nbsp;&nbsp; - An IP address. (IPv4 is preferred, then IPv6 mixed, then IPv6 hex-only.)
            - *.v4* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; - IPv4 address.
            - *.v6mixed* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; - IPv6 address using mixed hexadecimal and dot-decimal notations to represent an IPv4-mapped IPv6 address.
            - *.v6* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; - IPv6 address using only hexadecimal notation.
    - *.port* &nbsp; {string}
- *.path* &nbsp; {string}
- *.query* &nbsp; {string}
- *.fragment* &nbsp; {string}


**<samp style="background-color:transparent">URI.resolveRelativeURI(*relativeReference*, *baseURI*)</samp>**

Determines the target URI of a relative reference.

Parameters:
- *relativeReference* &nbsp; {string}
- *baseURI* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; - The URI that the reference is relative to.

Returns the target URI as a string.


**<samp style="background-color:transparent">URI.parseHost(*host*)</samp>**

Converts an obscured host to a more readable one, along with related representations.

Parameters:
- *host* &nbsp; {string}

Returns an object containing the normalized host (IP address or registered name) and related representations. The object and the objects it contains have overridden `toString` methods. Throws an error if it's not a valid host.
- *.name* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; - A registered name.
- *.ip* &nbsp; {object} &nbsp;&nbsp;&nbsp;&nbsp; - An IP address. (IPv4 is preferred, then IPv6 mixed, then IPv6 hex-only.)
    - *.v4* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; - IPv4 address.
    - *.v6mixed* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; - IPv6 address using mixed hexadecimal and dot-decimal notations to represent an IPv4-mapped IPv6 address.
    - *.v6* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; - IPv6 address using only hexadecimal notation.


**<samp style="background-color:transparent">URI.parseQuery(*query*, *pairSeparator*, *keyValueSeparator*)</samp>**

Parses a query string as a sequence of key/value pairs.

Parameters:
- *query* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; - Query string without the leading "?".
- *pairSeparator* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; - String separating the key/value pairs. Default is `"&"`.
- *keyValueSeparator* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; - String separating a key from its value. Default is `"="`.

Returns the normalized query and its key/value pairs. The object has an overridden `toString` method.
- *.pairs* &nbsp; {array} &nbsp;&nbsp;&nbsp;&nbsp; - Array of decoded key/value pairs. Each pair is an object with properties `key` and `value`.


### Scheme-specific Parsers








- *.query* &nbsp; {array} &nbsp;&nbsp;&nbsp;&nbsp; - For the *http* and *https* schemes. An array of decoded name/value pairs (each pair is an object {name, value}).
- *.to*, *.cc*, *.bcc* &nbsp; {array} &nbsp;&nbsp;&nbsp;&nbsp; - For the *mailto* scheme. Arrays of valid email addresses.
- *.subject*, *.body* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; - For the *mailto* scheme.
- *.headers* &nbsp; {array} &nbsp;&nbsp;&nbsp;&nbsp; - For the *mailto* scheme. An array of additional email headers (each header is an object {name, value}).

---








## Email Addresses

**<samp style="background-color:transparent">ParseURI.emailAddress(*address*)</samp>**

Normalizes a single email address (or mailbox) and splits it into its parts.

Parameters:
- *address* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; - Email address or mailbox (mailbox example: <samp>"John Doe" &lt;john.doe@example.com&gt;</samp> ).

Returns an object containing the normalized email address or mailbox and its parts. May contain these members:
- *.full* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; - If there is a display name: <samp>"display name" &lt;local@domain&gt;</samp>. If there isn't: <samp>local@domain</samp>.
- *.simple* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; - <samp>local@domain</samp>
- *.displayName* &nbsp; {string}
- *.localPart* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; - Local part of the address (to the left of "@").
- *.domain* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; - Domain part of the address. Only DNS domains and IP addresses are deemed valid.

---

## General References

- RFC 3986 "Uniform Resource Identifier (URI): Generic Syntax" &nbsp; https://tools.ietf.org/html/rfc3986
- How to Obscure Any URL &nbsp; http://www.pc-help.org/obscure.htm
- RFC 6068 "The 'mailto' URI Scheme" &nbsp; https://tools.ietf.org/html/rfc6068
- Wikipedia: Email address &nbsp; https://en.wikipedia.org/wiki/Email_address
- RFC 5322 "Internet Message Format" &nbsp; https://tools.ietf.org/html/rfc5322
- RFC 5321 "Simple Mail Transfer Protocol" &nbsp; https://tools.ietf.org/html/rfc5321#section-4.1.2
- RFC 5234 "Augmented BNF for Syntax Specifications: ABNF" &nbsp; https://tools.ietf.org/html/rfc5234#appendix-B.1
