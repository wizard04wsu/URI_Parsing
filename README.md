# Parsing for URIs and Email Addresses

JavaScript functions for validating, normalizing, and parsing URIs and email addresses.

Scheme-specific processing can be easily added. Processing for *http*, *https*, and *mailto* schemes is already included.

This script does not support:
- internationalized domain names (IDNs)
- IPvFuture literal address formats
- obsolete syntaxes
- non-ASCII email addresses

This is a JavaScript module that exports: [`URI`](#uri) (default), [`URIError`](#urierror), [`SegmentedString`](#segmentedstring), `isDNSDomain`, `parseMailbox`

[Try it on JSFiddle](https://jsfiddle.net/wizard04/896dmhga/)

---

## Classes

### SegmentedString

Constructs a String object. When converted to a primitive value, the primitive string is generated by a custom function instead of using the String object's value.

## URI Parsing

### URI()

The **URI()** function validates and normalizes a URI, splits it into its parts, and does any [additional processing for defined schemes](#scheme-parsers).

Syntax:
> `URI(uri)`

Parameters:
- ***uri*** - (string) A URI.

Return value:
- A [SegmentedString](#SegmentedString) object representing the normalized URI and its parts. Throws a [URIError](#urierror) if the URI is invalid or does not conform to its scheme's syntax.


### URI.parse()

The static **URI.parse()** method validates and normalizes a URI and splits it into its generic parts. It does not do any scheme-specific processing.

Syntax:
> `URI.parse(uri)`

Parameters:
- ***uri*** - (string) A URI.

Return value:
- A [SegmentedString](#SegmentedString) object representing the normalized URI and its parts. Throws a [URIError](#urierror) if the URI is invalid.

| Property | Type | Description |
| --- | --- | --- |
| .**scheme** | string ||
| .**authority** | SegmentedString | Undefined if the URI does not include an authority. |
| .authority.**userinfo** | string ||
| .authority.**host** | SegmentedString | Either a registered name (empty string included) or an IP address. |
| .authority.host.**name** | string | A registered name. Undefined if the host is an IP address. |
| .authority.host.**ip** | SegmentedString | An IP address. (IPv4 is preferred, then IPv6 mixed, then IPv6 hex-only.) Undefined if the host is a registered name. |
| .authority.host.ip.**v4** | string | IPv4 address. Undefined if the host can't be represented as an IPv4 address. |
| .authority.host.ip.**v6mixed** | string | IPv6 address using mixed hexadecimal and dot-decimal notations to represent an IPv4-mapped IPv6 address. Undefined if the host can't be represented as an IPv4 address. |
| .authority.host.ip.**v6** | string | IPv6 address using only hexadecimal notation. |
| .authority.**port** | string ||
| .**path** | string ||
| .**query** | string ||
| .**fragment** | string ||


### URI.resolveRelativeReference()

The static URI.resolveRelativeReference() method determines the target URI of a relative reference.

Syntax:
> `URI.resolveRelativeReference(relativeReference, baseURI)`

Parameters:
- ***relativeReference*** - (string) A relative reference.
- ***baseURI*** - (string) The URI that the reference is relative to.

Return value:
- (string) The target URI.


### URI.parseHost()

The static URI.parseHost() method converts an obscured host to a more readable one, along with related representations.

Syntax:
> `URI.parseHost(host)`

Parameters:
- ***host*** - A string. A registered name or IP address.

Return value:
- A [SegmentedString](#SegmentedString) object representing the normalized host (IP address or registered name) and related representations. Throws a [URIError](#urierror) if it's not a valid host.

| Property | Type | Description |
| --- | --- | --- |
| .**name** | string | A registered name. Undefined if the host is an IP address. |
| .**ip** | SegmentedString | An IP address. (IPv4 is preferred, then IPv6 mixed, then IPv6 hex-only.) Undefined if the host is a registered name. |
| .ip.**v4** | string | IPv4 address. Undefined if the host can't be represented as an IPv4 address. |
| .ip.**v6mixed** | string | IPv6 address using mixed hexadecimal and dot-decimal notations to represent an IPv4-mapped IPv6 address. Undefined if the host can't be represented as an IPv4 address. |
| .ip.**v6** | string | IPv6 address using only hexadecimal notation. |


### URI.parseQuery()

The static URI.parseQuery() method parses a query string as a sequence of key/value pairs.

Syntax:
> `URI.parseQuery(query, pairSeparator, keyValueSeparator)`

Parameters:
- ***query*** - (string) Query string without the leading "?".
- ***pairSeparator*** - (string) String separating the key/value pairs. Default is `"&"`.
- ***keyValueSeparator*** - (string) String separating a key from its value. Default is `"="`.

Return value:
- A [SegmentedString](#SegmentedString) object representing the normalized query string and its key/value pairs.

| Property | Type | Description |
| --- | --- | --- |
| .**pairs** | array | An array of decoded key/value pairs. Each pair is an object with properties `key` and `value`. |


## Scheme-specific Parsers








- *.query* &nbsp; {array} &nbsp;&nbsp;&nbsp;&nbsp; - For the *http* and *https* schemes. An array of decoded name/value pairs (each pair is an object {name, value}).
- *.to*, *.cc*, *.bcc* &nbsp; {array} &nbsp;&nbsp;&nbsp;&nbsp; - For the *mailto* scheme. Arrays of valid email addresses.
- *.subject*, *.body* &nbsp; {string} &nbsp;&nbsp;&nbsp;&nbsp; - For the *mailto* scheme.
- *.headers* &nbsp; {array} &nbsp;&nbsp;&nbsp;&nbsp; - For the *mailto* scheme. An array of additional email headers (each header is an object {name, value}).

---








## Email Address and Mailbox Parsing

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
