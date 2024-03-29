# Parsing for URIs and Email Addresses

JavaScript functions for validating, normalizing, and parsing URIs and email addresses.

Scheme-specific processing can be easily added. Processing for *http*, *https*, and *mailto* schemes is already included.

This script does not support:
- internationalized domain names (IDNs)
- IPvFuture literal address formats
- obsolete syntaxes
- non-ASCII email addresses

This is a JavaScript module that exports: [`URI`](#uri) (default), [`SegmentedString`](#segmentedstring), [`isDNSDomain`](#isdnsdomain), [`parseMailbox`](#parsemailbox)

[Try it on JSFiddle](https://jsfiddle.net/wizard04/evxog8r2/)

---

## Classes

### SegmentedString

The **SegmentedString** class extends the **String** class. When coercing an instance to a primitive string value, the value is generated by a custom function instead of using the object's inherent value.

Syntax:
> `new SegmentedString(toPrimitive, initialMembers)`

Parameters:
- ***toPrimitive*** - (function) This function is called when the object is being coerced into a primitive. Whatever it returns will be converted to a primitive string value.
- ***initialMembers*** - (object) Optional. The enumerable properties of this object are added to the new instance of SegmentedString.

---

## URI Parsing

### URI()

The **URI()** function validates and normalizes a URI, splits it into its parts, and does any [additional processing for defined schemes](#scheme-specific-parsers).

Syntax:
> `URI(uri)`

Parameters:
- ***uri*** - (string) A URI.

Return value:
- A [SegmentedString](#SegmentedString) object representing the normalized URI and its parts. Throws a URIError if the URI is invalid or does not conform to its scheme's syntax.


### URI.parse()

The static **URI.parse()** method validates and normalizes a URI and splits it into its generic parts. It does not do any scheme-specific processing.

Syntax:
> `URI.parse(uri)`

Parameters:
- ***uri*** - (string) A URI.

Return value:
- A [SegmentedString](#SegmentedString) object representing the normalized URI and its parts. Throws a URIError if the URI is invalid.

| Property | Type | Description |
| --- | --- | --- |
| .**scheme** | string ||
| .**authority** | SegmentedString | Undefined if the URI does not include an authority. |
| .authority.**userinfo** | string ||
| .authority.**host** | SegmentedString | An empty string, registered name, or an IP address. |
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

The static **URI.resolveRelativeReference()** method determines the target URI of a relative reference.

Syntax:
> `URI.resolveRelativeReference(relativeReference, baseURI)`

Parameters:
- ***relativeReference*** - (string) A relative reference.
- ***baseURI*** - (string) The URI that the reference is relative to.

Return value:
- (string) The target URI.


### URI.parseHost()

The static **URI.parseHost()** method converts an obscured host to a more readable one, along with related representations.

Syntax:
> `URI.parseHost(host)`

Parameters:
- ***host*** - (string) A registered name or IP address.

Return value:
- A [SegmentedString](#SegmentedString) object representing the normalized host (IP address or registered name) and related representations. Throws a URIError if it's not a valid host.

| Property | Type | Description |
| --- | --- | --- |
| .**name** | string | A registered name. Undefined if the host is an IP address. |
| .**ip** | SegmentedString | An IP address. (IPv4 is preferred, then IPv6 mixed, then IPv6 hex-only.) Undefined if the host is a registered name. |
| .ip.**v4** | string | IPv4 address. Undefined if the host can't be represented as an IPv4 address. |
| .ip.**v6mixed** | string | IPv6 address using mixed hexadecimal and dot-decimal notations to represent an IPv4-mapped IPv6 address. Undefined if the host can't be represented as an IPv4 address. |
| .ip.**v6** | string | IPv6 address using only hexadecimal notation. |


### URI.parseQuery()

The static **URI.parseQuery()** method parses a query string as a sequence of key/value pairs.

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

### URI.schemeParser

The name of each of this object's methods corresponds to a URI scheme. Each method takes a generically parsed URI of its scheme and further processes it.

Methods can be added to **URI.schemeParser** to handle any scheme. Methods are included for *[http](#urischemeparserhttp-and-urischemeparserhttps)*, *[https](#urischemeparserhttp-and-urischemeparserhttps)*, and *[mailto](#urischemeparsermailto)*.

### URI.schemeParser.http() and URI.schemeParser.https()

The static **URI.schemeParser.http()** and **URI.schemeParser.https()** methods continue parsing and normalizing an *http* or *https* URI, respectively, according to the scheme's syntax.

Syntax:
> `URI.schemeParser.http(parsed)`
> `URI.schemeParser.https(parsed)`

Parameters:
- ***parsed*** - ([SegmentedString](#SegmentedString)) The generically parsed URI. This object will be modified.

Return value:
- Nothing is returned. The ***parsed*** parameter is modified, adding the following properties. Throws a URIError if the URI does not conform to the scheme.

| Property | Type | Description |
| --- | --- | --- |
| .query.**pairs** | array | An array of decoded key/value pairs from the query string. Each pair is an object with properties `key` and `value`. |

### URI.schemeParser.mailto()

The static **URI.schemeParser.mailto()** method continues parsing and normalizing a *mailto* URI according to the scheme's syntax. Email addresses are validated and normalized using the [parseMailbox](#parsemailbox) function. Invalid email addresses are simply left out.

Syntax:
> `URI.schemeParser.mailto(parsed)`

Parameters:
- ***parsed*** - ([SegmentedString](#SegmentedString)) The generically parsed *mailto*-schemed URI. This object will be modified.

Return value:
- Nothing is returned. The ***parsed*** parameter is modified, adding the following properties. Throws a URIError if the URI does not conform to the scheme.

| Property | Type | Description |
| --- | --- | --- |
| .query.**pairs** | array | An array of decoded key/value pairs from the query string. Each pair is an object with properties `key` and `value`. |
| .**to** | array | An array of valid and normalized email addresses. |
| .**cc** | array | An array of valid and normalized email addresses. |
| .**bcc** | array | An array of valid and normalized email addresses. |
| .**subject** | string ||
| .**body** | string ||
| .**headers** | array | An array of decoded key/value pairs for any additional email headers in the URI. Each header is an object with properties `name` and `value`. |

---

## Miscellaneous functions

### isDNSDomain()

The **isDNSDomain()** function determines if a host name conforms to the domain name system (DNS) specifications. (I.e., if it can be used as a domain name.)

Syntax:
> `isDNSDomain(host)`

Parameters:
- ***host*** - (string)

Return value:
- (boolean)

### parseMailbox()

The **parseMailbox()** function validates and normalizes a mailbox or email address and splits it into its parts.

Syntax:
> `parseMailbox(mailbox)`

Parameters:
- ***mailbox*** - (string) An email address (e.g., *john.doe@example.com*) or mailbox (e.g., *"John Doe" \<john.doe@example.com\>*).

Return value:
- An object containing the following properties. Returns `null` if the mailbox is invalid.

| Property | Type | Description |
| --- | --- | --- |
| .**full** | string | If there is a display name: *"display name" \<local@domain\>*. If there isn't: *local@domain*. |
| .**simple** | string | The email address: *local@domain*. |
| .**displayName** | string | The display name or an empty string. |
| .**localPart** | string | The local part of the address (to the left of "@"). |
| .**domain** | string | The domain part of the address. Only DNS domains and IP addresses are deemed valid. |

---

## General References

- RFC 3986 "Uniform Resource Identifier (URI): Generic Syntax" &nbsp; https://tools.ietf.org/html/rfc3986
- How to Obscure Any URL &nbsp; http://www.pc-help.org/obscure.htm
- RFC 6068 "The 'mailto' URI Scheme" &nbsp; https://tools.ietf.org/html/rfc6068
- Wikipedia: Email address &nbsp; https://en.wikipedia.org/wiki/Email_address
- RFC 5322 "Internet Message Format" &nbsp; https://tools.ietf.org/html/rfc5322
- RFC 5321 "Simple Mail Transfer Protocol" &nbsp; https://tools.ietf.org/html/rfc5321#section-4.1.2
- RFC 5234 "Augmented BNF for Syntax Specifications: ABNF" &nbsp; https://tools.ietf.org/html/rfc5234#appendix-B.1
