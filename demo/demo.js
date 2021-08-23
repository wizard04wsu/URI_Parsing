import URI, {URIError, isDNSDomain, removeDotSegments} from "https://github.com/wizard04wsu/URI_Parsing/tree/dev/src/uri_parsing.mjs"

console.log(URI("https://www.google.com/search?q=javascript+is+cool&ie=UTF-8#footcnt"));