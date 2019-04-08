
let test = [
	["", null],
	["a", null],
	["a:", "a:"],
	[":", null],
	["a:b", "a:b"],
	[":b", null],
	["a:/", "a:/"],
	["a:b/", "a:b/"],
	["a:/b", "a:/b"],
	["a://", "a://"],
	["a:b//", "a:b//"],
	["a://b", "a://b"],
	
	
	["http:", null],
	["http:b", null],
	["http:/", null],
	["http:b/", null],
	["http:/b", null],
	["http://", null],
	["http:b//", null],
	["http://b", "http://b/"],
	
	["http://foo.bar/baz/bop.htm?a=1&b=&c#lorem", "http://foo.bar/baz/bop.htm?a=1&b=&c#lorem"],
	
	
	["mailto:a@b", "mailto:a@b"],
	["mailto:%22foo%22@bar", "mailto:foo@bar"]
]
console.group("URI assertions");
for(let i=0, result; i<test.length; i++){
	result = ParseURI(test[i][0]);
	if(test[i][1] === null){
		console.assert(result === null, (i+1)+". "+test[i][0]+" --> "+(result && result.uri));
	}
	else{
		console.assert(result && result.uri === test[i][1], "Parse "+(i+1)+":  "+test[i][0]+" --> "+(result ? result.uri : "null"));
	}
	result = ParseURI.fixHyperlink(test[i][0]);
	if(result !== (test[i][1] || void 0)){
		console.log("Fix "+(i+1)+":  "+test[i][0]+" --> "+result);
	}
}
console.groupEnd();

console.groupCollapsed("Email addresses");
console.log(ParseURI.emailAddress("foo \"ba\\\"r \cd\"baz < foo@bar.baz >"));
console.log(ParseURI.emailAddress("\"f.oo\"@bar.baz"));
console.log(ParseURI.emailAddress("\"f oo\"@bar.baz"));
console.log(ParseURI.fixHyperlink("http://foo"));
console.groupEnd();
