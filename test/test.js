
function fixTest(ifHttp, ifNotHttp){
	return /^https?:$/.test(loc.protocol)?loc.protocol+"//"+(loc.username?loc.username:"")+(loc.password?":"+loc.password:"")+(loc.username|loc.password?"@":"")+loc.host+ifHttp:loc.protocol+ifNotHttp;
}

let loc = window.location,
	test = [
		["", null],
		["a", null, fixTest("/a","a")],
		["a:", "a:"],
		[":", null, fixTest("/:",":")],
		["a:b", "a:b"],
		[":b", null, fixTest("/:b",":b")],
		["a:/", "a:/"],
		["a:b/", "a:b/"],
		["a:/b", "a:/b"],
		["a://", "a://"],
		["a:b//", "a:b//"],
		["a://b", "a://b"],
		["a://b/c", "a://b/c"],
		["a://b//c", "a://b//c"],
		["a://b/c/d", "a://b/c/d"],
		["a://b../c/d", "a://b../c/d"],
		["a://b/../c/d", "a://b/../c/d"],
		["a:../b/c", "a:../b/c"],
		["a:/../b/c", "a:/../b/c"],
		["a://b/../../././.././../c/./d/../e", "a://b/../../././.././../c/./d/../e"],
		["../a", null, fixTest("/a","../a")],
		["a:?b=?#&c#d", null, "a:?b=?#&c%23d"],
		["Aa://Bb@Cc/Dd", "aa://Bb@cc/Dd"],
		["a:[", null, "a:%5B"],
		
		
		["http:", null],
		["http:b", null],
		["http:/", null],
		["http:b/", null],
		["http:/b", null],
		["http://", null],
		["http:b//", null],
		["http://b", "http://b/"],
		["http://b/c", "http://b/c"],
		["http://b//c", "http://b//c"],
		["http://b/c/d", "http://b/c/d"],
		["http://b..c/d", null],
		["http://b/..c/d", "http://b/..c/d"],
		["http:../b/c", null],
		["http:/../b/c", null],
		["http://b/../../././.././../c/./d/../e", "http://b/c/e"],
		
		["http://foo.bar/baz/bop.htm?a=1&b=&c&=d&=&&#lorem", "http://foo.bar/baz/bop.htm?a=1&b=&c#lorem"],
		
		
		["mailto:a@b", "mailto:a@b"],
		["mailto:%22foo%22@bar", "mailto:foo@bar"]
	];

console.group("URI parse assertions");
	for(let i=0, result; i<test.length; i++){
		result = ParseURI(test[i][0]);
		if(test[i][1] === null){
			console.assert(result === null, "Parse "+(i+1)+". "+test[i][0]+" --> "+(result && result.uri));
			if(result !== null) console.log(result);
		}
		else{
			console.assert(result && result.uri === test[i][1], "Parse "+(i+1)+":  "+test[i][0]+" --> "+(result ? result.uri : "null"));
			if(result && result.uri !== test[i][1]) console.log(result);
		}
	}
console.groupEnd();

console.groupCollapsed("URI parse objects");
	for(let i=0, result; i<test.length; i++){
		result = ParseURI(test[i][0]);
		console.log(test[i][0], result);
	}
console.groupEnd();

console.group("URI fix assertions");
	for(let i=0, result; i<test.length; i++){
		result = ParseURI.fixHyperlink(test[i][0]);
		if(test[i][2] === void 0) test[i][2] = test[i][1];
		if(test[i][2] === null){
			console.assert(result === null, "Fix "+(i+1)+". "+test[i][0]+" --> "+(result && result.uri));
			if(result !== null) console.log(result);
		}
		else{
			console.assert(result && result.uri === test[i][2], "Fix "+(i+1)+":  "+test[i][0]+" --> "+(result ? result.uri : "null"));
			if(result && result.uri !== test[i][2]) console.log(result);
		}
	}
console.groupEnd();

console.groupCollapsed("URI fix objects");
	for(let i=0, result; i<test.length; i++){
		result = ParseURI.fixHyperlink(test[i][0]);
		console.log(test[i][0], result);
	}
console.groupEnd();

console.groupCollapsed("Email addresses");
	console.log(ParseURI.emailAddress("foo \"ba\\\"r \cd\"baz < foo@bar.baz >"));
	console.log(ParseURI.emailAddress("\"f.oo\"@bar.baz"));
	console.log(ParseURI.emailAddress("\"f oo\"@bar.baz"));
	console.log(ParseURI.fixHyperlink("http://foo"));
console.groupEnd();
