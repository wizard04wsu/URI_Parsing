import URI, {isDNSDomain, fixHyperlink} from "../src/uri_parsing.mjs";

function fixTest(ifHttp, ifNotHttp){
	const loc = window.location;
	return /^https?:$/.test(loc.protocol)?loc.protocol+"//"+(loc.username?loc.username:"")+(loc.password?":"+loc.password:"")+(loc.username|loc.password?"@":"")+loc.host+ifHttp:loc.protocol+ifNotHttp;
}

const test = [
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
		
		["http://foo.bar/baz/bop.htm?a=1&b=&c&=d&=&&#lorem", "http://foo.bar/baz/bop.htm?a=1&b=&c=#lorem"],
		
		
		["mailto:foo@bar", "mailto:foo@bar"],
		["mailto:%22foo%22@bar", "mailto:foo@bar"],
		["mailto:%3C%20%22foo%22@bar%20%3E", "mailto:foo@bar"],
		["mailto:John%20%22The%20Dude%22%20Doe%3Cjd@example.com%3E", "mailto:John%20%22The%20Dude%22%20Doe%20%3Cjd@example.com%3E"],
		["mailto:foo%20@bar", null],
		["mailto:foo@%20bar", null]
	];

console.group("URI parsing");
	for(let i=0; i<test.length; i++){
		const testSubject = (i+1)+". "+test[i][0]+"\n   ";
		try{
			const result = URI(test[i][0]);
			if(result.toString() === test[i][1]){
				console.log(testSubject, result);
			}
			else{
				console.assert(false, testSubject, result);
			}
		}catch(e){
			if(test[i][1] === null){
				console.log(testSubject, "(invalid)");
			}
			else{
				console.assert(false, testSubject, "Error: "+e.message);
				throw e;
			}
		}
	}
console.groupEnd();

/*console.group("URI fix assertions");
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
console.groupEnd();*/
