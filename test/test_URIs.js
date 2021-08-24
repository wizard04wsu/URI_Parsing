import URI, {URIError, defineStringPrimitive, isDNSDomain, parseMailbox} from "../src/uri_parsing.mjs";

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
		//mailto:"John \"The Dude\" Doe"<jd@example.com>
		["mailto:%20%22John%20%5C%22The%20Dude%5C%22%20Doe%22%3Cjd@example.com%3E%20", "mailto:%22John%20%5C%22The%20Dude%5C%22%20Doe%22%20%3Cjd@example.com%3E"],
		["mailto:foo%20@bar", null],
		["mailto:foo@%20bar", null],
		["mailto:a%22%5Cb%22c%3Cfoo@bar%3E", "mailto:abc%20%3Cfoo@bar%3E"]
	];

console.group("URI parsing");
	for(let i=0; i<test.length; i++){
		const testSubject = (i+1)+". "+test[i][0];
		try{
			const result = URI(test[i][0]);
			if(result.toString() === test[i][1]){
				console.groupCollapsed(testSubject);
				console.log("Expected:\n   ", test[i][1]===null ? "(invalid)" : test[i][1]);
				console.log("Result:\n   ", result.toString(), "\n   ", result);
			}
			else{
				console.group(testSubject);
				console.log("Expected:\n   ", test[i][1]===null ? "(invalid)" : test[i][1]);
				console.assert(false, "\nResult:\n   ", result.toString(), "\n   ", result);
			}
		}catch(e){
			if(test[i][1] === null){
				console.groupCollapsed(testSubject);
				console.log("Expected:\n   ", test[i][1]===null ? "(invalid)" : test[i][1]);
				console.log("Result:\n    (invalid)");
			}
			else{
				console.group(testSubject);
				console.log("Expected:\n   ", test[i][1]===null ? "(invalid)" : test[i][1]);
				console.assert(false, "\nError:\n   ", e.message);
				throw e;
			}
		}finally{
			console.groupEnd();
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
