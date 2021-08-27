import {parseMailbox} from "../src/uri_parsing.mjs";

const test = [
		["", null],
		["a", null],
		["a@", null],
		["@", null],
		["@b", null],
		["a@b", "a@b"],
		
		
		["foo \"ba\\\"r \cd\"baz < foo@bar.baz >", "\"foo ba\\\"r cdbaz\" <foo@bar.baz>"],
		["\"f.oo\"@bar.baz", "f.oo@bar.baz"],
		["\"f oo\"@bar.baz", "\"f oo\"@bar.baz"],
	];

console.group("Mailbox parsing");
	for(let i=0; i<test.length; i++){
		const testSubject = (i+1)+". "+test[i][0];
		try{
			const result = parseMailbox(test[i][0]);
			if(result.full === test[i][1]){
				console.groupCollapsed(testSubject);
				console.log("Expected:\n   ", test[i][1]===null ? "(invalid)" : test[i][1]);
				console.log("Result:\n   ", result.full, "\n   ", result);
			}
			else{
				console.group(testSubject);
				console.log("Expected:\n   ", test[i][1]===null ? "(invalid)" : test[i][1]);
				console.assert(false, "\nResult:\n   ", result.full, "\n   ", result);
			}
		}catch(e){
			if(test[i][1] === null){
				console.groupCollapsed(testSubject);
				console.log("Expected:\n   (invalid)");
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

/*console.group("Email addresses");
{
	console.groupCollapsed("Valid");
		
		//tests from RFC 3696   https://tools.ietf.org/html/rfc3696#section-3
		test('"Abc@def"@example.com', "emailAddress", "simple", '"Abc@def"@example.com');
		test('"Fred Bloggs"@example.com', "emailAddress", "simple", '"Fred Bloggs"@example.com');
		test("user+mailbox@example.com", "emailAddress", "simple", "user+mailbox@example.com");
		test("customer/department=shipping@example.com", "emailAddress", "simple", "customer/department=shipping@example.com");
		test("$A12345@example.com", "emailAddress", "simple", "$A12345@example.com");
		test("!def!xyz%abc@example.com", "emailAddress", "simple", "!def!xyz%abc@example.com");
		test("_somename@example.com", "emailAddress", "simple", "_somename@example.com");
		
		//without a display name
		test('john.doe@example.com', "emailAddress", "simple", 'john.doe@example.com');
		test('john.doe@example.com', "emailAddress", "simple", '<john.doe@example.com>');
		test('"\\"john\\" doe"@example.com', "emailAddress", "simple", '"\\"john\\" doe"@example.com');
		test('""john" doe"@example.com', "emailAddress", "unescapedSimple", '"\\"john\\" doe"@example.com');	//unescaped
		
		//with a display name
		test('John Doe <john@example.com>', "emailAddress", "full", 'John Doe < john@example.com >');
		test('"Joh\\"n Doe" <john@example.com>', "emailAddress", "full", '"Joh\\"n D\\oe" <john@example.com>');
		test('"John\" Doe" <john@example.com>', "emailAddress", "unescapedFull", '"John\\" Doe" <john@example.com>');	//unescaped
		test('"John Doe" <john@example.com>', "emailAddress", "full", '"John	Doe" <john@example.com>');	//with a tab instead of space
		test('John Doe <john@example.com>', "emailAddress", "full", 'John	Doe <john@example.com>');	//with a tab instead of space
		test('John " A Doe " <john@example.com>', "emailAddress", "full", ' John " A Doe " <john@example.com>');
		test('John Doe <john@example.com>', "emailAddress", "full", 'John Doe<john@example.com>');
		
	console.groupEnd();
	console.groupCollapsed("Invalid");
		
		//tests from RFC 3696 that use obsolete syntax
		test(null, "emailAddress", null, "Abc\\@def@example.com");
		test(null, "emailAddress", null, "Fred\\ Bloggs@example.com");
		test(null, "emailAddress", null, "Joe.\\\\Blow@example.com");
		
		//space around "@"
		test(null, "emailAddress", null, "john @ example.com");
		test(null, "emailAddress", null, "john @example.com");
		test(null, "emailAddress", null, "john@ example.com");
		
		//missing angle brackets
		test(null, "emailAddress", null, "<john@example.com");
		test(null, "emailAddress", null, "john@example.com>");
		
	console.groupEnd();
}
console.groupEnd();
*/