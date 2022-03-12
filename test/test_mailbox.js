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
		
		//tests from RFC 3696   https://tools.ietf.org/html/rfc3696#section-3
		['"Abc@def"@example.com', '"Abc@def"@example.com'],
		['"Fred Bloggs"@example.com', '"Fred Bloggs"@example.com'],
		["user+mailbox@example.com", "user+mailbox@example.com"],
		["customer/department=shipping@example.com", "customer/department=shipping@example.com"],
		["$A12345@example.com", "$A12345@example.com"],
		["!def!xyz%abc@example.com", "!def!xyz%abc@example.com"],
		["_somename@example.com", "_somename@example.com"],
		
		//without a display name
		['john.doe@example.com', 'john.doe@example.com'],
		['<john.doe@example.com>', 'john.doe@example.com'],
		['<"\\"john\\" doe"@example.com>', '"\\"john\\" doe"@example.com'],
		
		//with a display name
		['John Doe < john@example.com >', '"John Doe" <john@example.com>'],
		['"Joh\\"n D\\oe" <john@example.com>', '"Joh\\"n Doe" <john@example.com>'],
		['"John	Doe" <john@example.com>', '"John Doe" <john@example.com>'],	//with a tab instead of space
		['John	Doe <john@example.com>', '"John Doe" <john@example.com>'],	//with a tab instead of space
		[' John " A Doe " <john@example.com>', '"John A Doe" <john@example.com>'],
		['John Doe<john@example.com>', '"John Doe" <john@example.com>'],
		
		//tests from RFC 3696 that use obsolete syntax
		["Abc\\@def@example.com", null],
		["Fred\\ Bloggs@example.com", null],
		["Joe.\\\\Blow@example.com", null],
		
		//space around "@"
		["john @ example.com", null],
		["john @example.com", null],
		["john@ example.com", null],
		
		//missing angle brackets
		["<john@example.com", null],
		["john@example.com>", null],
	];

console.group("Mailbox parsing");
	for(let i=0; i<test.length; i++){
		const testSubject = (i+1)+". "+test[i][0];
		try{
			const result = parseMailbox(test[i][0]);
			if(result && result.full === test[i][1]){
				console.groupCollapsed(testSubject);
				console.log("Expected:\n   ", test[i][1]===null ? "(invalid)" : test[i][1]);
				console.log("Result:\n   ", result.full, "\n   ", result);
			}
			else if(result === null && test[i][1] === null){
				console.groupCollapsed(testSubject);
				console.log("Expected:\n    (invalid)");
				console.log("Result:\n    (invalid)\n   ", result);
			}
			else{
				console.group(testSubject);
				console.log("Expected:\n   ", test[i][1]===null ? "(invalid)" : test[i][1]);
				console.assert(false, "\nResult:\n   ", result===null ? "(invalid)" : result.full, "\n   ", result);
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
