
let useMixedNotation = void 0,
	test = function (expectedOutput, method, property, ...input){
		let i, output, actualOutput, testPassed;
		for(i=0; i<input.length; i++){
			console.log("Expected:",expectedOutput,"  Input:",input[i]);
			output = ParseURI[method](input[i], useMixedNotation);
			actualOutput = property === null ? output : output===null?null:output[property];
			if(actualOutput !== expectedOutput){
				testPassed = false;
				console.log("Actual:", actualOutput);
			}
			else{
				testPassed = true;
			}
			console.assert(testPassed, output);
		}
	};

console.group("Hosts");
{
	console.groupCollapsed("IPv4");
		
		test("1.1.1.10", "domain", "ipv4",
			"1.1.1.10",
			"1.1.513.10",		// 1 + (256*2)  -->  513  (add multiples of 256 to any/all segments)
			"1.1.266",			// (256)*1 + 10  -->  266  (turn the last 2 segments into a dword)
			"16843018",			// (256^3)*1 + (256^2)*1 + (256)*1 + (1)*10  -->  16843018  (turn the last 4 (all) segments into a dword)
			"1.1.131338",		// ( (256)*1 + 10 ) + ((256^2)*2)  -->  131338  (add multiples of 256^2 to the dword)
			"8606777610",		// ( (256^3)*1 + (256^2)*1 + (256)*1 + (1)*10 ) + ((256^4)*2)  -->  8606777610  (add multiples of 256^4 to the dword)
			"1.01.1.012",		// any/all segments can be an octal number
			"1.0001.1.00012",	// octal numbers with multiple leading zeroes
			"1.0X1.1.0xa",		// any/all segments can be hexadecimal
			"1.1.0x10A",		// turn the last 2 segments into a hexadecimal number
			"0x0101010A",		// turn the last 4 (all) segments into a hexadecimal number
			"1.0xABC01.1.0xABCD0A",	// add multiples of 256 to any/all segments
			"1.0xABC01.0xABCD010A",	// add multiples of 256 to any/all segments
			"01.0x1.266",		// combinations work, too
			"%31.%31.%31.%310",	// percent-encoded characters
			"1.0X1.1.%30%78A"	// any/all segments can be hexadecimal
		);
		test("0.0.0.1", "domain", "ipv4", "1", "%31");
		
	console.groupEnd();
	console.groupCollapsed("IPv6");
		
		console.group("with mixed notation");
			
			test("::ffff:1.1.1.10", "domain", "ipv6",
				"[::ffff:1.1.1.10]",
				"[::0:1.1.1.10]",
				"[::1.1.1.10]",
				"[0::0:1.1.1.10]",
				"[::ffff:1.1.1.010]",	//octals are not recognized here; they must be interpreted as decimal
				"[::ffff:101:10a]",
				"[::ffff:0101:010a]",
				"1.1.1.10"
			);
			test("::101:10a", "domain", "ipv6", "[::101:10a]", "[0::101:10a]");
			test("abcd::dcba", "domain", "ipv6", "[abcd::dcba]", "[abcd:0:0:0:0:0:0:dcba]");
			
		console.groupEnd();
		console.group("without mixed notation");
			
			useMixedNotation = false;
			test("::ffff:101:10a", "domain", "ipv6",
				"[::ffff:0101:010a]",
				"1.1.1.10"
			);
			test("::101:10a", "domain", "ipv6",
				"[::101:10a]"
			);
			useMixedNotation = void 0;
			
		console.groupEnd();
			
	console.groupEnd();
	console.groupCollapsed("Host (DNS Domain or IP)");
		
		test("1.1.1.10", "domain", "host", "1.1.1.10", "[::ffff:1.1.1.10]", "[::ffff:101:10a]");
		test("[::101:10a]", "domain", "host", "[::101:10a]");
		test("a", "domain", "host", "a", "A");
		test("a-1", "domain", "host", "a-1");
		test("1a", "domain", "host", "1a");
		test("a.b", "domain", "host", "a.b");
		test("1.a", "domain", "host", "1.a", "%31.%41", "%31%2E%41");
		test("example.com", "domain", "host", "example.com");
		
	console.groupEnd();
	console.groupCollapsed("Invalid");
		
		test(null, "domain", null,
			".",
			"[::ffff:1.1.1.0xC]",	//hexadecimals are not allowed here
			"[1.1.1.10]",
			"a-",
			"-a",
			"a.1"
		);
		
	console.groupEnd();
}
console.groupEnd();

console.group("Email addresses");
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
