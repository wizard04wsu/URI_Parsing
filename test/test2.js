
let useMixedNotation = void 0,
	test = function (expectedOutput, property, ...input){
		let i, output, actualOutput, testPassed;
		for(i=0; i<input.length; i++){
			console.log("Expected:",expectedOutput,"  Input:",input[i]);
			output = ParseURI.domain(input[i], useMixedNotation);
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
	console.groupCollapsed("IPv4");
		
		test("1.1.1.10", "ipv4",
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
		
	console.groupEnd();
	console.groupCollapsed("IPv6");
		
		console.group("with mixed notation");
			
			test("::ffff:1.1.1.10", "ipv6",
				"[::ffff:1.1.1.10]",
				"[::0:1.1.1.10]",
				"[::1.1.1.10]",
				"[0::0:1.1.1.10]",
				"[::ffff:1.1.1.010]",	//octals are not allowed here; they must be interpreted as decimal
				"[::ffff:101:10a]",
				"[::ffff:0101:010a]",
				"1.1.1.10"
			);
			test("::101:10a", "ipv6",
				"[::101:10a]",
				"[0::101:10a]"
			);
			test("abcd::dcba", "ipv6",
				"[abcd::dcba]",
				"[abcd:0:0:0:0:0:0:dcba]"
			);
			
		console.groupEnd();
		console.group("without mixed notation");
			
			useMixedNotation = false;
			test("::ffff:101:10a", "ipv6",
				"[::ffff:0101:010a]",
				"1.1.1.10"
			);
			test("::101:10a", "ipv6",
				"[::101:10a]"
			);
			useMixedNotation = void 0;
			
		console.groupEnd();
			
	console.groupEnd();
	console.group("DNS Domain");
		
		test("1.1.1.10", "host", "1.1.1.10", "[::ffff:1.1.1.10]", "[::ffff:101:10a]");
		test("[::101:10a]", "host", "[::101:10a]", "[0::0:101:10a]");
		test("[abcd::dcba]", "host", "[abcd::dcba]", "[abcd:0:0:0:0:0:0:dcba]");
		test("a", "host", "a", "A");
		test("a-1", "host", "a-1");
		test("1a", "host", "1a");
		test("a.b", "host", "a.b");
		test("1.a", "host", "1.a");
		test("a.1", "host", "a.1");
		test("0.0.0.1", "host", "1", "%31");
		
	console.groupEnd();
	console.group("Invalid");
		
		test(null, null,
			".",
			"[::ffff:1.1.1.0xC]",	//hexadecimals are not allowed here
			"[1.1.1.10]",
			"a-",
			"-a"
		);
		
	console.groupEnd();
console.groupEnd();
