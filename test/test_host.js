import URI from "../src/uri_parsing.mjs";

function test(expectedOutput, property, ...input){
	let result;
	console.group("Expected: "+(expectedOutput===void 0 ? "(invalid)" : expectedOutput));
	for(let i=0; i<input.length; i++){
		try{
			let uri = URI("http://"+input[i]),
				host = uri.authority.host;
			result = property===null ? ""+host : property==="name" ? host.name : host.ip[property];
			if(result === expectedOutput){
				console.log("Input: ", input[i], " ✔️");
			}
			else{
				console.log("Input: ", input[i], " ❌\nResult:", result, "( "+(host.name||"")+" / "+(host.ip.v4||"")+" / "+(host.ip.v6mixed||"")+" / "+(host.ip.v6||"")+" )");
			}
		}catch(e){
			if(expectedOutput === void 0){
				console.log("Input: ", input[i], " ✔️");
			}
			else{
				console.log("Input: ", input[i], " ❌\nError:", e.message);
				console.trace();
			}
		}
	}
	console.groupEnd();
}

console.group("Hosts");
{
	console.group("IPv4");
		
		test("1.1.1.10", "v4",
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
		test("0.0.0.1", "v4", "1", "%31");
		
	console.groupEnd();
	console.group("IPv6");
		
		console.group("with mixed notation");
			
			test("::ffff:1.1.1.10", "v6mixed",
				"[::ffff:1.1.1.10]",
				"[::0:1.1.1.10]",
				"[::1.1.1.10]",
				"[0::0:1.1.1.10]",
				"[::ffff:1.1.1.010]",	//octals are not recognized here; they must be interpreted as decimal
				"[::ffff:101:10a]",
				"[::ffff:0101:010a]",
				"[::101:10a]",
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
			test(void 0, "v6mixed",
				"[abcd::dcba]",
				"[abcd:0:0:0:0:0:0:dcba]"
			);
			
		console.groupEnd();
		console.group("without mixed notation");
			
			test("::ffff:101:10a", "v6",
				"[::ffff:1.1.1.10]",
				"[::0:1.1.1.10]",
				"[::1.1.1.10]",
				"[0::0:1.1.1.10]",
				"[::ffff:1.1.1.010]",	//octals are not recognized here; they must be interpreted as decimal
				"[::ffff:101:10a]",
				"[::ffff:0101:010a]",
				"[::101:10a]",
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
			test("abcd::dcba", "v6",
				"[abcd::dcba]",
				"[abcd:0:0:0:0:0:0:dcba]"
			);
			
		console.groupEnd();
			
	console.groupEnd();
	console.group("DNS Domain Name");
		
		test(void 0, "name", "1.1.1.10", "[::ffff:1.1.1.10]", "[::ffff:101:10a]", "[::101:10a]");
		test("a", "name", "a", "A");
		test("a-1", "name", "a-1");
		test("1a", "name", "1a");
		test("a.b", "name", "a.b");
		test("1.a", "name", "1.a", "%31.%41", "%31%2E%41");
		test("example.com", "name", "example.com");
		
	console.groupEnd();
	console.group("Invalid");
		
		test(void 0, null,
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
