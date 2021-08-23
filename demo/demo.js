import URI, {URIError, isDNSDomain, parseMailbox} from "https://cdn.jsdelivr.net/gh/wizard04wsu/URI_Parsing@dev/src/uri_parsing.mjs"

console.clear();

document.getElementById("parse_scheme").addEventListener("click", ()=>{
	let val = document.getElementById("uri").value;
	console.group("scheme");
	console.log(val);
	try{
		val = URI(val);
		console.log(val.toString());
		console.log(val);
	}catch(e){
		if(e instanceof URIError) console.error(e.message);
		else throw e;
	}finally{
		console.groupEnd();
	}
}, false);

document.getElementById("parse_generic").addEventListener("click", ()=>{
	let val = document.getElementById("uri").value;
	console.group("generic");
	console.log(val);
	try{
		val = URI.parse(val)
		console.log(val.toString());
		console.log(val);
	}catch(e){
		if(e instanceof URIError) console.error(e.message);
		else throw e;
	}finally{
		console.groupEnd();
	}
}, false);

document.getElementById("parse_mailbox").addEventListener("click", ()=>{
	let val = document.getElementById("email").value;
	console.group("email");
	console.log(val);
	try{
		val = parseMailbox(val);
		console.log(val.full);
		console.log(val);
	}catch(e){
		if(e instanceof URIError) console.log(e.message);
		else throw e;
	}finally{
		console.groupEnd();
	}
}, false);
