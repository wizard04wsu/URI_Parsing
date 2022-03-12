import URI, {URIError, isDNSDomain, parseMailbox} from "https://cdn.jsdelivr.net/gh/wizard04wsu/URI_Parsing@jsfiddle-demo/src/uri_parsing.js"

console.clear();

document.getElementById("parse_scheme").addEventListener("click", ()=>{
	let val = document.getElementById("uri").value;
	console.group("scheme");
	try{
		let obj = URI(val);
		console.log("--> "+obj.toString());
		console.log(obj);
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
	try{
		let obj = URI.parse(val)
		console.log("--> "+obj.toString());
		console.log(obj);
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
	try{
		let obj = parseMailbox(val);
		console.log("--> "+obj.toString());
		console.log(obj);
	}catch(e){
		if(e instanceof URIError) console.log(e.message);
		else throw e;
	}finally{
		console.groupEnd();
	}
}, false);
