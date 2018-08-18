// 2018.03.02: Add support of big file (slice used)
// 2018.03.05: Cookie supported; Fix bug of slice
// 2018.03.15: Add support of progress in sending slice (HTML5 only)
// 2018.03.18: Add auto-gen mode; "control-enter" support
// 2018.04.05: End-to-end encryption realized (plain text only)
// 2018.04.06: ETE now supports attachements; add key hash comparision (MITM block)
// 2018.08.16: Prevent repeat click on login and newid button

var CLIENT_VER = '180816';

// var DEFAULT_SERVER = 'wss://us2.srdmobile.tk';
var DEFAULT_SERVER = 'ws://localhost:9001';

var SLICE_THRESHOLD = 40960;						// Data whose length(base64) over this amount will be splited
var MAX_DATALENTH = SLICE_THRESHOLD*100;			// Max data length(base64)
var MAX_TXTLENGTH = 2048;							// Max character in message
var enabledFileExts = ['.jpg', '.gif', '.png', 'jpeg'];		// Supported file formate
var buffer = {};									// Used to receive coming slices and combine them

var ws;												// Websocket
var sToken;											// To certificate users' validation
var addrMap = {};									// {nickname: SHA-1}

var sliceQueue = [];								// Queen of data slice
var sendingSlice = ''								// The sign of sending slice
var sliceCounter = [0, 0];							// [numSent, numTotal]

var encryptMode = false;							// Using ETE or not
var publicKeyCache = '@';							// Public key of another user
var selfPrivateKey, selfPublicKey;					// Current user's PVK and PBK


// ===== Basic functions ====================
function rsaEncrypt(plaintext, key, enable=true) {
	if (enable) {
		var plain = base64_encode(plaintext);
		return cryptico.encrypt(plain, key).cipher;
	} else {
		return plaintext;
	}
}

function rsaDecrypt(xtext, key, enable=true) {
	if (enable) {
		var detext = cryptico.decrypt(xtext, selfPrivateKey).plaintext;
		return base64_decode(detext);
	} else {
		return xtext;
	}
}

function getCookie(key) {
	var arr, reg = new RegExp("(^| )"+key+"=([^;]*)(;|$)");
	if (arr = document.cookie.match(reg)) {
		return unescape(arr[2]);
	} else {
		return null;
	}
}

function randomStr(length, symbol=true) {
	var gen = '';
	if (symbol) {
		var charLib = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*?@~-';
	} else {
		var charLib = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
	}
	
	for (var i=0; i<length; i++) {
		index = Math.round(Math.random() * (charLib.length - 1));
		gen += charLib[index];
	}
	return gen;
}

// ==============================
// online = true: online mode
// online = false: offline mode
// ==============================
function formStatusSet(online) {
	$('#s_pvk').prop('disabled', online);
	$('#s_pbk').prop('disabled', true);
	$('#s_to').prop('disabled', !online);
	$('#s_send').prop('disabled', !online);
	$('#btn_auto').prop('disabled', online);
	$('#btn_enter').prop('disabled', online);
	$('#btn_encrypt').prop('disabled', !online);
	$('#btn_close').prop('disabled', !online);
	$('#btn_send').prop('disabled', !online);
	$('#fileSelector').prop('disabled', !online);
}
// ===========================================


// ================================================================
// Create a new websocket server, including all events:
// ws.onopen()
// ws.onmessage()
// ws.onclose()
// ws.onerror()
// ================================================================
function newSession(server) {

	// -- Connect to Web Socket
	ws = new WebSocket(server);

	// -- Set event handlers
	ws.onopen = function() {
		showMsg(`Server opened. Client ver: ${CLIENT_VER}`);
		// document.cookie = `server=${$('#s_server').val()}`;
		document.cookie = `pvk=${$('#s_pvk').val()}`;
		var now = new Date();

		// -- Send login request
		loginInfo = {
			type: 'login',
			msg: $('#s_pvk').val(),
			time: now.getTime().toString()
		}
		ws.send(JSON.stringify(loginInfo));
	};
		
	ws.onmessage = function(e) {
		// -- e.data contains received string.
		var getMsg = JSON.parse(e.data);
		// console.log(getMsg);

		// -- Server reply "login"
		if (getMsg.type === 'login') {
			sToken = getMsg.msg;
			$('#s_pbk').val(getMsg.to);
			console.log(`Server ver: ${getMsg.ver}\nGet token: [${sToken}]`);
			formStatusSet(true);
		}

		else if (getMsg.type === 'msg') {
			// -- Not a key-exchange request
			if (getMsg.key != 'true') {
				if (addrMap[getMsg.from] != undefined) {
					getMsg.from = addrMap[getMsg.from];
				}
				showMsg(getMsg, "blue");

			// -- Key-exchange request
			} else {
				// -- There is no existing public key
				if (publicKeyCache === '@') {
					showMsg(`Get public key from<br>${getMsg.from}.`, 'gray');
					publicKeyCache = getMsg.msg;
					showMsg(`!! ******** WARNING ********* !!<br>
						Please compare public keys (hash) in avoid of MITM attack.<br>
						Yours:<br>[${SHA1(selfPublicKey)}]<br>
						His/Hers:<br>[${SHA1(publicKeyCache)}]<br>
						********************************`, 'red')
					// -- Send self public key to receiver
					var now = new Date();
					var keyExchangeRequest = {
						from: $('#s_pbk').val(),
						to: [getMsg.from],
						type: 'msg',
						msg: selfPublicKey,
						key: 'true',
						token: sToken,
						time: now.getTime().toString()
					}
					ws.send(JSON.stringify(keyExchangeRequest));
					encryptMode = true;

					addReceiverFromSession(getMsg.from);
					$('#s_to').val(getMsg.from);
					$('#s_to').prop('disabled', true);
					$('#btn_encrypt').prop('disabled', true);
					// $('#fileSelector').prop('disabled', true);

					showMsg('🔒You have entered encrypt mode.', 'red');
					document.title='🔒henChat';
				}
			}
		}

		// -- Server info
		else if (getMsg.type === 'info') {
			if (getMsg.msg != '0 reciver(s) offline.') {
				showMsg(`${getMsg.msg}`, 'gray');
			}
		}

		// -- Server error info
		else if (getMsg.type === 'err') {
			alert(`ERROR from server: ${getMsg.msg}`);
			ws.close();
		}

		// -- Slice message
		else if (getMsg.type === 'slice') {
			var nextSlice = sliceQueue.pop();
			$(`#${sendingSlice}`).val(++sliceCounter[0] / sliceCounter[1]);
			if (nextSlice != undefined) {
				ws.send(JSON.stringify(nextSlice));
			}
		}
	};

	ws.onclose = function() {
		showMsg("Server closed.");
		formStatusSet(false);
		encryptMode = false;
		publicKeyCache = '@';
	};

	ws.onerror = function(e) {
		showMsg("Server error.", "red");
		formStatusSet(false);
	};
}


// ================================================================
// Output something in log region. There are 2 typical situations:
// 1. msg is plain text: text will be shown directly;
// 2. msg is json object: text will be handled first.
// And encrypt mode status can influence the handling process.
// ================================================================
function showMsg(msg, color="black") {
	// msg here is in struct of json

	// ===============================
	// Search "XSS attack" for detail
	// ===============================
	function xssAvoid(rawStr){
		return rawStr.replace(/</g, '&lt').replace(/>/g, '&gt');
	}

	var log = $('#log');
	var notice = true;

	if (typeof(msg) === 'object') {
		var now = new Date(parseInt(msg.time));
		strFrom = (function () {
			if (msg.from.indexOf('->') === -1) {
				return `<a href="javascript:addReceiverFromSession('${msg.from}')">${msg.from}</a>`;
			} else {
				return msg.from;
			}
		})();

		// -- Not in encrypt mode or the message is from the user
		if (encryptMode === false || color === 'green') {
			var strHead = `${now.toString()}<br>[${strFrom}]<br>`;
			showText = `${strHead}<font color="${color}">${xssAvoid(msg.msg).split('\n').join('<br>')}</font><br>`;
		
		// -- In encrypt mode
		} else {
			var strHead = `${now.toString()}<br>[🔒${msg.from}]<br>`;
			showText = `${strHead}<font color="${color}">${xssAvoid(rsaDecrypt(msg.msg, selfPrivateKey)).split('\n').join('<br>')}</font><br>`;
		}

		// -- Message with image
		if (msg['img'] != undefined) {

			// -- Whole file (without spliting)
			if (msg['rest'] === undefined) {

				if (encryptMode === false || color === 'green') {
					showText += `<img src="${msg.img}" width="200"><br>`;
				} else {
					showText += `<img src="${rsaDecrypt(msg.img, selfPrivateKey, true)}" width="200"><br>`;
				}
				showText += '<br>';
				log.prepend(showText);

			// -- Sliced file
			} else {

				if (buffer[msg.sign] == undefined) {
					showMsg(`Receiving an image from<br>${msg.from}<br><progress id="${msg.sign}" value="${msg.size[0]/msg.size[1]}">0%</progress>`, 'gray');
					buffer[msg.sign] = rsaDecrypt(msg.img, selfPrivateKey, encryptMode);
				} else {
					buffer[msg.sign] += rsaDecrypt(msg.img, selfPrivateKey, encryptMode);
					$(`#${msg.sign}`).val(msg.size[0]/msg.size[1]);
					notice = false;
				}

				// -- Transfer finished
				if (msg['rest'] <= 0) {
					showText += `<img src="${buffer[msg.sign]}" width="200"><br>`;
					showText += '<br>';
					log.prepend(showText);
					delete(buffer[msg.sign]);					// Clean buffer
				}
			}

		// -- Text message
		} else {
			showText += '<br>';
			log.prepend(showText);
		}

		// -- Show the notification
		if(document.hidden && Notification.permission === "granted" && notice) {
			var notification = new Notification('henChat', {
				body: 'New message comes!',
			});

			notification.onclick = function() {
				window.focus();
			};
		}

	// -- msg is plain text
	} else {
		log.prepend(`<font color="${color}">${msg}<br><br></font>`);
	}
}


// ================================================================
// Check the extension of selected file. Available extensions are 
// defined on the head
// ================================================================
function fileExtCheck(fileInputLable, extNames) {
			
	var fname = fileInputLable.value;
	if (!fname) {
		return false
	}
	var fext = fname.slice(-4).toLowerCase();
	if (extNames.indexOf(fext) != -1) {
		return true;
	} else {
		return false;
	}
}

// ===== Init ======================================
formStatusSet(false);
$('#s_pvk').val(getCookie('pvk'));
var fileSelector = document.getElementById('fileSelector');
// =================================================
