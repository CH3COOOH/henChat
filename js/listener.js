// ===== Button Events =============================

// -- Click "New ID"
$('#btn_auto').click(function () {

	$('#btn_auto').prop('disabled', true);
	$('#btn_enter').prop('disabled', true);
	$('#s_pvk').val(randomStr(64));
	showMsg('A new key will be generated. Please save it by yourself.', 'gray');
	$('#btn_enter').click();
});


// -- Click "Login"
$('#btn_enter').click(function () {
	$('#btn_auto').prop('disabled', true);
	$('#btn_enter').prop('disabled', true);

	// -- Check if pvk's formate is correct
	if ($('#s_pvk').val().length === 64) {

		// -- Keygen
		[selfPrivateKey, selfPublicKey] = (function() {
			var selfRSA = cryptico.generateRSAKey($('#s_pvk').val(), 1024);		// And it would also be used to decrypt
			return [selfRSA, cryptico.publicKeyString(selfRSA)];				// The later is used to encrypt plain text
		})();

		newSession(DEFAULT_SERVER);

	} else {
		alert('Invalid key.');
	}
});


// -- Click "ETE"
$('#btn_encrypt').click(function () {

	var receiver = '';
	for (c of contacts) {
		if ($(`#${c}`).prop('checked')) {
			receiver = c;
		}
	}
	if (receiver === '') {
		alert('There is no receiver in the list...');
		return -1;
	}

	$('#s_to').prop('disabled', true);					// Forbid multi-receiver
	$('#btn_encrypt').prop('disabled', true);			// Forbid ETE button
	$('#btn_send').prop('disabled', true);				// Temporary block ETE button
	$(`#${receiver}`).prop('checked', true);						// Fix receiver as the 1st receiver
	$(`#${receiver}`).prop('disabled', true);

	var now = new Date();
	var keyExchangeRequest = {
		from: $('#s_pbk').val(),
		to: [receiver],
		type: 'msg',
		msg: selfPublicKey,
		key: 'true',
		token: sToken,
		time: now.getTime().toString()
	}

	ws.send(JSON.stringify(keyExchangeRequest));
	while (publicKeyCache != '@');						// Wait for public key from receiver
	$('#btn_send').prop('disabled', false);				// Send button recovery

	encryptMode = true;
});


// -- Click "Send"
$('#btn_send').click(function () {

	var eteSign = (function () {
		if (encryptMode === true) {
			return '🔒';
		} else {
			return '';
		}
	})();

	// -- It is unacceptable to send empty message (no text, no attachement)
	if ($('#s_send').val() === '' && !fileExtCheck(fileSelector, enabledFileExts)) {
		showMsg('Cannot send empty message!', 'red');

	} else {

		// Msg infomation
		var now = new Date();
		var sendLst = [];

		// -- Make receivers' list
		for (c of contacts) {
			if ($(`#${c}`).prop('checked')) {
				sendLst.push(c);
			}
		}

		// -- Attachment exist
		// -- If file is supported
		if (fileExtCheck(fileSelector, enabledFileExts)) {
					
			var reader = new FileReader();

			reader.onload = function(e) {
				var data = e.target.result;
				var fsize = fileSelector.files[0].size;

				if (data.length > MAX_DATALENTH) {
					showMsg('File size over limit!', 'red');
					return -1;
				}

				// -- Big file (size over slice threshold)
				if (data.length > SLICE_THRESHOLD) {

					var cut = function (dataStr, maxSlice) {
						var sliceNum = parseInt(dataStr.length / maxSlice);
						var slices = [];
						var p = 0;

						for (var i=0; i<sliceNum+1; i++) {
							slices.push(rsaEncrypt(dataStr.substring(p, p+maxSlice), publicKeyCache, encryptMode));
							p += maxSlice;
						}
						return slices;
					}

					dataSlices = cut(data, SLICE_THRESHOLD);
					sendingSlice = randomStr(8, false);
					sliceCounter[0] = 0;
					sliceCounter[1] = dataSlices.length
					var sentLen = 0;
					var dataLen = data.length;

					// -- Show a process graph
					showMsg(`File sending... (${dataLen})<br><progress id="${sendingSlice}" value="0">0%</progress>`, 'gray');
					console.log(`Data has been splited into ${dataSlices.length} parts.`);

					for (var i=0; i<dataSlices.length; i++) {

						sentLen += SLICE_THRESHOLD;
						var contentWithImg = {
							from: $('#s_pbk').val(),
							to: sendLst,
							type: 'msg',
							sign: sendingSlice,
							size: [i+1, dataSlices.length],		// [sent slice, total slice number]
							rest: dataLen - sentLen,
							msg: rsaEncrypt($('#s_send').val(), publicKeyCache, encryptMode),
							img: dataSlices[i],
							token: sToken,
							time: now.getTime().toString()
						}
						sliceQueue.push(contentWithImg);
					}
					sliceQueue = sliceQueue.reverse();

					// Here the client just send the 1st slice and wait the response of server.
					// (Otherwise the sever would crash.)
					// Once get the response, the next slice would be able to be sent.
					// That part is written in function "ws.onmessage()"
					ws.send(JSON.stringify(sliceQueue.pop()));

				// -- Send small file without splitting
				} else {

					var contentWithImg = {
						from: $('#s_pbk').val(),
						to: sendLst,
						type: 'msg',
						msg: rsaEncrypt($('#s_send').val(), publicKeyCache, encryptMode),
						img: rsaEncrypt(data, publicKeyCache, encryptMode),
						token: sToken,
						time: now.getTime().toString()
					}
					var contentWithImg_show = {
						from: eteSign + $('#s_pbk').val() + ' -> ' + sendLst.toString(),
						msg: $('#s_send').val(),
						img: data,
						time: now.getTime().toString()
					}	// -- Encrypted message cannot be shown directly
					showMsg(contentWithImg_show, 'green');

					ws.send(JSON.stringify(contentWithImg));
					$('#s_send').val('');
				}

				fileSelector.value = '';
			}
			reader.readAsDataURL(fileSelector.files[0]);

		// -- Plain text
		} else {

			if ($('#s_send').val().length <= MAX_TXTLENGTH) {

				// -- ETE mode
				var content = {
					from: $('#s_pbk').val(),
					to: sendLst,
					type: 'msg',
					msg: rsaEncrypt($('#s_send').val(), publicKeyCache, encryptMode),
					token: sToken,
					time: now.getTime().toString()
				}

				var content_show = {
					from: eteSign + $('#s_pbk').val() + ' -> ' + sendLst.toString(),
					msg: $('#s_send').val(),
					time: now.getTime().toString()
				}
				showMsg(content_show, 'green');

				ws.send(JSON.stringify(content));
				$('#s_send').val('');

			} else {
				showMsg(`Too many characters!(over ${MAX_TXTLENGTH})`, 'red');
			}
		}
	}
});
			 

// -- Click "Logout"
$('#btn_close').click(function () {
	ws.close();
	if (encryptMode) {
		location.reload();
	}
});


// ===== Key Events ===============================

// -- Press "Ctrl+Enter" to send
prevKey = '';
document.onkeydown = function (e) {
	if (e.key === 'Enter' && prevKey === 'Control') {
		$('#btn_send').click();
	}
	if (e.key != prevKey) {
		prevKey = e.key;
	}
}

// ===== Add Contacts ===============================
contacts = [];
function addReceiver() {
	var newReceiver = $('#s_to').val();
	if (newReceiver === '' || contacts.indexOf(newReceiver) != -1) {
		return -1;
	}
	contacts.push(newReceiver);
	$('#receiverChoice').prepend(`<input type="checkbox" id="${newReceiver}" checked="checked"/>${newReceiver}<br>`);
	$('#s_to').val('');
}

function addReceiverFromSession(cid) {
	if (contacts.indexOf(cid) != -1) {
		return -1;
	}
	contacts.push(cid);
	$('#receiverChoice').prepend(`<input type="checkbox" id="${cid}" checked="checked"/>${cid}<br>`);
}