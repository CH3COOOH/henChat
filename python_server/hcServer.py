# -*- coding:utf-8 -*-

# Start: 2018.02.16
# Update:
# 2018.02.17: Multi-channel support
# 2018.02.19: History mode exchange
# 2018.02.27: Use SHA-1 as userid and random string as private key
	# Rebuild the whole server
# 2018.03.01: Multi-tag support (keep the coming message(json)'s key); can send small images
# 2018.03.02: Now can send sliced data (big files supported)
# 2018.03.05: Add user whitelist mode

import time
import hashlib
import json

from websocket_server import WebsocketServer
import azLib as al

SERVER_VER = '180405'
MAX_ONLINE = 15
WHITELIST = []				# Client(sha-1) in WHITELIST would not be limited by MAX_ONLINE
OFFLINE_BUFFER_LEN = 20


def randStr(length):
	from random import choice
	strLib = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&()=-~^|/*_?<>'
	return ''.join(choice(strLib) for _ in xrange(length))


class HCS:

	def __init__(self, port, host="127.0.0.1"):
		self.host = host
		self.port = port
		self.onlineLst = {}				# {sha-1: [client, token]}
		self.msgLst = {}				# {sha-1: [(obj)Msg]}
		self.online_total = 0			# Current online users


	def _getClientById(self, cid):
		for i in self.onlineLst.keys():
			if cid == i:
				return self.onlineLst[i][0]
		return None


	# def _wordBlock(self, rawText, blockLst):
	# 	handled = rawText
	# 	for w in blockLst:
	# 		if w in handled:
	# 			handled = handled.replace(w, '*'*len(w))
	# 	return handled


	def _reply(self, server, typE, content, reciver):
		reply = {'type': typE,
				'msg': content,
				'time': str(time.time())}
		server.send_message(reciver, json.dumps(reply))


	def newClient(self, client, server):
		self.online_total += 1
		client['id'] = str(time.time())
		al.log('New client comes at %s. There are %d clients online.' % (client['id'], self.online_total))


	def clientLeft(self, client, server):
		self.online_total -= 1
		al.log('ID: [%s] left. There are %d clients online.' % (client['id'], self.online_total))
		try:
			del(self.onlineLst[client['id']])
		except:
			al.log('ID: [%s] has already been removed.' % client['id'])


	def msgReceived(self, client, server, msg):

	# Coming message structure:
	# msg = {'from': str,
	# 		'to': str,
	# 		'type': ['login', 'check', 'msg'],
	# 		'msg': str,
	# 		'token': str,
	# 		'time': str}
		try:

			d_msg = eval(msg)

			### This will cause crash in some cases!! ###
			# for k in d_msg.keys():
			# 	print('%s: %s' % (k, d_msg[k]))
			#############################################

			if d_msg['type'] == 'login':

				pvk = d_msg['msg']
				cid = hashlib.sha1(pvk).hexdigest()

				if (self.online_total < MAX_ONLINE) or (cid in WHITELIST):
					
					if cid in self.onlineLst.keys():
						# Multi-device online is not supported
						self._reply(server, 'err', 'There is another device online. Please retry.', client)

					token = randStr(16)
					reply = {'to': cid,
							'type': 'login',
							'msg': token,
							'ver': SERVER_VER,
							'time': str(time.time())}
					server.send_message(client, json.dumps(reply))

					client['id'] = cid
					self.onlineLst[cid] = [client, token]

					if cid in self.msgLst.keys():
						for m in self.msgLst[cid]:
							server.send_message(client, json.dumps(m))
						del(self.msgLst[cid])

				else:
					self._reply(server, 'err', 'Too many clients online. (MAX=%d)' % MAX_ONLINE, client)

			
			elif d_msg['type'] == 'msg':
				# ===== Man page of type 'msg' ===
				# When a new message comes, the server does not change its contend but delete key 'token' and 'to'.
				# Thus it is safe to send 'msg' with any new keys.
				# ================================

				if d_msg['from'] in self.onlineLst.keys() and d_msg['token'] == self.onlineLst[d_msg['from']][1]:

					# Sender identify passed
					# content = {'from': d_msg['from'],
					# 			'type': 'msg',
					# 			'msg': self._wordBlock(d_msg['msg'], BLOCK),
					# 			'time': d_msg['time']}

					content = d_msg.copy()
					del(content['token'])
					del(content['to'])

					# Send
					offline_count = 0
					for cid in d_msg['to']:

						# Invalid address
						if len(cid) != 40 or cid == client['id']:
							self._reply(server, 'info', 'Invalid reciver: %s' % cid, client)
							continue

						target = self._getClientById(cid)
						if target != None:
							# Reciver online
							server.send_message(target, json.dumps(content))

						else:
							# Reciver offline
							offline_count += 1

							if 'rest' not in d_msg.keys():
								if cid in self.msgLst.keys():
									self.msgLst[cid].append(content)
								else:
									self.msgLst[cid] = [content]

								self._reply(server, 'info', '%d reciver(s) offline or not exist.' % offline_count, client)

						# Feedback to sender, notice it to send the next slice
						if 'rest' in d_msg.keys():
							reply = {'type': 'slice',
									'msg': 'OK',
									'time': str(time.time())}
							server.send_message(client, json.dumps(reply))

				else:

					# Sender identify failed
					al.log('%s is an invalid token.' % d_msg['token'])
					self._reply(server, 'err', 'Auth failed.', client)

		except:
			self._reply(server, 'err', 'Invalid message formate.', client)
			raise


	def start(self):
		al.log('Launch a server on port %d...' % self.port)
		server = WebsocketServer(self.port, host=self.host)
		server.set_fn_new_client(self.newClient)
		server.set_fn_client_left(self.clientLeft)
		server.set_fn_message_received(self.msgReceived)
		server.run_forever()



def main():
	a1 = HCS(9001)
	a1.start()



if __name__ == '__main__':
	main()

