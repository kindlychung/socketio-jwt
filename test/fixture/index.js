'use strict'; // Node 4.x workaround

const express = require('express');
const http = require('http');

const socketIo = require('socket.io');
const socketio_jwt = require('../../lib');

const jwt = require('jsonwebtoken');
const xtend = require('xtend');
const bodyParser = require('body-parser');
const enableDestroy = require('server-destroy');

let sio;

exports.start = (options, callback) => {

	if (typeof options == 'function') {
		callback = options;
		options = {};
	}

	options = xtend({
		secret: 'aaafoo super sercret',
		timeout: 1000,
		handshake: true
	}, options);

	const app = express();
	const server = http.createServer(app);
	sio = socketIo(server, {
		allowEIO3: false,
		pingTimeout: 2000, pingInterval: 3000
	});

	app.use(bodyParser.json());
	app.post('/login', (req, res) => {
		const profile = {
			first_name: 'John',
			last_name: 'Doe',
			email: 'john@doe.com',
			id: 123
		};

		// We are sending the profile inside the token
		const token = jwt.sign(profile, options.secret, { expiresIn: 60 * 60 * 5 });
		res.json({ token: token });
	});


	if (options.handshake) {
		sio.use(socketio_jwt.authorize(options));

		sio.sockets.on('echo', (m) => {
			sio.sockets.emit('echo-response', m);
		});
	} else {
		sio.sockets
			.on('connection', socketio_jwt.authorize(options))
			.on('authenticated', (socket) => {
				socket.on('echo', (m) => {
					socket.emit('echo-response', m);
				});
			});
	}

	server.__sockets = [];
	server.on('connection', (c) => {
		server.__sockets.push(c);
	});
	server.listen(9000, callback);
	enableDestroy(server);
};

exports.stop = (callback) => {
	sio.close();
	try {
		server.destroy();
	} catch (er) { }
	callback();
};
