require('console-stamp')(console, '[HH:MM:ss]');

const xtend = require('xtend');
const jwt = require('jsonwebtoken');
const UnauthorizedError = require('./UnauthorizedError');

function noQsMethod(options) {
	// console.log(">>>>>>>>>>>>>>>>>>>>>>>> options in noQsMethod", options)
	const defaults = { required: true };
	options = xtend(defaults, options);

	return (socket, next) => {
		'use strict'; // Node 4.x workaround

		console.log("next func: ", next);

		const server = this.server || socket.server;

		// console.log(">>>>>>>>>>>>>>>> socket from noqsmetod: ", socket)

		// if (!server.$emit) {
		// 	// console.error("$emit not found in socket server")
		// 	const Namespace = Object.getPrototypeOf(server.sockets).constructor;
		// 	console.log("🚀 ~ file: index.js ~ line 18 ~ return ~ Namespace", Namespace)
		// 	if (!~Namespace.events.indexOf('authenticated')) {
		// 		Namespace.events.push('authenticated');
		// 	}
		// }

		let auth_timeout = null;
		if (options.required) {
			auth_timeout = setTimeout(() => {
				socket.disconnect('unauthorized');
			}, options.timeout || 5000);
		}

		socket.on('authenticate', (data) => {
			if (options.required) {
				clearTimeout(auth_timeout);
			}

			// error handler
			const onError = (err, code) => {
				if (err) {
					code = code || 'unknown';
					const error = new UnauthorizedError(code, {
						message: (Object.prototype.toString.call(err) === '[object Object]' && err.message) ? err.message : err
					});

					let callback_timeout;
					// If callback explicitly set to false, start timeout to disconnect socket
					if (options.callback === false || typeof options.callback === 'number') {
						if (typeof options.callback === 'number') {
							if (options.callback < 0) {
								// If callback is negative(invalid value), make it positive
								options.callback = Math.abs(options.callback);
							}
						}

						callback_timeout = setTimeout(() => {
							socket.disconnect('unauthorized');
						}, (options.callback === false ? 0 : options.callback));
					}

					socket.emit('unauthorized', error, () => {
						if (typeof options.callback === 'number') {
							clearTimeout(callback_timeout);
						}
						socket.disconnect('unauthorized');
					});
					return; // stop logic, socket will be close on next tick
				}
			};

			// the jwt token is either in a cookie or in the authenticate req data
			const token = options.cookie ? socket.request.cookies[options.cookie] : (data ? data.token : undefined);

			if (!token || typeof token !== 'string') {
				return onError({ message: 'invalid token datatype' }, 'invalid_token');
			}

			// Store encoded JWT
			socket[options.encodedPropertyName] = token;

			const onJwtVerificationReady = (err, decoded) => {
				if (err) {
					return onError(err, 'invalid_token');
				}

				// success handler
				const onSuccess = () => {
					socket[options.decodedPropertyName] = options.customDecoded
						? options.customDecoded(decoded)
						: decoded;
					// socket.emit('authenticated', socket);
					if (server.$emit) {
						server.$emit('authenticated', socket);
					} else {
						//try getting the current namespace otherwise fallback to all sockets.
						if (server._nsps) {
							console.log("server._nsps is defined: ", server._nsps)
						} else {
							console.error("server._nsps not defined")
						}
						if (socket.nsp) {
							console.log("socket.nsp: ", socket.nsp)
						} else {
							console.error("socket.nsp undefined")
						}
						if (server._nsps[socket.nsp.name]) {
							console.log("server._nsps[socket.nsp.name]: ", server._nsps[socket.nsp.name])
						} else {
							console.error("server._nsps[socket.nsp.name] not defined")
						}
						if (server.sockets) {
							console.log("server.sockets: ", server.sockets)
						} else {
							console.error("server.sockets undefined")
						}
						let namespace = (server._nsps && socket.nsp &&
							server._nsps[socket.nsp.name])
						if (namespace) {
							console.log("\n\n\n\n>>>>>>>>>>>>>> Get namespace from server._nsps[socket.nsp.name]");
						} else {
							console.log("\n\n\n\n>>>>>>>>>>>>>> Get namespace from socket.server.sockets");
						}
						namespace = namespace || server.sockets;
						console.log("🚀 >>>>>>>>>>>>>>>>>>>. ~ file: index.js ~ line 116 ~ onSuccess ~ namespace", namespace)

						// explicit namespace
						namespace.emit('authenticated', socket);
					}
				};

				if (options.additional_auth && typeof options.additional_auth === 'function') {
					options.additional_auth(decoded, onSuccess, onError);
				} else {
					onSuccess();
				}
			};

			const onSecretReady = (err, secret) => {
				if (err || !secret) {
					return onError(err, 'invalid_secret');
				}

				jwt.verify(token, secret, options, onJwtVerificationReady);
			};

			// the following line triggers some actions:
			// * get the jwt secret from options
			// * when secret is acquired, verify the token
			// * when token is verified, store the decoded token in socket
			getSecret(socket.request, options.secret, token, onSecretReady);
		});
	};
}

function authorize(options) {
	options = xtend({ decodedPropertyName: 'decoded_token', encodedPropertyName: 'encoded_token' }, options);

	// console.log(">>>>>>>>>>>>>>>>>>>>>>>> options in authorize", options)

	if (typeof options.secret !== 'string' && typeof options.secret !== 'function') {
		throw new Error(`Provided secret ${options.secret} is invalid, must be of type string or function.`);
	}

	if (!options.handshake) {
		// console.log("🚀 ~ file: index.js ~ line 127 ~ authorize ~ options", options)
		return noQsMethod(options);
	} else {
		// console.log(">>>>>>>>>>>>>>>>>>> with handshake, no need to use noQsMethod")
	}

	const defaults = {
		success: (socket, accept) => {
			if (socket.request) {
				accept();
			} else {
				accept(null, true);
			}
		},
		fail: (error, socket, accept) => {
			if (socket.request) {
				accept(error);
			} else {
				accept(null, false);
			}
		}
	};

	const auth = xtend(defaults, options);

	return (socket, accept) => {
		'use strict'; // Node 4.x workaround

		let token, error;
		// console.log(">>>>>>>>>>>>>>>> socket from authorize", socket)

		// 3 ways to provide the jwt token:
		// * handshake query variable
		// * request url query variable
		const handshake = socket.handshake;
		const req = socket.request || socket;
		const authorization_header = (req.headers || {}).authorization;

		if (authorization_header) {
			const parts = authorization_header.split(' ');
			if (parts.length == 2) {
				const scheme = parts[0],
					credentials = parts[1];

				if (scheme.toLowerCase() === 'bearer') {
					token = credentials;
				}
			} else {
				error = new UnauthorizedError('credentials_bad_format', {
					message: 'Format is Authorization: Bearer [token]'
				});
				return auth.fail(error, socket, accept);
			}
		}

		// Check if the header has to include authentication
		if (options.auth_header_required && !token) {
			return auth.fail(new UnauthorizedError('missing_authorization_header', {
				message: 'Server requires Authorization Header'
			}), socket, accept);
		}

		// Get the token from handshake or query string
		if (handshake && handshake.query.token) {
			token = handshake.query.token;
		}
		else if (req._query && req._query.token) {
			token = req._query.token;
		}
		else if (req.query && req.query.token) {
			token = req.query.token;
		}

		if (!token) {
			error = new UnauthorizedError('credentials_required', {
				message: 'no token provided'
			});
			return auth.fail(error, socket, accept);
		}

		// Store encoded JWT
		socket[options.encodedPropertyName] = token;
		socket["____my_own_tag____"] = token;

		const onJwtVerificationReady = (err, decoded) => {
			if (err) {
				error = new UnauthorizedError(err.code || 'invalid_token', err);
				return auth.fail(error, socket, accept);
			}

			socket[options.decodedPropertyName] = options.customDecoded
				? options.customDecoded(decoded)
				: decoded;

			return auth.success(socket, accept);
		};

		const onSecretReady = (err, secret) => {
			if (err) {
				error = new UnauthorizedError(err.code || 'invalid_secret', err);
				return auth.fail(error, socket, accept);
			}

			jwt.verify(token, secret, options, onJwtVerificationReady);
		};

		// the following line triggers some actions:
		// * get the jwt secret from options
		// * when secret is acquired, verify the token
		// * when token is verified, store the decoded token in socket
		getSecret(req, options.secret, token, onSecretReady);
	};
}

function getSecret(request, secret, token, callback) {
	'use strict'; // Node 4.x workaround


	if (typeof secret === 'function') {
		if (!token) {
			return callback({ code: 'invalid_token', message: 'jwt must be provided' });
		}

		const parts = token.split('.');

		if (parts.length < 3) {
			return callback({ code: 'invalid_token', message: 'jwt malformed' });
		}

		if (parts[2].trim() === '') {
			return callback({ code: 'invalid_token', message: 'jwt signature is required' });
		}

		let decodedToken = jwt.decode(token, { complete: true });

		if (!decodedToken) {
			return callback({ code: 'invalid_token', message: 'jwt malformed' });
		}

		const arity = secret.length;
		if (arity == 4) {
			secret(request, decodedToken.header, decodedToken.payload, callback);
		} else { // arity == 3
			secret(request, decodedToken.payload, callback);
		}
	} else {
		callback(null, secret);
	}
}

exports.authorize = authorize;
exports.UnauthorizedError = UnauthorizedError;
