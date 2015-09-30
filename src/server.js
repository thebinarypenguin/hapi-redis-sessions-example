var AuthCookie  = require('hapi-auth-cookie');
var CatboxRedis = require('catbox-redis');
var Crypto      = require('crypto');
var Handlebars  = require('handlebars');
var Hapi        = require('hapi');
var Path        = require('path');
var Vision      = require('vision');
var Pkg         = require('../package.json');

// Create a hapi server
var server = new Hapi.Server({

  // Configure the server cache by defining a catbox client which uses the "catbox-redis" adapter.
  cache: {
    engine: CatboxRedis,
    host: '127.0.0.1',
    port: '6379',
    password: '',
  },
});

// Add an incoming connection to listen on
server.connection({
  host: 'localhost',
  port: 3000,
  router: {
    stripTrailingSlash: true,
  }
});

// Register plugins
server.register([
  AuthCookie,
  Vision,
], function(err) {
  if (err) { throw err; }

  // Provision a segment of the cache for storing session data by creating a catbox policy.
  // The policy is then saved in server.app for later use.
  server.app.cache = server.cache({
    segment: 'sessions',
    expiresIn: 3 * 24 * 60 * 60 * 1000
  });

  // Register an authentication strategy named "session" which uses the "cookie" scheme.
  // The "cookie" authentication scheme is provided by the "hapi-auth-cookie" plugin.
  server.auth.strategy(
    'session',
    'cookie',
    {
      cookie: 'example',
      password: 'secret',
      isSecure: false, // For development only
      redirectTo: '/login',
      redirectOnTry: false,
      appendNext: 'redirect',
      validateFunc: function(request, session, callback) {

        // Use session id (from cookie) to get session data (from cache).
        // If successful session id and data will be exposed in request.auth.credentials.
        request.server.app.cache.get(session.sid, function(err, value, cached, report) {
          var creds = {
            id: session.sid,
            data: value,
          };

          if (err) {
            return callback(err, false);
          }

          if (!cached) {
            return callback(null, false);
          }

          return callback(null, true, creds);
        });
      },
    }
  );

  // Configure template rendering.
  // The "views" method is provided by the "vision" plugin.
  server.views({
    engines: {
      html: Handlebars,
    },
    path: Path.join(__dirname, 'templates'),
    layout: 'layout',
  });

  // Register a route to show the "Home" page (no authentication required)
  server.route({
    method: 'GET',
    path: '/',
    config: {
      auth: {
        mode: 'try',
        strategy: 'session',
      }
    },
    handler: function(request, reply) {
      var context = {
        session: {},
      };

      if (request.auth.isAuthenticated) {
        context.session = request.auth.credentials.data;
      }

      reply.view('home', context);
    }
  });

  // Register a route to show the "Public" page (no authentication required)
  server.route({
    method: 'GET',
    path: '/public',
    config: {
      auth: {
        mode: 'try',
        strategy: 'session',
      }
    },
    handler: function(request, reply) {
      var context = {
        session: {},
      };

      if (request.auth.isAuthenticated) {
        context.session = request.auth.credentials.data;
      }

      reply.view('public', context);
    }
  });

  // Register a route to show the "Private" page (client must have a valid session).
  // If the client does not have a valid session it will be redirected to the "Login" page.
  server.route({
    method: 'GET',
    path: '/private',
    config: {
      auth: {
        mode: 'required',
        strategy: 'session',
      }
    },
    handler: function(request, reply) {
      var context = {
        session: request.auth.credentials.data,
      };

      reply.view('private', context);
    }
  });

  // Register a route to show the the "Login" page.
  // If the client already has a valid session it will be redirected to another page.
  server.route({
    method: 'GET',
    path: '/login',
    config: {
      auth: {
        mode: 'try',
        strategy: 'session',
      }
    },
    handler: function(request, reply) {
      var redirectPath = request.query.redirect || '/';
      var context = {
        session: {},
      };

      if (request.auth.isAuthenticated) {
        return reply.redirect(redirectPath);
      }

      reply.view('login', context);
    }
  });

  // Register a route to process the login credentials.
  // If the credentials are valid, create a session and redirect the client to another page.
  // If the credentials are invalid, show the login page and an error message.
  server.route({
    method: 'POST',
    path: '/login',
    config: {
      auth: {
        mode: 'try',
        strategy: 'session',
      }
    },
    handler: function(request, reply) {
      var redirectPath = request.query.redirect || '/';
      var sessionID    = null;
      var sessionData  = null;
      var context = {
        session: {},
      };

      if (request.auth.isAuthenticated) {
        return reply.redirect(redirectPath);
      }

      if (request.payload.username === 'admin' && request.payload.password === 'password') {

        // This is not guaranteed to be unique, but is sufficient for example purposes.
        sessionID = Crypto.randomBytes(16).toString('hex');

        sessionData = {
          username: request.payload.username
        };

        // Save session data to cache
        request.server.app.cache.set(sessionID, sessionData, 0, function(err) {
          if (err) {
            return reply(err);
          }

          // Save session id to cookie
          request.auth.session.set({ sid: sessionID });

          return reply.redirect(redirectPath);
        });
      } else {
        context.err = 'Invalid Credentials';
        reply.view('login', context);
      }

    }
  });

  // Register a route to destroy any existing session and redirect the client to the home page.
  server.route({
    method: 'GET',
    path: '/logout',
    config: {
      auth: {
        mode: 'try',
        strategy: 'session',
      }
    },
    handler: function(request, reply) {

      // Delete session data from cache
      request.server.app.cache.drop(request.auth.credentials.id, function(err) {
        if (err) {
          return reply(err);
        }

        // Delete session id from cookie
        request.auth.session.clear();

        return reply.redirect('/');
      });
    }
  });

  // Start listening for requests
  server.start(function(err) {
    if (err) { throw err; }

    console.log(Pkg.name + '@' + Pkg.version + ' is running at ' + server.info.uri);
  });
});