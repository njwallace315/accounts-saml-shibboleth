/* eslint-disable */
if (!Accounts.saml) {
  Accounts.saml = {};
}

let Fiber = Npm.require('fibers');
let connect = Npm.require('connect');
let zlib = Npm.require('zlib');
let xmldom = Npm.require('xmldom');
RoutePolicy.declare('/_saml/', 'network');

Accounts.registerLoginHandler(function (loginRequest) {
  try {
    var myKeys = Object.keys(profile);
    var concatfiles = "";
    for (var k = 0; k < myKeys.length; k++) {
      concatfiles = concatfiles + ", " + myKeys[k] + ": " + profile[myKeys[k]];
    }
    Accounts.saml.debugLog('saml_server.js', '19', 'Profile Fields: ' + concatfiles, false);
  }
  catch (err) {
  }

  if (!loginRequest.saml || !loginRequest.credentialToken) {
    return undefined;
  }

  var loginResult = Accounts.saml.retrieveCredential(loginRequest.credentialToken);

  if (loginResult && loginResult.profile && loginResult.profile.email) {
    var profile = loginResult.profile;
    var fname = '';
    var dbField = '';
    var user = null;
    var generateUsers = false;

    var settings = getSamlSettigs();
    if (settings) {
      if (typeof settings.generateUsers === 'boolean') {
        generateUsers = settings.generateUsers
      }
      if (settings.authFields) {
        fname = settings.authFields['fname'];
        dbField = settings.authFields['dbField'];
        Accounts.saml.debugLog('saml_server.js', '45', 'Using fname and dbField from settings.json', false);
      }
    }

    // Query with settings authfields
    if (dbField && fname) {
      Accounts.saml.debugLog('saml_server.js', '51', 'fname: ' + fname + ', dbField: ' + dbField + ', First Query is Meteor.user.findOne({ ' + dbField + ' : profile[' + fname + '] })', false);
      user = Meteor.users.findOne({ dbField: profile[fname] })
    }
    if (!user) {
      // try some default lookups
      var query = Accounts.saml.getDefaultUserQuery(profile)
      user = Meteor.users.findOne(query)
      Accounts.saml.debugLog('saml_server.js', '58', 'User not found from authFields attribute in settings.json.  Using generated default query: ' + query + ', to find user.', false);
    }

    if (!user) {
      if (generateUsers) {
        user = {};

        if (profile.nameIDFormat === 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' && profile.nameID) {
          user.email = profile.nameID;
        } else if (profile.email || profile.mail) {
          user.email = profile.email || profile.mail;
        }

        if (profile.uid) {
          user.username = profile.uid
        }

        if (profile.eduPersonPrincipalName) {
          user.netid = profile.eduPersonPrincipalName
        }
        if (!user.email && !user.username && !user.netid) {
          throw new Error('Failed to generate a new user due to lack of profile data')
        }
        var _id = Accounts.createUser(user);
        user = Meteor.users.findOne({ _id: _id });
        if (!user) {
          throw new Error('Failed to find user after generation')
        }
      } else {
        Accounts.saml.debugLog('saml_server.js', '87', 'Could not find an existing user with credentials, generate users not set to true in settings', true);
        throw new Error('User not found with data provided by login response.')
      }
    }
    else {
      Accounts.saml.debugLog('saml_server.js', '92', 'User found', false);
    }

    var stampedToken = Accounts._generateStampedLoginToken();

    Meteor.users.update(user,
      { $set: { 'nameIDFormat': profile.nameIDFormat, 'nameID': profile.nameID } }
    );

    Accounts.saml.debugLog('saml_server.js', '101', 'registerLoginHandler user._id, stampedToken: ' + user._id + ',' + stampedToken.token, false);

    //sending token along with the userId
    return {
      userId: user._id,
      token: stampedToken.token
    };

  }
  Accounts.saml.debugLog('saml_server.js', '110', 'Throw SAML Profile did not contain an email address', true);
  throw new Error("SAML Profile did not contain an email address");

});

Accounts.saml._loginResultForCredentialToken = {};

Accounts.saml.hasCredential = function (credentialToken) {
  return _.has(Accounts.saml._loginResultForCredentialToken, credentialToken);
};

Accounts.saml.retrieveCredential = function (credentialToken) {
  let result = Accounts.saml._loginResultForCredentialToken[credentialToken];
  delete Accounts.saml._loginResultForCredentialToken[credentialToken];
  return result;
};

Accounts.saml.getDefaultUserQuery = function (profile) {
  if (!profile) {
    throw new Error('cannot create default query without profile')
  }
  var $or = [];

  // email can show up in the profile 3 ways
  if (profile.nameIDFormat === 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' && profile.nameID) {
    $or.push({ 'emails.address': profile.nameID })
  } else if (profile.email || profile.mail) {
    $or.push({ 'emails.address': profile.email || profile.mail })
  }
  if (profile.uid) {
    $or.push({ username: profile.uid })
  }
  if (profile.eduPersonPrincipalName) {
    $or.push({ eduPersonPrincipalName: profile.eduPersonPrincipalName })
    // eduPersonPrincipalName is sometimes reffered to the user's netid
    $or.push({ netid: profile.eduPersonPrincipalName })
  }
  if ($or.length < 1) {
    throw new Error('could not discern unique information from login response profile to query user.')
  }
  return { $or: $or }
}

// Listen to incoming OAuth http requests
WebApp.connectHandlers.use(function (req, res, next) {
  // Need to create a Fiber since we're using synchronous http calls and nothing
  // else is wrapping this in a fiber automatically

  if (req.method === 'POST') {
    let fullBody = '';
    req.on('data', function (chunk) {
      fullBody += chunk.toString();
    });

    req.on('end', function () {
      req.body = { SAMLResponse: decodeURIComponent(fullBody.replace('SAMLResponse=', '')) };
      Fiber(function () {
        middleware(req, res, next);
      }).run();
    });
  } else {
    Fiber(function () {
      middleware(req, res, next);
    }).run();
  }
});

middleware = function (req, res, next) {
  // Make sure to catch any exceptions because otherwise we'd crash
  // the runner
  try {
    var settings = getSamlSettigs();
    if (!settings) {
      Accounts.saml.debugLog(
        'saml_server.js',
        '183',
        'Could not find Meteor.settings.saml. Check your settings file.',
        true
      );
      throw new Error('Missing config settings');
    }
    let samlObject = samlUrlToObject(req.url);
    if (!samlObject || !samlObject.serviceName) {
      next();
      return;
    }

    if (!samlObject.actionName) {
      Accounts.saml.debugLog('saml_server.js', '198', 'Throw Missing SAML action', true);
      throw new Error('Missing SAML action');
    }

    let service = _.find({ settings }, function (samlSetting) {
      return samlSetting.provider === samlObject.serviceName;
    });

    // Skip everything if there's no service set by the saml middleware
    if (!service) {
      Accounts.saml.debugLog(
        'saml_server.js',
        '208',
        'Throw Unexpected SAML service ' + samlObject.serviceName,
        true
      );
      throw new Error('Unexpected SAML service ' + samlObject.serviceName);
    }
    switch (samlObject.actionName) {
      case 'authorize': {
        if (settings && settings.issuer) {
          service.callbackUrl = 'https://' + settings.issuer + '/_saml/validate/' + service.provider
        } else {
          Accounts.saml.debugLog('saml_server.js', '221', 'Issuer not set in SAML settings. Using ROOT_URL environment variable. If you are using localhost, this may cause issues with shibboleth.', false);
          service.callbackUrl = Meteor.absoluteUrl('/_saml/validate/' + service.provider);
        }
        service.id = samlObject.credentialToken;
        _saml = new SAML(service);
        _saml.getAuthorizeUrl(req, function (err, url) {
          if (err) {
            Accounts.saml.debugLog(
              'saml_server.js',
              '230',
              'Throw Unable to generate authorize url',
              true
            );
            throw new Error('Unable to generate authorize url');
          }
          res.writeHead(302, { Location: url });
          res.end();
        });
        break;
      }
      case 'validate': {
        _saml = new SAML(service);
        // decrypt response first, then validate the decrypted response
        let decryptedResponse = _saml.decryptSAMLResponse(req.body.SAMLResponse);
        _saml.validateResponse(decryptedResponse, req.body, function (err, profile) {
          if (err) {
            Accounts.saml.debugLog(
              'saml_server.js',
              '249',
              'Throw Unable to validate response url',
              true
            );
            throw new Error('Unable to validate response url');
          }

          let credentialToken =
            profile.inResponseToId || profile.InResponseTo || samlObject.credentialToken;
          if (!credentialToken) {
            Accounts.saml.debugLog(
              'saml_server.js',
              '261',
              'Throw Unable to determine credentialToken',
              true
            );
            throw new Error('Unable to determine credentialToken');
          }

          // Accounts.saml keys are hasCredential, retrieveCredential  TV
          Accounts.saml._loginResultForCredentialToken[credentialToken] = {
            profile,
          };

          Accounts.saml.debugLog(
            'saml_server.js',
            '275',
            'closePopup being called.  CredentialToken: ' + credentialToken,
            false
          );

          closePopup(res);
        });
        break;
      }
      case 'logout': {
        let userId = samlObject.credentialToken;
        const user = Meteor.users.findOne({ _id: userId });
        if (!user) {
          Accounts.saml.debugLog(
            'saml_server.js',
            '290',
            'No logged in user ' + samlObject.actionName,
            true
          );
          throw new Error('Attempted to log out a user but Meteor.user() returned null');
        }
        req.user = user;
        _saml = new SAML(service);
        _saml.getLogoutUrl(req, function (err, url) {
          if (err) {
            Accounts.saml.debugLog(
              'saml_server.js',
              '302',
              'Throw Unable to generate logout url',
              true
            );
            throw new Error('Unable to generate logout url');
          }
          res.writeHead(302, { Location: url });
          res.end();
        });
        break;
      }
      case 'validateLogout': {
        req.body = {
          SAMLResponse: decodeURIComponent(req.query.SAMLResponse.replace('SAMLResponse=', '')),
        };
        _saml = new SAML(service);
        _saml.verifyLogoutResponse(req.body.SAMLResponse);
        res.end();
        break;
      }
      case 'metadata': {
        _saml = new SAML(service);
        res.writeHead(200);
        res.write(_saml.generateServiceProviderMetadata());
        res.end();
        break;
      }
      default: {
        closePopup(res, err);
      }
    }
  } catch (err) {
    closePopup(res, err);
  }
};

var samlUrlToObject = function (url) {
  Accounts.saml.debugLog('saml_server.js', '339', "samlUtrlToObject: " + url, false);
  // req.url will be "/_saml/<action>/<service name>/<credentialToken>"
  if (!url) return null;

  let splitPath = url.split('/');

  // Any non-saml request will continue down the default
  // middlewares.
  if (splitPath[1] !== '_saml') return null;

  // logout response url has a query string that can get mixed up in the service name
  // the logout response should not have a credential token.
  return {
    actionName: splitPath[2],
    serviceName: splitPath[3].split('?')[0],
    credentialToken: splitPath[4],
  };
};

var closePopup = function (res, err) {
  res.writeHead(200, { 'Content-Type': 'text/html' });

  let content = '<html><head><script>window.close()</script></head></html>';
  if (err) {
    Accounts.saml.debugLog('saml_server.js', '363', 'Throw error: ' + err.reason, true);
    content =
      '<html><body><h2>Sorry, an error occured</h2><div>' +
      err +
      '</div><a onclick="window.close();">Close Window</a></body></html>';
  }

  res.end(content, 'utf-8');
};

var getSamlSettigs = function () {
  if (Meteor.settings && Meteor.settings.saml) return Meteor.settings.saml;
  return null
}
