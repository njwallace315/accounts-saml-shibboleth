/* eslint-disable */
var zlib = Npm.require('zlib');
var xmlCrypto = Npm.require('xml-crypto');
var crypto = Npm.require('crypto');
var xmldom = Npm.require('xmldom');
var querystring = Npm.require('querystring');
var xmlencryption = Npm.require('xml-encryption');
var xpath = Npm.require('xpath');
var fs = Npm.require('fs');
var xml2js = Npm.require('xml2js')
var xmlbuilder = Npm.require('xmlbuilder');

SAML = function (options) {
  this.options = this.initialize(options);
};

SAML.prototype.initialize = function (options) {
  if (!options) {
    options = {};
  }

  if (!options.protocol) {
    options.protocol = 'https://';
  }

  if (!options.path) {
    options.path = '/_saml/';
  }

  if (!options.issuer) {
    options.issuer = Meteor.absoluteUrl().split;
  }

  if (options.issuer[options.issuer.length - 1] === '/') {
    options.issuer = options.issuer.substring(0, options.issuer.length - 1)
  }

  if (!options.provider) {
    options.provider = 'shibboleth-idp'
  }

  if (!options.callbackUrl) {
    options.callbackUrl = options.protocol + options.issuer + options.path + 'validate/' + options.provider
  }

  if (!options.logoutCallbackUrl) {
    options.logoutCallbackUrl = options.protocol + options.issuer + options.path + 'validateLogout/' + options.provider
  }

  if (!options.identifierFormat) {
    options.identifierFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  }
  return options;
};

SAML.prototype.generateUniqueID = function () {
  return crypto.randomBytes(10).toString('hex');
};

SAML.prototype.generateInstant = function () {
  return new Date().toISOString();
};

SAML.prototype.signRequest = function (xml) {
  var signer = crypto.createSign('RSA-SHA1');
  signer.update(xml);
  return signer.sign(this.options.spSamlKey, 'base64');
}

SAML.prototype.generateAuthorizeRequest = function (req) {
  const self = this;
  var id = "_" + this.generateUniqueID();
  var instant = this.generateInstant();

  if (this.options.id) id = this.options.id;

  var request = {
    'samlp:AuthnRequest': {
      '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
      '@ID': id,
      '@Version': '2.0',
      '@IssueInstant': instant,
      '@ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      '@Destination': this.options.entryPoint,
      'saml:Issuer': {
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        '#text': this.options.issuer
      }
    }
  };

  if (!this.options.disableRequestACSUrl) {
    request['samlp:AuthnRequest']['@AssertionConsumerServiceURL'] = this.options.callbackUrl
  }

  if (this.options.identifierFormat) {
    request['samlp:AuthnRequest']['samlp:NameIDPolicy'] = {
      '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
      '@Format': self.options.identifierFormat,
      '@AllowCreate': 'true'
    };
  }

  request['samlp:AuthnRequest']['samlp:RequestedAuthnContext'] = {
    '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
    '@Comparison': "exact",
    'saml:AuthnContextClassRef': {
      '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
      '#text': 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
    }
  };

  return xmlbuilder.create(request).end()
};

SAML.prototype.generateLogoutRequest = function (req) {
  var id = "_" + this.generateUniqueID();
  var instant = this.generateInstant();

  var request = {
    'samlp:LogoutRequest': {
      '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
      '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
      '@ID': id,
      '@Version': '2.0',
      '@IssueInstant': instant,
      '@AssertionConsumerServiceURL': this.options.logoutCallbackUrl,
      '@Destination': this.options.logoutUrl,
      'saml:Issuer': {
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        '#text': this.options.issuer
      },
      'saml2:NameID': {
        '@Format': req.user.nameIDFormat,
        '@NameQualifier': this.options.idpMetadataUrl,
        '@SPNameQualifier': this.options.issuer,
        '@xmlns:saml2': "urn:oasis:names:tc:SAML:2.0:assertion",
        '#text': req.user.nameID
      }
    }
  };

  return xmlbuilder.create(request).end()
}

SAML.prototype.requestToUrl = function (request, operation, callback) {
  var self = this;
  zlib.deflateRaw(request, function (err, buffer) {

    if (err) {
      return callback(err);
    }

    var base64 = buffer.toString('base64');
    var target = self.options.entryPoint;

    if (operation === 'logout') {
      if (self.options.logoutUrl) {
        target = self.options.logoutUrl;
      }
    }

    if (target.indexOf('?') > 0)
      target += '&';
    else
      target += '?';

    var samlRequest = {
      SAMLRequest: base64
    };

    if (self.options.spSamlKey) {
      samlRequest.SigAlg = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
      samlRequest.Signature = self.signRequest(querystring.stringify(samlRequest));
    }
    target += querystring.stringify(samlRequest);

    callback(null, target);
  });
}

SAML.prototype.inflateResponse = function (response, callback) {
  zlib.inflateRaw(response, function (err, inflated) {
    if (err) {
      return callback(err)
    }
    else return callback(null, inflated)
  })
}

SAML.prototype.getAuthorizeUrl = function (req, callback) {
  var request = this.generateAuthorizeRequest(req);

  this.requestToUrl(request, 'authorize', callback);
};

SAML.prototype.getLogoutUrl = function (req, callback) {
  var request = this.generateLogoutRequest(req);

  this.requestToUrl(request, 'logout', callback);
}

SAML.prototype.certToPEM = function (cert) {
  cert = cert.match(/.{1,64}/g).join('\n');

  if (cert.indexOf('-BEGIN CERTIFICATE-') === -1)
    cert = "-----BEGIN CERTIFICATE-----\n" + cert;
  if (cert.indexOf('-END CERTIFICATE-') === -1)
    cert = cert + "\n-----END CERTIFICATE-----\n";

  return cert;
};

SAML.prototype.validateSignature = function (xml, currentNode) {
  var self = this;
  var cert = self.options.idpCert
  var xpathSigQuery = ".//*[local-name(.)='Signature' and " +
    "namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']";
  var signatures = xmlCrypto.xpath(currentNode, xpathSigQuery);
  // This function is expecting to validate exactly one signature, so reject if we find more or fewer
  if (signatures.length !== 1) throw new Error('Could not find signature')
  var signature = signatures[0];

  var sig = new xmlCrypto.SignedXml();
  sig.keyInfoProvider = {
    getKeyInfo: function (key) {
      return "<X509Data></X509Data>"
    },
    getKey: function (keyInfo) {
      return cert
    }
  };
  sig.loadSignature(signature.toString());
  return sig.checkSignature(xml);
};

SAML.prototype.getElement = function (parentElement, elementName) {
  if (parentElement['saml:' + elementName]) {
    return parentElement['saml:' + elementName];
  } else if (parentElement['samlp:' + elementName]) {
    return parentElement['samlp:' + elementName];
  } else if (parentElement['saml2p:' + elementName]) {
    return parentElement['saml2p:' + elementName];
  } else if (parentElement['saml2:' + elementName]) {
    return parentElement['saml2:' + elementName];
  }
  return parentElement[elementName];
}

SAML.prototype.validateResponse = function (samlResponse, container, callback) {
  var self = this;
  var xmlDomDoc = new xmldom.DOMParser().parseFromString(samlResponse);
  try {
    var fname = "";
    if (this.options['authFields']) {
      fname = this.options.authFields['fname'];
      Accounts.saml.debugLog('saml_util.js', '258', 'Loaded fname inside validate response for parsing saml.  fname: ' + fname, false);
    }

    // Verify signature
    if (self.options.idpCert) {
      try {
        var xml = Buffer.from(container.SAMLResponse, 'base64').toString('utf8');
        var doc = new xmldom.DOMParser({}).parseFromString(xml);
        if (!doc.hasOwnProperty('documentElement'))
          throw new Error('SAMLResponse is not valid base64-encoded XML');
        if (!self.validateSignature(xml, doc.documentElement)) {
          throw new Error('Signature did not match idpCert')
        }
      } catch (err) {
        return callback(new Error('Invalid signature'), null);
      }
    } else {
      return callback(new Error('idpCert required in settings to validate signature'), null);
    }
    var assertion = xmlCrypto.xpath(xmlDomDoc, "//*[local-name(.)='Assertion']");
    if (assertion) {
      profile = {};

      //Get InResponseTo
      var inResponseTo = xmlCrypto.xpath(xmlDomDoc, "//*[local-name(.)='SubjectConfirmationData']/@InResponseTo");
      if (inResponseTo) {
        profile.inResponseToId = inResponseTo[0].nodeValue;
      }

      //Get Issuer
      var issuer = xpath.select("//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']/text()", xmlDomDoc);
      if (issuer) {
        profile.issuer = issuer[0].nodeValue;
      }

      //Get NameID
      var nameID = xmlCrypto.xpath(xmlDomDoc, "//*[local-name(.)='Assertion']/*[local-name(.)='Subject']/*[local-name(.)='NameID']/text()");
      if (nameID) {
        profile.nameID = nameID[0].nodeValue;

        var nameIDNode = xmlCrypto.xpath(xmlDomDoc, "//*[local-name(.)='Assertion']/*[local-name(.)='Subject']/*[local-name(.)='NameID']/@Format");
        if (nameIDNode[0]) {
          profile.nameIDFormat = nameIDNode[0].nodeValue;
        }
      }

      var attributeStatement = xmlCrypto.xpath(xmlDomDoc, "//*[local-name(.)='Assertion']/*[local-name(.)='AttributeStatement']");
      if (attributeStatement[0].childNodes) {
        xmlCrypto.xpath(xmlDomDoc, "//*[local-name(.)='Assertion']/*[local-name(.)='AttributeStatement']/*[local-name(.)='Attribute']").forEach(function (item, count) {
          var profileKey = null;
          for (var key in item.attributes) {
            try {
              if (item.attributes[key].nodeName == 'FriendlyName') {
                profileKey = item.attributes[key].nodeValue;
              }
              else if (item.attributes[key].nodeName == 'Name' && item.attributes[key].nodeValue == fname) {
                profileKey = item.attributes[key].nodeValue;
              }
            }
            catch (err) {
              Accounts.saml.debugLog('saml_utils.js', '317', 'Error inside item.attributes for loop', true);
            }
          }
          if (profileKey) {
            try {
              profile[profileKey] = item.firstChild.firstChild.nodeValue;
            }
            catch (err) {
              Accounts.saml.debugLog('saml_utils.js', '325', 'Error setting the attribute ' + profileKey + ' on the profile.', true);
            }
          }
        });

        if (!profile.mail && profile['urn:oid:0.9.2342.19200300.100.1.3']) {
          profile.mail = profile['urn:oid:0.9.2342.19200300.100.1.3'];
        }

        if (!profile.email && profile.mail) {
          profile.email = profile.mail;
        }
      }

      if (!profile.email && profile.nameID && profile.nameIDFormat && profile.nameIDFormat.indexOf('emailAddress') >= 0) {
        profile.email = profile.nameID;
      }

      /**
       * eduPersonalName seems to be a remnant of shibboleth 1.x
       * "it is commonly thought of as the global equivalent of a "netid""
       * it may be that we don't want this assigned to email
       */
      if (!profile.email && profile['eduPersonPrincipalName']) {
        Accounts.saml.debugLog('saml_utils.js', '349', 'Adding profile.email as eduPersonPrincipalName', false);
        profile['netid'] = profile['eduPersonPrincipalName'];
      }
      callback(null, profile);
    } else {
      return callback(new Error('Unknown SAML response message'), null);
    }
  }
  catch (error) {
    Accounts.saml.debugLog('saml_utils.js', '358', 'Unknown SAML response message.. Error: ' + error, true);

    return callback(new Error('Unknown SAML response message'), null);
  }
};

SAML.prototype.decryptSAMLResponse = function (samlResponse) {
  var self = this;
  var xml = new Buffer(samlResponse, 'base64').toString();

  try {
    var xmlDomDoc = new xmldom.DOMParser().parseFromString(xml);

    var encryptedDataNode = xmlCrypto.xpath(xmlDomDoc, "//*[local-name(.)='EncryptedData' and namespace-uri(.)='http://www.w3.org/2001/04/xmlenc#']")[0]

    var encryptedData = encryptedDataNode.toString();
    var spSamlKey = this.options.spSamlKey;
    var decryptOptions = { key: spSamlKey };
    var resultObj = self.decryptSAML(encryptedData, decryptOptions);

    if (resultObj.err) {
      return null;
    }
    else {
      Accounts.saml.debugLog('saml_utils.js', '382', 'decryptSAMLResponse: ' + resultObj.result, false);
      return resultObj.result;
    }
  }
  catch (error) {
    Accounts.saml.debugLog('saml_utils.js', '387', 'error: ' + error, true);
    return null;
  }
}

SAML.prototype.decryptSAML = function (xml, options) {
  Accounts.saml.debugLog('saml_utils.js', '393', 'decryptSAML', false);

  if (!options) {
    return {
      err: new Error('must provide options'),
      result: null
    };
  }
  if (!xml) {
    return {
      err: new Error('must provide XML to encrypt'),
      result: null
    };
  }
  if (!options.key) {
    return {
      err: new Error('key option is mandatory and you should provide a valid RSA private key'),
      result: null
    };
  }
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var symmetricKey = xmlencryption.decryptKeyInfo(doc, options);
  var encryptionMethod = xpath.select("/*[local-name(.)='EncryptedData']/*[local-name(.)='EncryptionMethod']", doc)[0];
  var encryptionAlgorithm = encryptionMethod.getAttribute('Algorithm');
  var encryptedContent = xpath.select("/*[local-name(.)='EncryptedData']/*[local-name(.)='CipherData']/*[local-name(.)='CipherValue']", doc)[0];
  var encrypted = new Buffer(encryptedContent.textContent, 'base64');
  var decrypted;
  var decipher;

  switch (encryptionAlgorithm) {
    case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
      decipher = crypto.createDecipheriv('aes-256-cbc', symmetricKey, encrypted.slice(0, 16));
      break;
    case 'http://www.w3.org/2001/04/xmlenc#aes128-cbc':
      decipher = crypto.createDecipheriv('aes-128-cbc', symmetricKey, encrypted.slice(0, 16));
      break;
    default:
      throw new Error('encryption algorithm ' + encryptionAlgorithm + ' not supported');
  }

  decipher.setAutoPadding(auto_padding = false);
  decrypted = decipher.update(encrypted.slice(16), 'base64', 'utf8') + decipher.final('utf8');

  //remove anything after </saml2:Assertion>
  decrypted = decrypted.substring(0, decrypted.indexOf('</saml2:Assertion>')) + '</saml2:Assertion>';

  return {
    err: null,
    result: decrypted
  };
};

SAML.prototype.verifyLogoutResponse = function (deflatedResponse) {
  const self = this;
  var data = Buffer.from(deflatedResponse, "base64")
  zlib.inflateRaw(data, function (err, inflated) {
    if (err) {
    }
    // if we have trouble validating signature we won't throw an error on logout
    var parserConfig = {
      explicitRoot: true,
      explicitCharKey: true,
      tagNameProcessors: [xml2js.processors.stripPrefix]
    };
    var parser = new xml2js.Parser(parserConfig);
    parser.parseString(inflated, function (err, doc) {
      if (err) {
        throw new Error('Error parsing logout response')
      }
      var statusCode = doc.LogoutResponse.Status[0].StatusCode[0].$.Value;
      if (statusCode === "urn:oasis:names:tc:SAML:2.0:status:Success") {
        return true;
      }
      throw new Error('Invalid status code, logout not successful')
    })
  })

};

SAML.prototype.checkSAMLStatus = function (xmlDomDoc) {
  var status = { StatusCodeValue: null, StatusMessage: null, StatusDetail: null }

  var statusCodeValueNode = xmlCrypto.xpath(xmlDomDoc, "//*[local-name(.)='StatusCode']")[0];
  if (statusCodeValueNode) {
    status.StatusCodeValue = statusCodeValueNode.getAttribute('Value');
  }

  var statusMessageNode = xmlCrypto.xpath(xmlDomDoc, "//*[local-name(.)='StatusMessage']")[0];
  if (statusMessageNode) {
    status.StatusMessage = statusMessageNode.childNodes[0].nodeValue;
  }

  var statusDetailNode = xmlCrypto.xpath(xmlDomDoc, "//*[local-name(.)='StatusDetail']/*[local-name(.)='Cause']")[0];
  if (statusDetailNode) {
    status.StatusDetail = statusDetailNode.childNodes[0].nodeValue;
  }
  return status;
};

SAML.prototype.generateServiceProviderMetadata = function () {
  var issuer = this.options.issuer;
  var spSamlKey = this.options.spSamlKey;
  var spSamlCert = this.options.spSamlCert;
  var callbackUrl = this.options.callbackUrl
  var logoutCallbackUrl = this.options.logoutCallbackUrl
  var identifierFormat = this.options.identifierFormat;

  var metadata = {
    'EntityDescriptor': {
      '@xmlns': 'urn:oasis:names:tc:SAML:2.0:metadata',
      '@xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
      '@entityID': issuer,
      '@ID': issuer.replace(/\W/g, '_'),
      'SPSSODescriptor': {
        '@protocolSupportEnumeration': 'urn:oasis:names:tc:SAML:2.0:protocol',
      },
    }
  };

  if (spSamlKey) {
    if (!spSamlCert) {
      throw new Error(
        "Missing spSamlCert while generating metadata for decrypting service provider");
    }
  }

  if (spSamlKey) {
    metadata.EntityDescriptor.SPSSODescriptor.KeyDescriptor = [];

    if (spSamlKey) {
      spSamlCert = spSamlCert.replace(/-+BEGIN CERTIFICATE-+\r?\n?/, '');
      spSamlCert = spSamlCert.replace(/-+END CERTIFICATE-+\r?\n?/, '');
      spSamlCert = spSamlCert.replace(/\r\n/g, '\n');

      metadata.EntityDescriptor.SPSSODescriptor.KeyDescriptor.push({
        '@use': 'encryption',
        'ds:KeyInfo': {
          'ds:X509Data': {
            'ds:X509Certificate': {
              '#text': spSamlCert
            }
          }
        },
        'EncryptionMethod': [
          // this should be the set that the xmlenc library supports
          { '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#aes256-cbc' },
          { '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#aes128-cbc' },
          { '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc' }
        ]
      });
      metadata.EntityDescriptor.SPSSODescriptor.KeyDescriptor.push({
        '@use': 'signing',
        'ds:KeyInfo': {
          'ds:X509Data': {
            'ds:X509Certificate': {
              '#text': spSamlCert
            }
          }
        }
      });
    }
  }
  if (logoutCallbackUrl) {
    metadata.EntityDescriptor.SPSSODescriptor.SingleLogoutService = {
      '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
      '@Location': logoutCallbackUrl
    };
  }

  metadata.EntityDescriptor.SPSSODescriptor.NameIDFormat = identifierFormat;
  metadata.EntityDescriptor.SPSSODescriptor.AssertionConsumerService = {
    '@index': '1',
    '@isDefault': 'true',
    '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    '@Location': callbackUrl,
  };
  return xmlbuilder.create(metadata).end({ pretty: true, indent: '  ', newline: '\n' });
};