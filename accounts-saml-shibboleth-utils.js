var zlib = Npm.require('zlib');
var xmlCrypto = Npm.require('xml-crypto');
var crypto = Npm.require('crypto');
var xmldom = Npm.require('xmldom');
var querystring = Npm.require('querystring');
var xmlencryption = Npm.require('xml-encryption');
var xpath = Npm.require('xpath');
var fs = Npm.require('fs');
var xmlbuilder = Npm.require('xmlbuilder');

SAML = function (options) {
  // console.log('utils: constructor')
  this.options = this.initialize(options);
};

SAML.prototype.initialize = function (options) {
  // console.log('utils: initialize')
  if (!options) {
    options = {};
  }

  if (!options.protocol) {
    options.protocol = 'https://';
  }

  if (!options.path) {
    options.path = '/saml/consume';
  }

  if (!options.issuer) {
    options.issuer = 'onelogin_saml';
  }

  if (options.identifierFormat === undefined) {
    // options.identifierFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
    options.identifierFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
  }
  return options;
};

SAML.prototype.generateUniqueID = function () {
  // console.log('utils: generate unique id')
  var chars = "abcdef0123456789";
  var uniqueID = "";
  for (var i = 0; i < 20; i++) {
    uniqueID += chars.substr(Math.floor((Math.random() * 15)), 1);
  }
  return uniqueID;
};

SAML.prototype.generateInstant = function () {
  // console.log('utils: generate instant')
  return new Date().toISOString();
};

SAML.prototype.signRequest = function (xml) {
  // console.log('utils: sign request')
  var signer = crypto.createSign('RSA-SHA1');
  signer.update(xml);
  return signer.sign(this.options.spSamlKey, 'base64');
}

SAML.prototype.generateAuthorizeRequest = function (req) {
  // console.log('utils: generate authorize request')
  var id = "_" + this.generateUniqueID();
  var instant = this.generateInstant();

  // Post-auth destination
  if (this.options.callbackUrl) {
    callbackUrl = this.options.callbackUrl;
  } else {
    var callbackUrl = this.options.protocol + req.headers.host + this.options.path;
  }
  // console.log('utils: callbackUrl: ', callbackUrl)

  if (this.options.id)
    id = this.options.id;
  // console.log('login issuer: ', this.options.issuer)

  var request =
    "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"" + id + "\" Version=\"2.0\" IssueInstant=\"" + instant +
    "\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"" + callbackUrl + "\" Destination=\"" +
    this.options.entryPoint + "\">" +
    "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + this.options.issuer + "</saml:Issuer>\n";

  if (this.options.identifierFormat) {
    request += "<samlp:NameIDPolicy xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Format=\"" + this.options.identifierFormat +
      "\" AllowCreate=\"true\"></samlp:NameIDPolicy>\n";
  }

  request +=
    "<samlp:RequestedAuthnContext xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Comparison=\"exact\">" +
    "<saml:AuthnContextClassRef xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>\n" +
    "</samlp:AuthnRequest>";
  return request;
};

SAML.prototype.generateLogoutRequest = function (req) {
  // console.log('utils: generate logout request')
  var id = "_" + this.generateUniqueID();
  var instant = this.generateInstant();
  if (this.options.callbackUrl) {
    // console.log('utils: callbackUrl: ', callbackUrl)
    callbackUrl = this.options.callbackUrl;
  } else {
    var callbackUrl = this.options.protocol + req.headers.host + this.options.path;
  }

  // var request = "samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  // ID="_135ad2fd-b275-4428-b5d6-3ac3361c3a7f" Version="2.0" Destination="https://idphost/adfs/ls/"
  // IssueInstant="2008-06-03T12:59:57Z"><saml:Issuer>myhost</saml:Issuer><NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  // NameQualifier="https://idphost/adfs/ls/">myemail@mydomain.com</NameID<samlp:SessionIndex>_0628125f-7f95-42cc-ad8e-fde86ae90bbe
  // </samlp:SessionIndex></samlp:LogoutRequest>"
  // // console.log('logout issuer: ', this.options.issuer)

  var request = "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
    "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"" + id + "\" Version=\"2.0\" IssueInstant=\"" + instant +
    "\" AssertionConsumerServiceURL=\"" + "https://nate-dev-brms.ngrok.io/_saml/logoutRes/shibboleth-idp" + "\" Destination=\"" + this.options.logoutUrl + "\">" +
    "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + this.options.issuer + "</saml:Issuer>" +
    "<saml:NameID Format=\"" + req.user.profile.nameIDFormat + "\">" + req.user.profile.nameID + "</saml:NameID>" +
    "</samlp:LogoutRequest>";
  // console.log('request: ', request)
  return request;
}

SAML.prototype.requestToUrl = function (request, operation, callback) {
  // console.log('utils: request to url')
  // // console.log('utils: request: ', request)
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

SAML.prototype.getAuthorizeUrl = function (req, callback) {
  // console.log('utils: get authorize url')
  var request = this.generateAuthorizeRequest(req);

  this.requestToUrl(request, 'authorize', callback);
};

SAML.prototype.getLogoutUrl = function (req, callback) {
  // console.log('utils: get logout url')
  var request = this.generateLogoutRequest(req);

  this.requestToUrl(request, 'logout', callback);
}

SAML.prototype.certToPEM = function (cert) {
  // console.log('utils: cert to pem')
  cert = cert.match(/.{1,64}/g).join('\n');
  cert = "-----BEGIN CERTIFICATE-----\n" + cert;
  cert = cert + "\n-----END CERTIFICATE-----\n";
  return cert;
};

SAML.prototype.validateSignature = function (xml, cert) {
  // console.log('utils: validate signature')
  var self = this;
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var signature = xmlCrypto.xpath(doc, "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
  var sig = new xmlCrypto.SignedXml();
  sig.keyInfoProvider = {
    getKeyInfo: function (key) {
      return "<X509Data></X509Data>"
    },
    getKey: function (keyInfo) {
      return self.certToPEM(cert);
    }
  };
  sig.loadSignature(signature.toString());
  return sig.checkSignature(xml);
};

SAML.prototype.getElement = function (parentElement, elementName) {
  // console.log('utils: get element')
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

SAML.prototype.validateResponse = function (samlResponse, callback) {
  // console.log('utils: validate response')
  var self = this;
  var xmlDomDoc = new xmldom.DOMParser().parseFromString(samlResponse);
  try {
    var fname = "";
    if (Meteor.settings) {
      if (Meteor.settings['saml']) {
        if (Meteor.settings.saml[0]['authFields']) {
          fname = Meteor.settings.saml[0].authFields['fname'];
          Accounts.saml.debugLog('saml_util.js', '208', 'Loaded fname inside validate response for parsing saml.  fname: ' + fname, false);
        }
      }
    }

    // Verify signature
    //if (self.options.cert && !self.validateSignature(xml, self.options.cert)) {
    //    return callback(new Error('Invalid signature'), null, false);
    //}

    var assertion = xmlCrypto.xpath(xmlDomDoc, "//*[local-name(.)='Assertion']");
    if (assertion) {
      profile = {};

      var conditions = xmlCrypto.xpath(xmlDomDoc, "//*[local-name(.)='Assertion']/*[local-name(.)='Subject']");
      var authnStatement = xmlCrypto.xpath(xmlDomDoc, "//*[local-name(.)='Assertion']/*[local-name(.)='AuthnStatement']");

      //Get InResponseTo
      //sample...  1ed79ec15dfd
      var inResponseTo = xmlCrypto.xpath(xmlDomDoc, "//*[local-name(.)='SubjectConfirmationData']/@InResponseTo");
      if (inResponseTo) {
        profile.inResponseToId = inResponseTo[0].nodeValue;
      }

      //Get Issuer
      //sample...  https://idp.testshib.org/idp/shibboleth
      //Get Issuer
      //sample...  https://idp.testshib.org/idp/shibboleth
      var issuer = xpath.select("//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']/text()", xmlDomDoc);
      if (issuer) {
        profile.issuer = issuer[0].nodeValue;
      }

      //Get NameID
      //sample...
      var nameID = xmlCrypto.xpath(xmlDomDoc, "//*[local-name(.)='Assertion']/*[local-name(.)='Subject']/*[local-name(.)='NameID']/text()");
      // // console.log('nameId: ', nameID)
      if (nameID) {
        profile.nameID = nameID[0].nodeValue;
        // console.log('profile.nameID: ', profile.nameID)

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
              Accounts.saml.debugLog('saml_utils.js', '267', 'Error inside item.attributes for loop', true);
            }
          }
          if (profileKey) {
            try {
              profile[profileKey] = item.firstChild.firstChild.nodeValue;
            }
            catch (err) {
              Accounts.saml.debugLog('saml_utils.js', '275', 'Error setting the attribute ' + profileKey + ' on the profile.', true);
            }
          }
        });

        if (!profile.mail && profile['urn:oid:0.9.2342.19200300.100.1.3']) {
          // See http://www.incommonfederation.org/attributesummary.html for definition of attribute OIDs
          profile.mail = profile['urn:oid:0.9.2342.19200300.100.1.3'];
        }

        if (!profile.email && profile.mail) {
          profile.email = profile.mail;
        }
      }

      if (!profile.email && profile.nameID && profile.nameIDFormat && profile.nameIDFormat.indexOf('emailAddress') >= 0) {
        profile.email = profile.nameID;
      }

      if (!profile.email && profile.uid && isTestShib) {
        profile['email'] = profile.uid + '@testshib.org';
      }
      if (!profile.email && profile['eduPersonPrincipalName']) {
        Accounts.saml.debugLog('saml_utils.js', '305', 'Adding profile.email as eduPersonPrincipalName', false);
        profile['email'] = profile['eduPersonPrincipalName'];
      }

      callback(null, profile, false);
    } else {
      var logoutResponse = self.getElement(xmlDomDoc, 'LogoutResponse');
      Accounts.saml.debugLog('saml_utils.js', '307', 'Unknown SAML response message', true);

      if (logoutResponse) {
        callback(null, null, true);
      } else {
        return callback(new Error('Unknown SAML response message'), null, false);
      }

    }
  }
  catch (error) {
    Accounts.saml.debugLog('saml_utils.js', '318', 'Unknown SAML response message.. Error: ' + error, true);

    return callback(new Error('Unknown SAML response message'), null, false);
  }
};

//TRuby added below.
SAML.prototype.decryptSAMLResponse = function (samlResponse) {
  // console.log('utils: decrypt saml response')
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
      Accounts.saml.debugLog('saml_utils.js', '342', 'decryptSAMLResponse: ' + resultObj.result, false);
      return resultObj.result;
    }
  }
  catch (error) {
    Accounts.saml.debugLog('saml_utils.js', '347', 'error: ' + error, true);
    return null;
  }
}

SAML.prototype.decryptSAML = function (xml, options) {
  // console.log('utils: decrypt saml')
  Accounts.saml.debugLog('saml_utils.js', '353', 'decryptSAML', false);

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
  // console.log('symmetricKey: ', symmetricKey)
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

  //remove anything after </saml2:Assertion>  //test shib had a few binary characters after this..
  decrypted = decrypted.substring(0, decrypted.indexOf('</saml2:Assertion>')) + '</saml2:Assertion>';

  return {
    err: null,
    result: decrypted
  };
};

SAML.prototype.checkSAMLStatus = function (xmlDomDoc) {
  // console.log('utils: check saml status')
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
  //status.StatusMessage = xmlCrypto.xpath(xmlDomDoc, "//*[local-name(.)='StatusMessage']")[0].childNodes[0].nodeValue;
  //status.StatusDetail = xmlCrypto.xpath(xmlDomDoc, "//*[local-name(.)='StatusDetail']/*[local-name(.)='Cause']")[0].childNodes[0].nodeValue;
  return status;
};

SAML.prototype.generateServiceProviderMetadata = function () {
  // console.log('utils: generate metadata')
  var issuer = '';
  var spSamlKey = '';
  var spSamlCert = '';
  var callbackUrl = this.options.callbackUrl || 'https://nate-dev-brms.ngrok.io/_saml/validate/shibboleth-idp'
  var logoutCallbackUrl = this.options.logoutCallbackUrl || 'https://nate-dev-brms.ngrok.io/_saml/logoutRes/shibboleth-idp'
  var identifierFormat = null;
  if (Meteor.settings) {
    if (Meteor.settings['saml']) {
      if (Meteor.settings.saml[0]['authFields']) {
        issuer = Meteor.settings.saml[0]['issuer'];
        spSamlKey = Meteor.settings.saml[0]['spSamlKey']
        spSamlCert = Meteor.settings.saml[0]['spSamlCert']
        // callbackUrl = Meteor.settings.saml[0]['callbackUrl'] || issuer.replace('/shibboleth', ':443')
        Accounts.saml.debugLog('saml_server.js', '38', 'fetching metadata info from settings', false);
      }
    }
  }
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