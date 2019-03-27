if (!Accounts.saml) {
  Accounts.saml = {};
}

Accounts.saml.initiateLogin = function (options, callback, dimensions) {
  // default dimensions that worked well for facebook and google
  var popup = openCenteredPopup(
    Meteor.absoluteUrl("_saml/authorize/" + options.provider + "/" + options.credentialToken),
    (dimensions && dimensions.width) || 650,
    (dimensions && dimensions.height) || 500);

  var checkPopupOpen = setInterval(function () {
    try {
      // Fix for #328 - added a second test criteria (popup.closed === undefined)
      // to humour this Android quirk:
      // http://code.google.com/p/android/issues/detail?id=21061
      var popupClosed = popup.closed || popup.closed === undefined;
    } catch (e) {
      // For some unknown reason, IE9 (and others?) sometimes (when
      // the popup closes too quickly?) throws "SCRIPT16386: No such
      // interface supported" when trying to read 'popup.closed'. Try
      // again in 100ms.
      return;
    }

    if (popupClosed) {
      clearInterval(checkPopupOpen);
      callback(null, options.credentialToken);
    }
  }, 100);
};

var openCenteredPopup = function (url, width, height) {
  var screenX = typeof window.screenX !== 'undefined'
    ? window.screenX : window.screenLeft;
  var screenY = typeof window.screenY !== 'undefined'
    ? window.screenY : window.screenTop;
  var outerWidth = typeof window.outerWidth !== 'undefined'
    ? window.outerWidth : document.body.clientWidth;
  var outerHeight = typeof window.outerHeight !== 'undefined'
    ? window.outerHeight : (document.body.clientHeight - 22);
  // XXX what is the 22?

  // Use `outerWidth - width` and `outerHeight - height` for help in
  // positioning the popup centered relative to the current window
  var left = screenX + (outerWidth - width) / 2;
  var top = screenY + (outerHeight - height) / 2;
  var features = ('width=' + width + ',height=' + height +
    ',left=' + left + ',top=' + top + ',scrollbars=yes');

  Accounts.saml.debugLog('saml_client.js', '53', 'Open new window with url: ' + url, false);
  var newwindow = window.open(url, 'Login', features);
  if (newwindow.focus)
    newwindow.focus();
  return newwindow;
};

Meteor.loginWithSaml = function (options, callback) {
  if (Meteor.userId()) {
    callback('A user is already logged in')
    return;
  }
  options = options || {};
  var credentialToken = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
  options.credentialToken = credentialToken;

  Accounts.saml.initiateLogin(options, function (error, result) {
    if (result) {
      Accounts.saml.debugLog('saml_client.js', '67', 'result from initiateLogin: ' + result, false);
    } else {
      Accounts.saml.debugLog('saml_client.js', '69', 'error from initiateLogin: ' + error, true);
    }

    Accounts.callLoginMethod({
      methodArguments: [{ saml: true, credentialToken: credentialToken }],
      userCallback: callback
    });
  });
};

Meteor.logoutWithSaml = function (options, callback) {
  const userId = Meteor.userId();
  if (!userId) {
    callback('There is no logged in user')
    return;
  }
  Meteor.logout(() => {
    try {
      console.log(Meteor.settings.logoutLandingUrl || Meteor.absoluteUrl())
      window.location.href = "_saml/logout/" + options.provider + '/' + userId
      callback(null, 'Logout successful')
    } catch (err) {
      callback(err)
    }
  });
};

Meteor.goToLogoutLanding = function (options, callback) {
  console.log('here')
  if (Meteor.settings && Meteor.settings.saml && Meteor.settings.saml[0]) {
    window.location.href = Meteor.settings.saml[0].logoutLandingUrl || Meteor.absoluteUrl()
  } else {
    window.location.href = Meteor.absoluteUrl();
  }

}

