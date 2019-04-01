when the login result shows up the query to find the user is 
if (dbField === 'profile.studentID') {
    user = Meteor.users.findOne({ 'profile.studentID': profile[fname] });
} else if (dbField === 'emails.address') {
    user = Meteor.users.findOne({ 'emails.address': loginResult.profile.email });
} else {
    user = Meteor.users.findOne({dbField: profile[fname]})
}
Make it clear that I will (evenbtually) avoid putting data on the users profile field and 
it is ill-advised to have an 'fname' that begins with 'profile.'.

if generateUsers is set to true the user needs to run 'meteor add accounts-password' for now

Settings should contain a saml object. this should contain:

    spSamlCert: the public key that you generated for your service provider,
    spSamlKey: the private key that you generated for your service provider,
    entryPoint: The single-sign-on login url from your Idp,
    logoutUrl: The single-log-out logout url from your Idp,
    idpMetadataUrl: The url where the Idp's metadata file can be accessed,
    idpCert: Your Idp's public certificate. 


    --- optional ---
    generateUsers: (Boolean) if true, users who are authenticated but do not exist in the meteor users collection will have a document created and inserted.
    issuer: Your domain without any protocol or paths e.g. yourdomain.example.com
            if this is not specified the ROOT_URL environment variable will be used. this can cause problems if you are using localhost
    