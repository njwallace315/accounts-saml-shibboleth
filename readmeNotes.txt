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
