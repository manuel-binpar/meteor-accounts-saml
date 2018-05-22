'use strict';

if (!Accounts.saml) {
    Accounts.saml = {};
}

let Fiber = Npm.require('fibers');
//let connect = Npm.require('connect');
let bodyParser = Npm.require('body-parser');
let _ = Npm.require('underscore');
let busboy = Npm.require('connect-busboy');

//RoutePolicy.declare('/login/', 'network');

Meteor.methods({
    samlLogout: function (provider) {
        // Make sure the user is logged in before initiate SAML SLO
        if (!Meteor.userId()) {
            throw new Meteor.Error("not-authorized");
        }
        let samlProvider = function (element) {
            return (element.provider == provider)
        }
        providerConfig = Meteor.settings.private.saml.filter(samlProvider)[0];

        if (Meteor.settings.debug) {
            console.log("Logout request from " + JSON.stringify(providerConfig));
        }
        // This query should respect upcoming array of SAML logins
        let user = Meteor.users.findOne({
            _id: Meteor.userId(),
            "services.saml.provider": provider
        }, {
            "services.saml": 1
        });
        let nameID = user.services.saml.nameID;
        let sessionIndex = nameID = user.services.saml.idpSession;
        if (Meteor.settings.debug) {
            console.log("NameID for user " + Meteor.userId() + " found: " + JSON.stringify(nameID));
        }

        _saml = new SAML(providerConfig);

        let request = _saml.generateLogoutRequest({
            nameID: nameID,
            sessionIndex: sessionIndex
        });

        // request.request: actual XML SAML Request
        // request.id: comminucation id which will be mentioned in the ResponseTo field of SAMLResponse

        Meteor.users.update({
            _id: Meteor.userId()
        }, {
            $set: {
                'services.saml.inResponseTo': request.id
            }
        });

        let _syncRequestToUrl = Meteor.wrapAsync(_saml.requestToUrl, _saml);
        let result = _syncRequestToUrl(request.request, "logout");
        if (Meteor.settings.debug) {
            console.log("SAML Logout Request " + result);
        }

        return result;
    }
})

Accounts.registerLoginHandler(function (loginRequest) {
    if (!loginRequest.saml || !loginRequest.credentialToken) {
        return undefined;
    }
    let loginResult = Accounts.saml.retrieveCredential(loginRequest.credentialToken);
    if (Meteor.settings.debug) {
        console.log("RESULT :" + JSON.stringify(loginResult));
    }

    if (loginResult && loginResult.profile && loginResult.profile.nameID) {
        console.log("Profile: " + JSON.stringify(loginResult.profile.nameID));
        let localProfileMatchAttribute;
        let localFindStructure;
        let nameIDFormat;
        // Default nameIDFormat is emailAddress
        nameIDFormat = Meteor.settings.private.saml[0].identifierFormat;

        if (nameIDFormat == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress") {
            // If nameID Format is emailAdress, we should not force 'email' as localProfileMatchAttribute
            localProfileMatchAttribute = "email";
            localFindStructure = "emails.address";
            profileOrEmail = "email";
            profileOrEmailValue = loginResult.profile.nameID;
        } else // any other nameID format
            // Check if Meteor.settings.private.saml[0].localProfileMatchAttribute has value
            // These values will be stored in profile substructure. They're NOT security relevant because profile isn't a safe place
            if (Meteor.settings.private.saml[0].localProfileMatchAttribute) {
                profileOrEmail = "profile";
                profileOrEmailValue = {
                    [Meteor.settings.private.saml[0].localProfileMatchAttribute]: loginResult.profile.nameID
                };
                localFindStructure = 'profile.' + Meteor.settings.private.saml[0].localProfileMatchAttribute;
            }
        if (Meteor.settings.debug) {
            console.log("Looking for user with " + localFindStructure + "=" + loginResult.profile.nameID);
        }
        let user = Meteor.users.findOne({
            //profile[Meteor.settings.private.saml[0].localProfileMatchAttribute]: loginResult.profile.nameID
            [localFindStructure]: loginResult.profile.nameID
        });

        if (!user) {
            if (Meteor.settings.private.saml[0].dynamicProfile) {
                if (Meteor.settings.debug) {
                    console.log("User not found. Will dynamically create one with '" + Meteor.settings.private.saml[0].localProfileMatchAttribute + "' = " + loginResult.profile[Meteor.settings.private.saml[0].localProfileMatchAttribute]);
                    console.log("Identity handle: " + profileOrEmail + " = " + JSON.stringify(profileOrEmailValue) + " || username = " + loginResult.profile.nameID);
                }
                Accounts.createUser({
                    //email: loginResult.profile.email,
                    password: "",
                    username: loginResult.profile.nameID,
                    [profileOrEmail]: profileOrEmailValue

                    //[Meteor.settings.private.saml[0].localProfileMatchAttribute]: loginResult.profile[Meteor.settings.private.saml[0].localProfileMatchAttribute]
                });
                if (Meteor.settings.debug) {
                    console.log("Trying to find user");
                }
                user = Meteor.users.findOne({
                    "username": loginResult.profile.nameID
                });
                // update user profile w attrs from SAML Attr Satement
                //Meteor.user.update(user, )
                if (Meteor.settings.debug) {
                    console.log("Profile for attributes: " + JSON.stringify(loginResult.profile));
                }
                let attributeNames = Meteor.settings.private.saml[0].attributesSAML;
                let meteorProfile = {};
                if (attributeNames) {
                    attributeNames.forEach(function (attribute) {
                        meteorProfile[attribute] = loginResult.profile[attribute];
                    });
                }
                if (Meteor.settings.debug) {
                    console.log("Profile for Meteor: " + JSON.stringify(meteorProfile));
                }
                Meteor.users.update(user, {
                    $set: {
                        'profile': meteorProfile
                    }
                });
                if (Meteor.settings.debug) {
                    console.log("Created new user");
                }
            } else {
                throw new Error("Could not find an existing user with supplied attribute  '" + Meteor.settings.private.saml[0].localProfileMatchAttribute + "' and value:" + loginResult.profile[Meteor.settings.private.saml[0].localProfileMatchAttribute]);
            }
        }

        //creating the token and adding to the user
        let stampedToken = Accounts._generateStampedLoginToken();
        Meteor.users.update(user, {
            $push: {
                'services.resume.loginTokens': stampedToken
            }
        });

        let samlLogin = {
            provider: Accounts.saml.RelayState,
            idp: loginResult.profile.issuer,
            idpSession: loginResult.profile.sessionIndex,
            nameID: loginResult.profile.nameID
        };

        Meteor.users.update({
            _id: user._id
        }, {
            $set: {
                // TBD this should be pushed, otherwise we're only able to SSO into a single IDP at a time
                'services.saml': samlLogin
            }
        });

        if (loginResult.profile.uid) {
            Meteor.users.update({
                _id: user._id
            }, {
                $set: {
                    // TBD this should be pushed, otherwise we're only able to SSO into a single IDP at a time
                    'uid': loginResult.profile.uid
                }
            });
        }

        let attributeNames = Meteor.settings.private.saml[0].attributesSAML;
        let meteorProfile = {};
        if (attributeNames) {
            attributeNames.forEach(function (attribute) {
                meteorProfile[attribute] = loginResult.profile[attribute];
            });
        }
        if (Meteor.settings.debug) {
            console.log("Profile Update for Meteor: " + JSON.stringify(meteorProfile));
        }
        Meteor.users.update({
            _id: user._id
        }, {
            $set: {
                'profile': meteorProfile
            }
        });

        //sending token along with the userId
        let result = {
            userId: user._id,
            token: stampedToken.token
        };

        return result

    } else {
        throw new Error("SAML Assertion did not contain a proper SAML subject value");
    }
});

Accounts.saml._loginResultForCredentialToken = {};

Accounts.saml.hasCredential = function (credentialToken) {
    return _.has(Accounts.saml._loginResultForCredentialToken, credentialToken);
}

Accounts.saml.retrieveCredential = function (credentialToken) {
    // The credentialToken in all these functions corresponds to SAMLs inResponseTo field and is mandatory to check.
    let result = Accounts.saml._loginResultForCredentialToken[credentialToken];
    delete Accounts.saml._loginResultForCredentialToken[credentialToken];
    return result;
}

// Listen to incoming SAML http requests
// WebApp.connectHandlers.use(bodyParser.urlencoded({
//     extended: true
// })).use(function(req, res, next) {
//     // Need to create a Fiber since we're using synchronous http calls and nothing
//     // else is wrapping this in a fiber automatically
//     Fiber(function() {
//         middleware(req, res, next);
//     }).run();
// });

// middleware = function(req, res, next) {
//     // Make sure to catch any exceptions because otherwise we'd crash
//     // the runner
//     try {
//         let samlObject = samlUrlToObject(req.url);
//         if (!samlObject || !samlObject.serviceName) {
//             next();
//             return;
//         }

//         if (!samlObject.actionName)
//             throw new Error("Missing SAML action");

//         /* let service = _.find(Meteor.settings.private.saml, function(samlSetting) {
//             console.log(samlSetting.provider === samlObject.serviceName);
//             return samlSetting.provider === samlObject.serviceName;
//         }); */
//         let service = Meteor.settings.private.saml;
//         console.log("service", service);
//         // Skip everything if there's no service set by the saml middleware
//         if (!service)
//             throw new Error("Unexpected SAML service " + samlObject.serviceName);
//         switch (samlObject.actionName) {
//             case "metadata":
//                 _saml = new SAML(service);
//                 service.callbackUrl = Meteor.settings.private.saml.idpSLORedirectURL; //Meteor.absoluteUrl("_saml/validate/" + service.provider);
//                 res.writeHead(200);
//                 res.write(_saml.generateServiceProviderMetadata(service.callbackUrl));
//                 res.end();
//                 //closePopup(res);
//                 break;
//             case "logout":
//                 // This is where we receive SAML LogoutResponse
//                 if (Meteor.settings.debug) {
//                     console.log("Handling call to 'logout' endpoint." + req.query.SAMLResponse);
//                 }
//                 _saml = new SAML(service);
//                 _saml.validateLogoutResponse(req.query.SAMLResponse, function(err, result) {
//                     if (!err) {
//                         let logOutUser = function(inResponseTo) {
//                             if (Meteor.settings.debug) {
//                                 console.log("Logging Out user via inResponseTo " + inResponseTo);
//                             }
//                             let loggedOutUser = Meteor.users.find({
//                                 'services.saml.inResponseTo': inResponseTo
//                             }).fetch();
//                             if (loggedOutUser.length == 1) {
//                                 if (Meteor.settings.debug) {
//                                     console.log("Found user " + loggedOutUser[0]._id);
//                                 }
//                                 Meteor.users.update({
//                                     _id: loggedOutUser[0]._id
//                                 }, {
//                                     $set: {
//                                         "services.resume.loginTokens": []
//                                     }
//                                 });
//                                 Meteor.users.update({
//                                     _id: loggedOutUser[0]._id
//                                 }, {
//                                     $unset: {
//                                         "services.saml": ""
//                                     }
//                                 });
//                             } else {
//                                 throw new Meteor.error("Found multiple users matching SAML inResponseTo fields");
//                             }
//                         }

//                         Fiber(function() {
//                             logOutUser(result);
//                         }).run();


//                         res.writeHead(302, {
//                             'Location': req.query.RelayState
//                         });
//                         res.end();
//                     } else {
//                       if (Meteor.settings.debug) {
//                           console.log("Couldn't validate SAML Logout Response..");
//                       }
//                     }
//                 })
//                 break;
//             case "sloRedirect":
//                 let idpLogout = req.query.redirect
//                 res.writeHead(302, {
//                     // credentialToken here is the SAML LogOut Request that we'll send back to IDP
//                     'Location': idpLogout
//                 });
//                 res.end();
//                 break;
//             case "authorize":
//                 service.callbackUrl = Meteor.settings.private.saml.idpSLORedirectURL; //Meteor.absoluteUrl("_saml/validate/" + service.provider);
//                 service.id = samlObject.credentialToken;
//                 console.log("service", service);
//                 _saml = new SAML(service);
//                 console.log("saml", _saml);
//                 _saml.getAuthorizeUrl(req, function(err, url) {
//                     if (err)
//                         throw new Error("Unable to generate authorize url");
//                     res.writeHead(302, {
//                         'Location': url
//                     });
//                     res.end();
//                 });
//                 break;
//             case "callback": //validate => _saml/validate
//                 console.log("Entrada SAML");
//                 _saml = new SAML(service);
//                 if (Meteor.settings.debug) {
//                   console.log("Service: " + JSON.stringify(service));
//                 };
//                 Accounts.saml.RelayState = req.body.RelayState;
//                 _saml.validateResponse(req.body.SAMLResponse, req.body.RelayState, function(err, profile, loggedOut) {
//                     if (err)
//                         throw new Error("Unable to validate response url: " + err);

//                     let credentialToken = profile.inResponseToId || profile.InResponseTo || samlObject.credentialToken;
//                     if (!credentialToken)
//                         throw new Error("Unable to determine credentialToken");
//                     Accounts.saml._loginResultForCredentialToken[credentialToken] = {
//                         profile: profile
//                     };
//                     closePopup(res);
//                 });
//                 break;
//             default:
//                 throw new Error("Unexpected SAML action " + samlObject.actionName);

//         }
//     } catch (err) {
//         closePopup(res, err);
//     }
// };

let samlUrlToObject = function (url) {
    // req.url will be "/_saml/<action>/<service name>/<credentialToken>"
    if (!url)
        return null;

    let splitPath = url.split('/');

    // Any non-saml request will continue down the default
    // middlewares.
    console.log(url);
    /* if (splitPath[1] !== '_saml')
        return null; */

    let result = {
        actionName: splitPath[2],
        serviceName: splitPath[3],
        credentialToken: splitPath[4]
    };
    if (Meteor.settings.debug) {
        console.log(result);
    }
    return result;
};

let closePopup = function (res, err) {
    res.writeHead(200, {
        'Content-Type': 'text/html'
    });
    let content =
        '<html><head><script>window.close()</script></head><body><H1>Verified</H1></body></html>';
    if (err)
        content = '<html><body><h2>Error</h2><div>' + err + '</div><a onclick="window.close();">Cerrar ventana</a></body></html>';
    res.end(content, 'utf-8');
};

WebApp.connectHandlers.use(busboy());
WebApp.connectHandlers.use("/login/callback", (req, res, next) => {

    /* let service = _.find(Meteor.settings.private.saml, function(samlSetting) {
    	console.log(samlSetting.provider === samlObject.serviceName);
    	return samlSetting.provider === samlObject.serviceName;
    }); */
    let samlObject = samlUrlToObject(req.originalUrl);
    let service = Meteor.settings.private.saml;

    try {
        _saml = new SAML(service);
        if (Meteor.settings.debug) {
            console.log("Service: " + JSON.stringify(service));
        };

        let body = '';

        req.on('data', Meteor.bindEnvironment(function (data) {
            //console.log('on data: ', data.toString());
            body += data;
        }));

        req.on('end', Meteor.bindEnvironment(function () {

            try {
                let obj = {}; 
                body.replace(/([^=&]+)=([^&]*)/g, function(m, key, value) {
                    obj[decodeURIComponent(key)] = decodeURIComponent(value);
                }); 

                Accounts.saml.RelayState = obj.RelayState;
                //console.log("obj.SAMLResponse", obj.SAMLResponse);
                _saml.validateResponse(obj.SAMLResponse, obj.RelayState, function (err, profile, loggedOut) {
                    if (err)
                        throw new Error("Unable to validate response url: " + err);

                    console.log("profile", profile);

                    let credentialToken = profile.inResponseToId || profile.InResponseTo || samlObject.credentialToken;
                    if (!credentialToken)
                        throw new Error("Unable to determine credentialToken");

                    Accounts.saml._loginResultForCredentialToken[credentialToken] = {
                        profile: profile
                    };

                    res.end(`Login OK`);
                    //closePopup(res);
                });
                req.pipe(req.busboy);
                res.end(`Login FAIL`);

            } catch (e) {
                res.error = `
                ${e.reason || e.message}:
                ${e.stack}
                `;
                console.log('Error! ', res.error);
                res.writeHead(200);
            }
        }));
    } catch (err) {
        console.log(err);
        res.writeHead(500);
        res.end(JSON.stringify(err));
    }
});

WebApp.connectHandlers.use("/_saml/authorize", (req, res, next) => {

    /* let service = _.find(Meteor.settings.private.saml, function(samlSetting) {
    	console.log(samlSetting.provider === samlObject.serviceName);
    	return samlSetting.provider === samlObject.serviceName;
    }); */
    let samlObject = samlUrlToObject(req.originalUrl);
    let service = Meteor.settings.private.saml;
    console.log(samlObject);
    try {
        service.callbackUrl = Meteor.settings.private.saml.idpSLORedirectURL; //Meteor.absoluteUrl("_saml/validate/" + service.provider);
        service.id = samlObject.credentialToken;
        _saml = new SAML(service);

        _saml.getAuthorizeUrl(req, function (err, url) {
            if (err)
                throw new Error("Unable to generate authorize url");
            res.writeHead(302, {
                'Location': url
            });
            res.end();
        });
    } catch (err) {
        console.log(err);
        res.writeHead(500);
        res.end(JSON.stringify(err));
    }
});