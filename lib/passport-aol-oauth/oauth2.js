/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth').OAuth2Strategy;


/**
 * `Strategy` constructor.
 *
 * The AOL authentication strategy authenticates requests by delegating to
 * AOL using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your AOL application's client id
 *   - `callbackURL`   URL to which AOL will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new AOLStrategy({
 *         clientID: '123-456-789',
 *         callbackURL: 'https://www.example.net/auth/aol/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://api.screenname.aol.com/auth/authorize';
  options.tokenURL = options.tokenURL || 'https://api.screenname.aol.com/auth/access_token';
  options.scope = options.scope || ['profile'];

  //basic profile fields & optional email if scope is specified
  this.attributes = 'attribute=family_name,given_name,gender,birthdate,postalcode';
  if(options.scope.indexOf('email')){
    this.attributes += ',email';
  }
  
  OAuth2Strategy.call(this, options, verify);
  this.name = 'aol';
};

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from AOL.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `AOL`
 *   - `id`
 *   - `username`
 *   - `displayName`
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  this._oauth2.get('https://api.screenname.aol.com/auth/getUserData?bearer_token=' + accessToken + '&' + this.attributes + '&f=json', accessToken, function (err, body, res) {
    if (err) { return done(err); }

    try {
      var json = JSON.parse(body);

      var profile = { provider: 'aol' };
      profile.id = json.response.data.userData.loginId;
      profile.displayName = json.response.data.userData.displayName;
      profile.name = { familyName: json.response.data.userData.family_name,
                       givenName: json.response.data.userData.given_name };
      profile._raw = body;
      profile._json = json;

      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
