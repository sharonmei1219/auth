const passport = require('passport')
const User = require('../models/user')
const config = require('../config')
const JwtStrategy = require('passport-jwt').Strategy
const ExtractJwt = require('passport-jwt').ExtractJwt
const LocalStrategy = require('passport-local')

//Create local strategy
const localOptions = { usernameField: 'email' }
const localLogin = new LocalStrategy(localOptions, function(
    email,
    password,
    done
) {
    //Verify this username and password
    //if it is the correct username and password
    //otherwise call done (false)
    User.findOne({ email: email }, function(err, user) {
        if (err) {
            return done(err)
        }
        if (!user) {
            return done(null, false)
        }

        //compare password
        user.comparePassword(password, function(err, isMatch) {
            if (err) {
                return done(err)
            }
            if (!isMatch) {
                return done(null, false)
            }
            return done(null, user) //done is provided by passport, and passport serves as midware will
            //then pass on this user to the req in the router, say signin req
        })
    })
})

//Setup Stratey for JWT
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromHeader('authorization'), // tell passport where to extract jwt token from the request
    secretOrKey: config.secret,
}

//Create JWT strategy
//payload is decoded jwt token
//done is also a callback
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
    //see if the userId exist in our database
    //if it does, call done with that user
    //otherwise, call done without a user object
    User.findById(payload.sub, function(err, user) {
        if (err) {
            done(err, false)
        }

        if (user) {
            done(null, user)
        } else {
            done(null, false)
        }
    })
})

//Tell passport to use this strategy
passport.use(jwtLogin)
passport.use(localLogin)
