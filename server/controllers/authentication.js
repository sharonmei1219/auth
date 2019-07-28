const jwt = require('jwt-simple')
const config = require('../config')
const User = require('../models/user')

function tokenForUser(user) {
    const timestamp = new Date().getTime()
    return jwt.encode({ sub: user.id, iat: timestamp }, config.secret)
} //sub means subject, iat means issued at time

exports.signin = function(req, res, next) {
    //User already had their email and password auth'd
    res.json({ token: tokenForUser(req.user) })
}

exports.signup = function(req, res, next) {
    const email = req.body.email
    const password = req.body.password
    if (!email || !password) {
        res.status(422).send({ error: 'you must provide email and password' })
    }
    // see if a user with given email exist
    User.findOne({ email: email }, function(err, existingUser) {
        if (err) {
            return next(err)
        }
        // if a user with email does exist, return an error
        if (existingUser) {
            return res.status(422).send({ error: 'Emial is in use' })
        }
        // if a user with email does NOT exist, create and save user account
        const user = new User({ email: email, password: password }) //in memory

        user.save(function(err) {
            if (err) {
                return next(err)
            }
            // responde to request indicating that the user was created
            res.json({ token: tokenForUser(user) })
        }) //save to database
    })
}
