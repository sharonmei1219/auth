const Authentication = require('./controllers/authentication')
const passportService = require('./services/passport')
const passport = require('passport')

//session is cookie based authentication, set it to false as we are using jwt
const requireAuth = passport.authenticate('jwt', { session: false })
const requireSignin = passport.authenticate('local', { session: false })

module.exports = function(app) {
    app.get('/', requireAuth, function(req, res, next) {
        res.send({ hi: 'there' })
    })

    app.post('/signin', requireSignin, Authentication.signin)
    app.post('/signup', Authentication.signup)
}
