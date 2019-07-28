const mongoose = require('mongoose')
const Schema = mongoose.Schema
const bcrypt = require('bcrypt-nodejs')

//Define our model
const userSchema = new Schema({
    email: { type: String, unique: true, lowercase: true },
    password: String,
})

//On save hook, encrypt password
//before saving a model, run this function
userSchema.pre('save', function(next) {
    //get access to the user model
    const user = this

    //generate a salt then run callback
    bcrypt.genSalt(10, function(err, salt) {
        if (err) {
            return next(err)
        }
        //hash (encrypt) our password using the salt
        bcrypt.hash(user.password, salt, null, function(err, hash) {
            if (err) {
                return next(err)
            }

            //overwrite plain text password with encrypted password
            user.password = hash
            next()
        })
    })
})

//methods is accessable
userSchema.methods.comparePassword = function(candidatePassword, callback) {
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
        if (err) {
            return callback(err)
        }
        callback(null, isMatch)
    })
}

//Create model class, model class correspond to a collection 'user' is the collection name
const ModelClass = mongoose.model('user', userSchema)

//export model
module.exports = ModelClass
