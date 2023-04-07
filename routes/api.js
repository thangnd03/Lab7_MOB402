var passport = require('passport');
var config = require('../config/database');
require('../config/passport')(passport);
var express = require('express');
var jwt = require('jsonwebtoken');
var router = express.Router();
var User = require("../models/user");
var Book = require("../models/book");

const bodyParser = require("body-parser");
const { checkAccount, checkLogin } = require('../middleware/auth');

// // parse requests of content-type - application/json
router.use(bodyParser.json());

const parser = bodyParser.urlencoded({ extended: true });

router.use(parser);

router.get('/login', (req, res) => {
    console.log(req.session.userReg);
    res.render('login', { layout: 'form', user: req.session.userReg });
});

router.get('/signup', (req, res) => {
    res.render('signup', { layout: 'form' });
});

router.post('/signup', checkAccount, async function (req, res) {
    console.log(req.body);
    if (!req.body.username || !req.body.pass) {
        res.json({ success: false, msg: 'Please pass username and password.' });
    } else {
        var newUser = new User({
            username: req.body.username,
            password: req.body.pass
        });
        // save the user
        await newUser.save();
        req.session.userReg = { username: newUser.username, password: req.body.pass };
        res.redirect('/api/login')
        // res.json({ success: true, msg: 'Successful created new user.' });
    }
});


router.post('/login', async function (req, res) {
    let user = await User.findOne({ username: req.body.username });
    if (!user) {
        res.status(401).send({ success: false, msg: 'Authentication failed. User not found.' });
    } else {
        // check if password matches
        user.comparePassword(req.body.pass, function (err, isMatch) {
            if (isMatch && !err) {
                // if user is found and password is right create a token
                var token = jwt.sign(user.toJSON(), config.secret);
                // return the information including token as JSON
                res.json({ success: true, token: 'JWT ' + token });
            } else {
                res.status(401).send({ success: false, msg: 'Authentication failed. Wrong password.' });
            }
        });
    }
});

router.get('/book', passport.authenticate('jwt', { session: false }), async function (req, res) {
    console.log(req.headers);
    var token = getToken(req.headers);
    if (token) {
        jwt.verify(token, config.secret, async function (err, decoded) {
            if (err) {
                console.error(err);
                return res.status(403).send({ success: false, msg: 'Unauthorized.' });
            } else {
                let books = await Book.find();
                console.log(token);
                res.render("listBook", { listBook: books.map((book) => book.toObject()) });
            }
        });
        // let books = await Book.find();
        // console.log(token);
        // res.render("listBook", { listBook: books.map((book) => book.toObject()) });
    } else {
        return res.status(403).send({ success: false, msg: 'Unauthorized.' });
    }
});

router.post('/book', passport.authenticate('jwt', { session: false }), function (req, res) {
    var token = getToken(req.headers);
    if (token) {
        console.log(req.body);
        var newBook = new Book({
            isbn: req.body.isbn,
            title: req.body.title,
            author: req.body.author,
            publisher: req.body.publisher
        });
        try {
            newBook.save();
            res.json({ success: true, msg: 'Successful created new book.' });
        } catch (error) {
            return res.json({ success: false, msg: 'Save book failed.' });
        }

    } else {
        return res.status(403).send({ success: false, msg: 'Unauthorized.' });
    }
});

const getToken = (headers) => {
    if (headers && headers.authorization) {
        var parted = headers.authorization.split(' ');
        if (parted.length === 2) {
            return parted[1];
        } else {
            return null;
        }
    } else {
        return null;
    }
};

module.exports = router;
