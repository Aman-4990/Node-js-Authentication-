const passport = require('passport');
const bcryptjs = require('bcryptjs');
const nodemailer = require('nodemailer');
const { google } = require("googleapis");

const  OAuth2  = google.auth.OAuth2;

const jwt = require('jsonwebtoken');
const JWT_KEY = "jwtactive987";
const JWT_RESET_KEY = "jwtreset987";
require('dotenv').config();

//------------ User Model ------------//
const User = require('../models/User');

//------------ Register Handle ------------//
exports.registerHandle = (req, res) => {
    const { name, email, password, password2 } = req.body;
    let errors = [];

    //------------ Checking required fields ------------//
    if (!name || !email || !password || !password2) {
        errors.push({ msg: 'Please enter all fields' });
    }

    //------------ Checking password mismatch ------------//
    if (password != password2) {
        errors.push({ msg: 'Passwords do not match' });
    }

    //------------ Checking password length ------------//
    if (password.length < 8) {
        errors.push({ msg: 'Password must be at least 8 characters' });
    }

    if (errors.length > 0) {
        res.render('register', {
            errors,
            name,
            email,
            password,
            password2
        });
    } else {
        //------------ Validation passed ------------//
        User.findOne({ email: email }).then(user => {
            if (user) {
                //------------ User already exists ------------//
                errors.push({ msg: 'Email ID already registered' });
                res.render('register', {
                    errors,
                    name,
                    email,
                    password,
                    password2
                });
            } else {

                const oauth2Client = new OAuth2(
                    "173872994719-pvsnau5mbj47h0c6ea6ojrl7gjqq1908.apps.googleusercontent.com", // ClientID
                    "OKXIYR14wBB_zumf30EC__iJ", // Client Secret
                    "https://developers.google.com/oauthplayground" // Redirect URL
                );

                oauth2Client.setCredentials({
                    refresh_token: "1//04T_nqlj9UVrVCgYIARAAGAQSNwF-L9IrGm-NOdEKBOakzMn1cbbCHgg2ivkad3Q_hMyBkSQen0b5ABfR8kPR18aOoqhRrSlPm9w"
                });
                const accessToken = oauth2Client.getAccessToken()

                const token = jwt.sign({ name, email, password }, JWT_KEY, { expiresIn: '30m' });
                const CLIENT_URL = 'http://' + req.headers.host;

                const output = `
                <h2>Please click on below link to activate your account</h2>
                <p>${CLIENT_URL}/auth/activate/${token}</p>
                <p><b>NOTE: </b> The above activation link expires in 30 minutes.</p>
                `;

                const transporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                        type: "OAuth2",
                        user: "nodejsa@gmail.com",
                        clientId: "173872994719-pvsnau5mbj47h0c6ea6ojrl7gjqq1908.apps.googleusercontent.com",
                        clientSecret: "OKXIYR14wBB_zumf30EC__iJ",
                        refreshToken: "1//04T_nqlj9UVrVCgYIARAAGAQSNwF-L9IrGm-NOdEKBOakzMn1cbbCHgg2ivkad3Q_hMyBkSQen0b5ABfR8kPR18aOoqhRrSlPm9w",
                        accessToken: accessToken
                    },
                });

                // send mail with defined transport object
                const mailOptions = {
                    from: '"Auth Admin" <nodejs@gmail.com>', // sender address
                    to: email, // list of receivers
                    subject: "Account Verification: Mail ✔", // Subject line
                    generateTextFromHTML: true,
                    html: output, // html body
                };

                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.log(error);
                        req.flash(
                            'error_msg',
                            'Something went wrong on our end. Please register again.'
                        );
                        res.redirect('/auth/login');
                    }
                    else {
                        console.log('Mail sent : %s', info.response);
                        req.flash(
                            'success_msg',
                            'Activation link sent to email ID. Please activate to log in.'
                        );
                        res.redirect('/auth/login');
                    }
                })

            }
        });
    }
}

//------------ Activate Account Handle ------------//
exports.activateHandle = (req, res) => {
    const token = req.params.token;
    let errors = [];
    if (token) {
        jwt.verify(token, JWT_KEY, (err, decodedToken) => {
            if (err) {
                req.flash(
                    'error_msg',
                    'Incorrect or expired link! Please register again.'
                );
                res.redirect('/auth/register');
            }
            else {
                const { name, email, password } = decodedToken;
                User.findOne({ email: email }).then(user => {
                    if (user) {
                        //------------ User already exists ------------//
                        req.flash(
                            'error_msg',
                            'Email ID already registered! Please log in.'
                        );
                        res.redirect('/auth/login');
                    } else {
                        const newUser = new User({
                            name,
                            email,
                            password
                        });

                        bcryptjs.genSalt(10, (err, salt) => {
                            bcryptjs.hash(newUser.password, salt, (err, hash) => {
                                if (err) throw err;
                                newUser.password = hash;
                                newUser
                                    .save()
                                    .then(user => {
                                        req.flash(
                                            'success_msg',
                                            'Account activated. You can now log in.'
                                        );
                                        res.redirect('/auth/login');
                                    })
                                    .catch(err => console.log(err));
                            });
                        });
                    }
                });
            }

        })
    }
    else {
        console.log("Account activation error!")
    }
}

//------------ Forgot Password Handle ------------//
exports.forgotPassword = async (req, res) => {
    const { email } = req.body;
    let errors = [];

    // Checking required fields
    if (!email) {
        errors.push({ msg: 'Please enter an email ID' });
    }

    if (errors.length > 0) {
        return res.render('forgot', { errors, email });
    }

    try {
        const user = await User.findOne({ email });

        if (!user) {
            errors.push({ msg: 'User with Email ID does not exist!' });
            return res.render('forgot', { errors, email });
        }

        const oauth2Client = new OAuth2(
            "173872994719-pvsnau5mbj47h0c6ea6ojrl7gjqq1908.apps.googleusercontent.com", // Client ID
            "OKXIYR14wBB_zumf30EC__iJ", // Client Secret
            "https://developers.google.com/oauthplayground" // Redirect URL
        );

        oauth2Client.setCredentials({
            refresh_token: "1//04T_nqlj9UVrVCgYIARAAGAQSNwF-L9IrGm-NOdEKBOakzMn1cbbCHgg2ivkad3Q_hMyBkSQen0b5ABfR8kPR18aOoqhRrSlPm9w"
        });

        const accessToken = await oauth2Client.getAccessToken();

        const token = jwt.sign({ _id: user._id }, JWT_RESET_KEY, { expiresIn: '30m' });
        const CLIENT_URL = 'http://' + req.headers.host;
        const output = `
            <h2>Please click on below link to reset your account password</h2>
            <p>${CLIENT_URL}/auth/forgot/${token}</p>
            <p><b>NOTE: </b> The activation link expires in 30 minutes.</p>
        `;

        // Update resetLink for the user
        user.resetLink = token;
        await user.save(); // Save the updated user

        // Create transporter
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                type: "OAuth2",
                user: "nodejsa@gmail.com", // Your email
                clientId: "173872994719-pvsnau5mbj47h0c6ea6ojrl7gjqq1908.apps.googleusercontent.com",
                clientSecret: "OKXIYR14wBB_zumf30EC__iJ",
                refreshToken: "1//04T_nqlj9UVrVCgYIARAAGAQSNwF-L9IrGm-NOdEKBOakzMn1cbbCHgg2ivkad3Q_hMyBkSQen0b5ABfR8kPR18aOoqhRrSlPm9w",
                accessToken: accessToken
            },
        });

        const mailOptions = {
            from: '"Auth Admin" <nodejs@gmail.com>',
            to: email,
            subject: "Account Password Reset: Mail ✔",
            html: output,
        };

        await transporter.sendMail(mailOptions);
        req.flash('success_msg', 'Password reset link sent to email ID. Please follow the instructions.');
        res.redirect('/auth/login');

    } catch (err) {
        console.error(err);
    }
}


//------------ Redirect to Reset Handle ------------//
exports.gotoReset = async (req, res) => {
    const { token } = req.params;

    if (!token) {
        console.log("Password reset error!");
        return res.redirect('/auth/login');
    }

    try {
        const decodedToken = await jwt.verify(token, process.env.JWT_RESET_KEY);
        const { _id } = decodedToken;

        const user = await User.findById(_id);
        if (!user) {
            req.flash('error_msg', 'User with email ID does not exist! Please try again.');
            return res.redirect('/auth/login');
        }

        res.redirect(`/auth/reset/${_id}`);
    } catch (err) {
        req.flash('error_msg', 'Incorrect or expired link! Please try again.');
        res.redirect('/auth/login');
    }
};

exports.resetPassword = async (req, res) => {
    const { password, password2 } = req.body;
    const id = req.params.id;
    let errors = [];

    //------------ Checking required fields ------------//
    if (!password || !password2) {
        req.flash('error_msg', 'Please enter all fields.');
        return res.redirect(`/auth/reset/${id}`);
    }

    //------------ Checking password length ------------//
    if (password.length < 8) {
        req.flash('error_msg', 'Password must be at least 8 characters.');
        return res.redirect(`/auth/reset/${id}`);
    }

    //------------ Checking password mismatch ------------//
    if (password !== password2) {
        req.flash('error_msg', 'Passwords do not match.');
        return res.redirect(`/auth/reset/${id}`);
    }

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        await User.findByIdAndUpdate(id, { password: hashedPassword });
        req.flash('success_msg', 'Password reset successfully!');
        res.redirect('/auth/login');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Error resetting password!');
        res.redirect(`/auth/reset/${id}`);
    }
};

//------------ Login Handle ------------//
exports.loginHandle = (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/auth/login',
        failureFlash: true
    })(req, res, next);
}

//------------ Logout Handle ------------//
exports.logoutHandle = (req, res) => {
    req.logout((err) => {
        if (err) {
            req.flash('error_msg', 'Error logging out. Please try again.');
            return res.redirect('/auth/login');
        }
        req.flash('success_msg', 'You are logged out');
        res.redirect('/auth/login');
    });

}