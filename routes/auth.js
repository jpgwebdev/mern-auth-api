const express = require('express');
const router = express.Router();

// import controller
const {facebookLogin, googleLogin, signup, signin, accountActivation, forgotPassword, resetPassword} = require('../controllers/auth');

// import validators
const {userSignupValidator, userSigninValidator, resetPasswordValidator, forgotPasswordValidator} = require('../validators/auth');
const {runValidation} = require('../validators');

router.post('/signup', userSignupValidator, runValidation, signup);
router.post('/activate', accountActivation);
router.post('/signin', userSigninValidator, runValidation, signin);

//forgot reset password
router.put('/forgot-password', forgotPasswordValidator,runValidation, forgotPassword);
router.put('/reset-password', resetPasswordValidator,runValidation, resetPassword);

//google
router.post('/google-login', googleLogin);
//facebook
router.post('/facebook-login', facebookLogin);
module.exports = router;