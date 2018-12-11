var router = require('express').Router()
var vulnDict = require('../config/vulns')
var authHandler = require('../core/authHandler')

module.exports = function (passport) {
	router.get('/', authHandler.isAuthenticated, function (req, res) {
		res.redirect('/learn')
	})

	router.get('/login', authHandler.isNotAuthenticated, function (req, res) {
		res.render('login')
	})

	router.get('/learn/hacking-web/vulnerability/:vuln', authHandler.isAuthenticated, function (req, res) {
		res.render('hacking-web-vulnerabilities/layout', {
			vuln: req.params.vuln,
			vuln_title: vulnDict['hackingWeb'][req.params.vuln],
			vuln_scenario: req.params.vuln + '/scenario',
			vuln_description: req.params.vuln + '/description',
			vuln_reference: req.params.vuln + '/reference',
			vulnerabilities:vulnDict['hackingWeb'],
			path: '/learn/hacking-web/vulnerability/'+req.params.vuln
		}, function (err, html) {
			if (err) {
				console.log(err)
				res.status(404).send('404')
			} else {
				res.send(html)
			}
		})
	})

	router.get('/learn/cryptography/vulnerability/:vuln', authHandler.isAuthenticated, function (req, res) {
		res.render('cryptography-vulnerabilities/layout', {
			vuln: req.params.vuln,
			vuln_title: vulnDict['cryptography'][req.params.vuln],
			vuln_scenario: req.params.vuln + '/scenario',
			vuln_description: req.params.vuln + '/description',
			vuln_reference: req.params.vuln + '/reference',
			vulnerabilities:vulnDict['cryptography'],
			path: '/learn/cryptography/vulnerability/'+req.params.vuln
		}, function (err, html) {
			if (err) {
				console.log(err)
				res.status(404).send('404')
			} else {
				res.send(html)
			}
		})
	})

	router.get('/learn', authHandler.isAuthenticated, function (req, res) {
		console.log(vulnDict);
		const keysHackingWeb = Object.keys(vulnDict['hackingWeb']);
		const mainKeyHackingWeb = keysHackingWeb[0];

		const keysCryptography = Object.keys(vulnDict['cryptography']);
		const mainKeyCryptography = keysCryptography[0];
		
		res.render('learn',{
			vulnerabilities:vulnDict['hackingWeb'],
			hackingWebMainVulnerability: mainKeyHackingWeb,
			cryptographyMainVulnerability: mainKeyCryptography
		})
	})

	router.get('/register', authHandler.isNotAuthenticated, function (req, res) {
		res.render('register')
	})

	router.get('/logout', function (req, res) {
		req.logout();
		res.redirect('/');
	})

	router.get('/forgotpw', function (req, res) {
		res.render('forgotpw')
	})

	router.get('/resetpw', authHandler.resetPw)

	router.post('/login', passport.authenticate('login', {
		successRedirect: '/learn',
		failureRedirect: '/login',
		failureFlash: true
	}))

	router.post('/register', passport.authenticate('signup', {
		successRedirect: '/learn',
		failureRedirect: '/register',
		failureFlash: true
	}))

	router.post('/forgotpw', authHandler.forgotPw)

	router.post('/resetpw', authHandler.resetPwSubmit)

	return router
}