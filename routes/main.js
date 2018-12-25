var router = require('express').Router()
var vulnDict = require('../config/vulns')
var authHandler = require('../core/authHandler')
var db = require('../models')
const Op = db.Sequelize.Op

module.exports = function (passport) {
	router.get('/', authHandler.isAuthenticated, function (req, res) {
		res.redirect('/learn')
	})

	router.get('/login', authHandler.isNotAuthenticated, function (req, res) {
		res.render('login')
	})

	function renderWeb(req, res, mode) {
		let path = '/learn/hacking-web/vulnerability/'+req.params.vuln;
		let owaspPath = '/learn/hacking-web-owasp/vulnerability/'+req.params.vuln;
		let layersPath = '/learn/hacking-web/vulnerability/'+req.params.vuln;
		if (mode === 2) {
			path = '/learn/hacking-web-owasp/vulnerability/'+req.params.vuln;
		} 
		res.render('hacking-web-vulnerabilities/layout', {
			vuln: req.params.vuln,
			vuln_title: vulnDict['hackingWeb'][req.params.vuln],
			vuln_scenario: req.params.vuln + '/scenario',
			vuln_description: req.params.vuln + '/description',
			vuln_reference: req.params.vuln + '/reference',
			vulnerabilities:vulnDict['hackingWeb'],
			path,
			owaspPath,
			layersPath,
			mode,
			type: 'web'
		}, function (err, html) {
			if (err) {
				console.log(err)
				res.status(404).send('404')
			} else {
				res.send(html)
			}
		})
	}
	router.get('/learn/hacking-web/vulnerability/:vuln', authHandler.isAuthenticated, function (req, res) {
		renderWeb(req, res, 1);
	})

	router.get('/learn/hacking-web-owasp/vulnerability/:vuln', authHandler.isAuthenticated, function (req, res) {
		renderWeb(req, res, 2);
	})
	
	router.get('/learn/cryptography/vulnerability/:vuln', authHandler.isAuthenticated, function (req, res) {
		res.render('cryptography-vulnerabilities/layout', {
			vuln: req.params.vuln,
			vuln_title: vulnDict['cryptography'][req.params.vuln],
			vuln_description: req.params.vuln + '/description',
			vuln_reference: req.params.vuln + '/reference',
			vulnerabilities:vulnDict['cryptography'],
			path: '/learn/cryptography/vulnerability/'+req.params.vuln,
			type: 'crypto'
		}, function (err, html) {
			if (err) {
				console.log(err)
				res.status(404).send('404')
			} else {
				res.send(html)
			}
		})
	})
	async function initCTFGetOutput(req) {
		let output = {};
		switch (req.params.vuln) {
			case 'home':
			case 'documents-to-sign':
				const products = await db.Product.findAll();
				output = {
					products
				}
				break;
			
			case 'create-new-document':
			case 'edit-document':
				const isCreateNewDocument = req.params.vuln === 'create-new-document';
				if (!req.query.id || req.query.id === '') {
					output = {
						product: {},
						canUpload: isCreateNewDocument
					}
				} else {
					let product = await db.Product.find({
						where: {
							'id': req.query.id
						}
					})
					if (!product) {
						product = {}
					}
					output = {
						product,
						canUpload: isCreateNewDocument
					}
				}
				break;
			case 'trash':
				const trashProducts = await db.Product.findAll();
				output = {
					products: trashProducts
				}
				break;
			case 'upload-document':
				output = {
					legacy: req.query.legacy,
				}
				break;
		}
		return output;
	}
	router.get('/ctf/:vuln', authHandler.isAuthenticated, async function (req, res) {
		const { vuln } = req.params;
		let output = await initCTFGetOutput(req);
		
		res.render('ctf/layout', {
			admin: (req.user.role === 'admin'),
			vuln: vuln,
			vuln_title: vulnDict['ctf'][vuln],
			vuln_description: vuln + '/index',
			vulnerabilities:vulnDict['ctf'],
			path: '/ctf/'+vuln,
			type: 'ctf',
			// For the profile
			userId: req.user.id,
			userEmail: req.user.email,
			userName: req.user.name,
			output,
		}, function (err, html) {
			if (err) {
				console.log(err)
				res.status(404).send('404')
			} else {
				res.send(html)
			}
		})
	});
	

	router.get('/learn', authHandler.isAuthenticated, function (req, res) {
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

	
	async function initCTFPostOutput(req) {
		let output = {};
		switch (req.params.vuln) {
			case 'home':
			case 'documents-to-sign':
			case 'trash':
				const products = await db.Product.findAll({
					where: {
						name: {
							[Op.like]: '%' + req.body.name + '%'
						}
					}
				});
				output = {
					products,
					searchTerm: req.body.name
				}
				break;

			case 'edit-document':
				try {
					if (!req.body.id || req.body.id == '') {
						req.body.id = 0
					}
					const product = await db.Product.find({
						where: {
							'id': req.body.id
						}
					});
					if (!product) {
						product = new db.Product()
					}
					product.code = req.body.code
					product.name = req.body.name
					product.description = req.body.description
					product.tags = req.body.tags
					output = {
						product
					}
					const newProduct = await product.save();
					if (newProduct) {
						req.flash('success', 'Product added/modified!')
					}
				} catch(err) {
					output = {
						product
					}
					req.flash('danger',err)
				}
				break;
			case 'profile':
				const user = await db.User.find({
					where: {
						'id': req.body.id
					}		
				});
				if (req.body.password.length > 0) {
					if (req.body.password.length > 0) {
						if (req.body.password === req.body.cpassword) {
							user.password = bCrypt.hashSync(req.body.password, bCrypt.genSaltSync(10), null)
						} else{
							req.flash('warning', "Passwords don't match")
							return		
						}
					} else{
						req.flash('warning', 'Invalid Password')
						return
					}
				}
				user.email = req.body.email
				user.name = req.body.name
				await user.save()
				req.flash('success',"Updated successfully")
				break;

		}
		return output;
	} 

	router.post('/ctf/:vuln', authHandler.isAuthenticated, async function (req, res) {
		const { vuln } = req.params;
		let output = await initCTFPostOutput(req);
		let userEmail = req.user.email;
		let userName = req.user.name;
		if (vuln === 'profile') {
			userEmail = req.body.email;
			userName = req.body.name;
		}
		res.render('ctf/layout', {
			admin: (req.user.role === 'admin'),
			vuln: vuln,
			vuln_title: vulnDict['ctf'][vuln],
			vuln_description: vuln + '/index',
			vulnerabilities:vulnDict['ctf'],
			path: '/ctf/' + vuln,
			type: 'ctf',
			userId: req.user.id,
			userEmail,
			userName,
			output
		}, function (err, html) {
			if (err) {
				console.log(err)
				res.status(404).send('404')
			} else {
				res.send(html)
			}
		})
	});

	router.post('/login', passport.authenticate('login', {
		// successRedirect: '/learn',
		successRedirect: '/ctf/home',
		failureRedirect: '/login',
		failureFlash: true
	}))

	router.post('/register', passport.authenticate('signup', {
		// successRedirect: '/learn',
		successRedirect: '/ctf/home',
		failureRedirect: '/register',
		failureFlash: true
	}))

	router.post('/forgotpw', authHandler.forgotPw)

	router.post('/resetpw', authHandler.resetPwSubmit)

	return router
}