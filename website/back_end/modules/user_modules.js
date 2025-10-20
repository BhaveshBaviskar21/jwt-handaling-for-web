const mongoose = require('mongoose')

const User = new mongoose.Schema(
	{
		name: { type: String, required: true },
		email: { type: String, required: true, unique: true },
		password: { type: String, required: true },
		quote: { type: String },
		hash: { type: String },
	},
	{ collection: 'users' }
)

const model = mongoose.model('UsersData', User)

module.exports = model