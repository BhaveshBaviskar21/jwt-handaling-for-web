const express = require('express')
const app = express()
const mongoose = require('mongoose')
const User = require('./modules/user_modules')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const cors = require('cors')
const { Web3 } = require('web3')
const c_jwt = require('E:/intern/thesis/build/contracts/jwt_storage.json')

app.use(cors())
app.use(express.json())


mongoose.connect("mongodb://localhost:27017/webpage")

const web3 = new Web3('http://127.0.0.1:7545');

const contractabi = c_jwt["abi"]
const contractbytcode = c_jwt["bytecode"]

// Endpoint to get balance for a given address
app.get('/balance', async (req, res) => {
  const address  = req.body.address;
  console.log(req.body)
  // Check if the address is valid
  if (!web3.utils.isAddress(address)) {
    return res.status(400).json({ error: 'Invalid Ethereum address' });
  }
  try {
    const balanceWei = await web3.eth.getBalance(address);
    const balanceEth = web3.utils.fromWei(balanceWei, 'ether');
    res.json({ address, balance: balanceEth });
  } catch (error) {
    console.error('Error fetching balance:', error);
    res.status(500).json({ error: 'Failed to fetch balance' });
  }
});

async function deployContract(userAddress) {
    const contract = new web3.eth.Contract(contractabi);
    const newContractInstance = await contract.deploy({
        data: contractbytcode,
      })
      .send({
        from: userAddress,
        gas: 600000,
      });
    return newContractInstance.options.address
}


app.post('/api/register',async (req,res)=>{
    console.log(req.body)
	try {
		const newPassword = await bcrypt.hash(req.body.password, 10)
		await User.create({
			name: req.body.name,
			email: req.body.email,
			password: newPassword,
		})
		res.json({ status: 'ok' })
	} catch (err) {
		res.json({ status: 'error', error: err })
	}
})


app.post('/api/login',async (req,res)=>{
    const user = await User.findOne({
		email: req.body.email,
	})

	if (!user) {
		return { status: 'error', error: 'Invalid login' }
	}

	const isPasswordValid = await bcrypt.compare(
		req.body.password,
		user.password
	)

	if (isPasswordValid) {
        if(user.hash){
            const prevcontract = new web3.eth.Contract(contractabi, user.hash)
            try {
                const token = await prevcontract.methods.getToken().call()
                console.log(token)
                if (await isjwtvalid(token)){
                    return res.json({ status: 'ok', contractHash: user.hash})
                }
            }catch(error) {
                console.log(error)
            }
        }
        const token = jwt.sign(
            {
                name: user.name,
                email: user.email,
                expires: Date.now() // + 300000
            }, 'secret123'
        )
        const contractaddress = await deployContract(req.body.address)
        const contract = new web3.eth.Contract(contractabi,contractaddress)
        try {
            await contract.methods.setToken(token).send({ from: req.body.address ,gas:600000});
            await User.updateOne(
                { email: user.email },
                { $set: { hash: contractaddress} }
            )    
            return res.json({ status: 'ok', contractHash: contractaddress})
        } catch (error) {
            return res.status(500).json({ error: 'Failed to set text in contract' });
        }
	} else {
		return res.json({ status: 'error', user: false })
	}
})


async function isjwtvalid(jwttoken) {
    try{
        const decoded = jwt.verify(jwttoken,'secret123')
        if( Date.now() <= decoded.expires){
            return true
        }else{
            return false
        }
    } catch (error) {
		console.log(error)
	}
}

app.get('/api/quote', async (req, res) => {
	const hash = req.headers['x-access-token']

    const contract = new web3.eth.Contract(contractabi,hash)
    try {
        const token = await contract.methods.getToken().call()
        const decoded = jwt.verify(token, 'secret123')
		const email = decoded.email
		const user = await User.findOne({ email: email })
		return res.json({ status: 'ok', quote: token })
    }catch(error) {
		console.log(error)
		res.json({ status: 'error', error: error })
	}
})

app.post('/api/quote', async (req, res) => {

    const hash = req.headers['x-access-token']

    const contract = new web3.eth.Contract(contractabi,hash)
    try {
        const token = await contract.methods.getToken().call()
        const decoded = jwt.verify(token, 'secret123')
		const email = decoded.email
		await User.updateOne(
			{ email: email },
			{ $set: { quote: req.body.quote } }
        )
		return res.json({ status: 'ok' })
    }catch(error) {
		console.log(error)
		res.json({ status: 'error', error: error })
	}
})


app.get('/test',(req,res)=>{
    res.send("hi there")
})

app.listen(21066,()=>{
    console.log('i am here')
})