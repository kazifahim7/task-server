const express = require('express')
const app = express()
const cors = require('cors')
require('dotenv').config()
var jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt');
const port = process.env.PORT || 7000



app.use(cors())

app.use(express.json())




const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.afhro9w.mongodb.net/?appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {

        const userCollection = client.db("nexPay").collection('AllUser')
        const PaymentCollection = client.db("nexPay").collection('payment')


        app.post('/jwt', async (req, res) => {
            const email = req.body;
            const token = jwt.sign(email, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '7d' })
            console.log(token)
            res.send({ token })
        })

        const verifyToken = (req, res, next) => {
            if (!req.headers.authorization) {
                return res.status(401).send({ massage: 'unAuthorized' })
            }
            const token = req.headers.authorization.split(' ')[1]
            console.log('token is', token)
            jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
                if (err) {
                    console.log(err)
                    return res.status(401).send({ message: 'Unauthorized access' });
                }
                req.user = decoded
                console.log(decoded)
                next()
            })


        }

        const verifyAdmin = async (req, res, next) => {
            const email = req.user?.identity;
            console.log('yess',email)
            const query = { identity: email }
            const user = await userCollection.findOne(query)
            const isAdmin = user?.role === 'admin'
            if (!isAdmin) {
                return res.status(403).send({ massage: 'forbidden access' })
            }
            next()

        }

        app.get('/allUser',verifyToken,verifyAdmin,async(req,res)=>{
            console.log(req.user?.identity)
            const result=await userCollection.find().toArray()
            res.send(result)
        })


        app.post('/allUsers', async (req,res)=>{
            const data=req.body;
            const saltRounds = 10;

            const password= await bcrypt.hash(data.pin,saltRounds)

            const lastData={
                identity: data.identity,
                imageUrl: data.imageUrl,
                status: data.status,
                role: data.role,
                password,
                money:0,
                name:data.name



            }

            const query = {
                identity: data.identity,
            }
            const existing = await userCollection.findOne(query)
            if (existing) {
                return res.send({ massage: 'already available' })
            }


            console.log(lastData)


            const result= await userCollection.insertOne(lastData)
            res.send(result)
        })

        app.post('/login',async(req,res)=>{
            const data=req.body;
            const filter={
                identity: data.identity
            }
            const user=await userCollection.findOne(filter)

            if (user && await bcrypt.compare(data.pin, user.password)) {
                // Authentication successful
                res.send(user);
            } else {
                // Authentication failed
                res.send('Invalid identity or password');
            }
        

        })


        app.get('/allUser/:id',verifyToken,async(req,res)=>{
            const id=req.params.id
            const filter={
                identity:id
            }
            const result= await userCollection.findOne(filter)
            let role=''
            if(result){
                role=result?.role
            }
            res.send({role})
        })


        app.post('/user/:id',verifyToken,verifyAdmin,async(req,res)=>{
            const id=req.params.id
            const data=req.body
            const filter={_id : new ObjectId(id)}
            const updateDoc = {
                $set: {
                    role: data.status,

                    money:data.amount,
                    status:'approved'
                }
            }

            const result=await userCollection.updateOne(filter,updateDoc)
            res.send(result)
        })
        app.post('/status/:id',verifyToken,verifyAdmin,async(req,res)=>{
            const id=req.params.id
            const data=req.body
            const filter={_id : new ObjectId(id)}
            const updateDoc = {
                $set: {
                   
                    status:data.status
                }
            }

            const result=await userCollection.updateOne(filter,updateDoc)
            res.send(result)
        })

        app.get('/singleUser/:id',  async (req, res) => {
            const id = req.params.id
            const filter = {
                identity: id
            }
            const result = await userCollection.findOne(filter)
           
            res.send(result)
        })

        app.post('/send-money',async(req,res)=>{
            const datas=req.body;
            const transactionId=new ObjectId().toString()
            datas.transactionId=transactionId;
            const filter = { identity: datas.toNumber }
            const result1= await userCollection.findOne(filter)
            const filter2 = { identity: datas.fromNumber }
            const result2 = await userCollection.findOne(filter2)
            if(!result1){
              return  res.send('user not found')
            }
            else if (result2 && await bcrypt.compare(datas.password, result2.password)){
                const updateDoc1={
                    $set:{
                        money: result2?.money - datas.finalTaka

                    }
                }
                const upadateFormuser=await userCollection.updateOne(filter2,updateDoc1)
                const updateDoc2={
                    $set:{
                        money: result1?.money + datas.finalTaka

                    }
                }
                const upadateTouser = await userCollection.updateOne(filter, updateDoc2)

                const result=await PaymentCollection.insertOne(datas)
                res.send(result)


            }
            else {
                // Authentication failed
                res.send('Invalid identity or password'); 
            }
        })


        app.get('/payment/:id',async(req,res)=>{
            const id=req.params.id
            const filter={
                fromNumber:id
            }
            const result=await PaymentCollection.find(filter).toArray()


            res.send(result)
        })






       
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        
    }
}
run().catch(console.dir);














app.get('/', (req, res) => {
    res.send('payNexus coming')
})

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})