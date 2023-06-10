const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config({path: './.env'});
const stripe = require("stripe")(process.env.PAYMENT_SECRET_KEY);
const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const verifyJWT = (req,res,next)=>{
  const authorization = req.headers.authorization;
  if(!authorization){
    return res.status(401).send({error: true, message: 'Unauthorized access'})
  }
  const token = authorization.split(' ')[1];
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded)=>{
    if(err){
      return res.status(401).send({error: true, message: 'Unauthorized access'})
    }
    req.decoded = decoded;
    next();
  })
}

const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_User}:${process.env.DB_Pass}@cluster0.xyrtm8p.mongodb.net/?retryWrites=true&w=majority`;

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
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    const usersCollection = client.db('summerCampDB').collection('users');
    const classCollection = client.db('summerCampDB').collection('classes');
    const selectedClassesCollection = client.db('summerCampDB').collection('selectedClasses');

    app.post('/jwt', async(req,res)=>{
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '1h'})
      res.send({token});
    })

    const verifyAdmin = async (req,res, next)=>{
      const email = req.decoded.email;
      const query = {email: email};
      const user = await usersCollection.findOne(query);
      if(user?.role !== 'Admin'){
        return res.status(403).send({error: true, message: 'Forbidden message'});
      }
      next();
    }
    const verifyInstructor = async (req,res, next)=>{
      const email = req.decoded.email;
      const query = {email: email};
      const user = await usersCollection.findOne(query);
      if(user?.role !== 'Instructor'){
        return res.status(403).send({error: true, message: 'Forbidden message'});
      }
      next();
    }
    const verifyStudent = async (req,res, next)=>{
      const email = req.decoded.email;
      const query = {email: email};
      const user = await usersCollection.findOne(query);
      if(user?.role !== 'Admin' && user?.role !== 'Instructor'){
        return next();
      }
      return res.status(403).send({error: true, message: 'Forbidden message'});
    }

    //users collection
    app.post('/users', async(req,res)=>{
        const user = req.body;
        const query = {email: user.email}
        const existingUser = await usersCollection.findOne(query);
        if(existingUser){
            return res.send({message: 'User already exists'})
        }
        const result = await usersCollection.insertOne(user);
        res.send(result);
    })
    app.get('/users', async(req,res)=>{
      const result = await usersCollection.find().toArray();
      res.send(result);
    })
    app.get('/users/:email', verifyJWT, async(req,res)=>{
      const email = req.params.email;
      if(req.decoded.email !== email){
        return res.send({role: 'Student'})
      }
      const query = {email: email};
      const user = await usersCollection.findOne(query);
      const result = {role: user?.role}
      res.send(result);
    })
    app.patch('/users/:id', verifyJWT, verifyAdmin, async(req,res)=>{
      const id = req.params.id;
      const value = req.query.role;
      const filter = {_id: new ObjectId(id)};
      const updateDoc = {
        $set: {
          role: value
        },
      };
      const result = await usersCollection.updateOne(filter, updateDoc);
      res.send(result);
    })
    // class collection
    app.post('/classes', verifyJWT, verifyInstructor, async(req,res)=>{
      const data = req.body;
      const result = await classCollection.insertOne(data);
      res.send(result);
    })
    app.get('/addedClasses', verifyJWT, verifyAdmin, async(req,res)=>{
      const result = await classCollection.find().toArray();
      res.send(result);
    })
    app.get('/classes', async(req,res)=>{
      const query = {status: 'Approved'}
      const result = await classCollection.find(query).toArray();
      res.send(result);
    })
    app.patch('/addedClasses/:id', verifyJWT, verifyAdmin, async(req,res)=>{
      const id = req.params.id;
      const value = req.query.status;
      const filter = {_id: new ObjectId(id)};
      if(value === 'Approve'){
        const updateDoc = {
          $set:{
            status: 'Approved'
          },
        }; 
        const result = await classCollection.updateOne(filter, updateDoc);
        res.send(result);
      }else{
        const updateDoc = {
          $set:{
            status: 'Denied'
          },
        }; 
        const result = await classCollection.updateOne(filter, updateDoc);
        res.send(result);
      }
    })
    // selected class section
    app.post('/selectedClasses', verifyJWT, verifyStudent, async(req,res)=>{
      const item = req.body;
      const result = await selectedClassesCollection.insertOne(item);
      res.send(result);
    })
    app.get('/selectedClasses', verifyJWT, verifyStudent, async(req,res)=>{
      const email = req.query.email;
      if(!email){
        res.send([]);
      }
      const decodedEmail = req.decoded.email;
      if(email !== decodedEmail){
        return res.status(403).send({error: true, message: 'forbidden access'})
      }
      const query = {email: email};
      const result = await selectedClassesCollection.find(query).toArray();
      res.send(result);
    })
    app.delete('/selectedClasses/:id', verifyJWT, verifyStudent, async(req,res)=>{
      const id = req.params.id;
      const query = {_id: new ObjectId(id)};
      const result = await selectedClassesCollection.deleteOne(query);
      res.send(result);
    })
    // create payment intent
    app.post('/create-payment-intent', verifyJWT, verifyStudent, async(req,res)=>{
      const {price} = req.body;
      const amount = price*100;
      const paymentIntent = await stripe.paymentIntents.create({
        amount: amount,
        currency: 'usd',
        payment_method_types: ['card']
      })
      res.send({
        clientSecret: paymentIntent.client_secret,
      })
    })
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);


app.get('/', (req,res)=>{
    res.send('server is running');
})
app.listen(port, ()=>{
    console.log(`app is running on port: ${port}`);
})