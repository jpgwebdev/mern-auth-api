const express = require('express');
const morgan = require('morgan');
const cors = require('cors');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();

// connect db
mongoose.connect(process.env.DATABASE,{
    useNewUrlParser: true,
    useFindAndModify: false,
    useUnifiedTopology: true,
    useCreateIndex: true
})
.then(() => console.log('DB Connected'))
.catch(err => console.log('DB Error: ',err));

const PORT = process.env.PORT || 8000;

// import route
const authRoute = require('./routes/auth');
const userRoute = require('./routes/user');
// app midlewares
app.use(morgan('dev'));
app.use(bodyParser.json());

if(process.env.NODE_ENV = 'development'){
    app.use(cors({origin: 'http://localhost:3000'}));
}

// middlewares
app.use('/api', authRoute);
// middlewares
app.use('/api', userRoute);

app.listen(PORT , () =>{
    console.log(`API is running on port: ${PORT} and ${process.env.NODE_ENV}`);
});


