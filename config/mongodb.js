import mongoose from "mongoose";

const mongodb_url = process.env.MONGODB_URL

const ConnectDB = async () => {
    mongoose.connection.on('connected', ()=>console.log('Database connected '))
    await  mongoose.connect(`${mongodb_url}/learningdeck`)
}

export default ConnectDB;