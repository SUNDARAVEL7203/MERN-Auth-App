import mongoose from 'mongoose';

const connectDB = async () => {
    mongoose.connection.on('connected', () => console.log('Database connected'))
    await mongoose.connect(`${process.env.MONGO_URI}/mern-auth`);
}

export default connectDB
