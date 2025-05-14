const mongoose = require("mongoose");

const mongoURI = process.env.MONGOURI;

const initializeDatabase = async () => {
  try {
    const connection = await mongoose.connect(mongoURI);
    if (connection) {
      console.log("connected successfull.");
    }
  } catch (error) {
    console.error("connection failed:", error);
  }
};

module.exports = { initializeDatabase };
