const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const connectDB = require('./Config/DB');
const authRoutes = require('./Routes/AuthRoute');
const protect = require('./Middlewares/AuthMiddlewares');


dotenv.config();
const app = express();
connectDB();

// Middleware
app.use(express.json()); // For parsing JSON requests
app.use(cors()); 

app.use(cors({
  origin: "*",
  // methods: ['GET', 'POST',"PUT", "DELETE"],
}));

app.get("/", (req, res) => {
  res.send("Hello World!");
});

// Routes
app.use('/api/auth', authRoutes);

const PORT = process.env.PORT;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
