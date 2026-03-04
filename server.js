const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3");
const { open } = require("sqlite");
const cors = require("cors");
const app = express();
app.use(express.json());
app.use(cors());
let db = null;
const dbPath = path.join(__dirname, "bookhall.db");
const intializingDb = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(5000, () => {
      console.log("Server starts at 5000 backend");
    });
  } catch (e) {
    console.log(`error is : ${e}`);
  }
};
intializingDb();

  {/* Middleware Funtion for other api calls */}
const middleware = async(req,res,next)=>{
  let jwtToken;
  const authHeader = req.headers["authorization"];
  if(authHeader === undefined){
    res.status(401)
    res.json({"message":"Invalid Jwt Token"})
  }else{
    jwtToken = authHeader.split(" ")[1];
    jwt.verify(jwtToken,"MY_SECRET_KEY",async(error,payload)=>{
        if(error){
            res.status(401)
            res.json({"message":"Invalid Jwt Token"})
        }else{
            req.username = payload.username;
            next()
        }
    })
  }
}

app.post("/user", async (req, res) => {
  const { username, password } = req.body;
  try {
    const query = `SELECT * FROM user WHERE username = ?`;
    const result = await db.get(query, [username]);
    if (result === undefined) {
      const hashedPassword = await bcrypt.hash(password, 10);
      const query = `INSERT INTO user (username,password) VALUES(?,?)`;
      const result = await db.run(query, [username, hashedPassword]);
      res.json({ message: "Register Success" });
    } else {
      res.status(400);
      res.json({ message: "User Exists" });
    }
  } catch (e) {
    res.status(500);
    res.json({ message: `${e} Error in Register API` });
  }
});

app.post("/log", async (req, res) => {
  const { username, password } = req.body;
  try {
    const query = `SELECT * FROM user WHERE username = ?`;
    const result = await db.get(query, [username]);
    if (result === undefined) {
      res.status(400);
      res.json({ message: "Invalid User" });
    } else {
      const compare = await bcrypt.compare(password, result.password);
      if (compare === false) {
        res.status(400);
        res.json({ message: "Invalid Password" });
      } else {
        const payload = { username: username };
        const jwtToken = jwt.sign(payload, "MY_SECRET_KEY");
        res.json({ jwt_token: jwtToken });
      }
    }
  } catch (e) {
    res.status(500);
    res.json({ message: "Error in Login APIs" });
  }
});
