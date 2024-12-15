const express = require("express");
const fs = require("fs");
const { ObjectId } = require("mongodb");
const path = require("path");
const mongo = require("mongodb");
const jwt = require("jsonwebtoken");
const Joi = require("joi");
const uuid = require("uuid");
const axios = require("axios");

const multer = require("multer");
const crypto = require("crypto");
const twilio = require("twilio");
const cookieParser = require("cookie-parser");

const client = new mongo.MongoClient("mongodb://127.0.0.1:27017/upes");
let conn;
let db;
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5000 * 1024,
  },
});

const imageDirectory = path.join(__dirname, "uploads");

// Ensure the directory exists, create if not
if (!fs.existsSync(imageDirectory)) {
  fs.mkdirSync(imageDirectory);
}

const accountSid = "ACe75a4d6b94c0d31c529faa14ec60532a"; // Replace with your Twilio SID
const authToken = "acf890599225bc648a85e22432d337e6"; // Replace with your Twilio Auth Token
const twilio_client = require("twilio")(accountSid, authToken);

try {
  conn = client.connect();
  db = client.db("upes");
} catch (e) {
  console.error(e);
}

const JWT_SECRET = "bad-dev-practices"; // Make sure to keep this secret safe

function generateToken(username, password) {
  return jwt.sign({ username: username, password: password }, JWT_SECRET, {
    expiresIn: "1h",
  });
}

const authenticateJWT = (req, res, next) => {
  const token = req.cookies.token;

  if (token) {
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.status(403).json({ message: "Invalid or expired token" });
      }

      req.user = user;
      next();
    });
  } else {
    res.redirect("/login");
  }
};

const schema = Joi.object({
  name: Joi.string()
    .pattern(/^[a-zA-Z\s]+$/)
    .min(4)
    .required(),
  dob: Joi.date()
    .iso()
    .greater("2000-01-01")
    .required(),
  address: Joi.string().required(),
  subject: Joi.string().valid("Backend", "AI", "EDGE", "DataNetworks").required(),
});

let collection = db.collection("SubjectDetails");
let otpColl = db.collection("otpAuth");
let authdb = db.collection("auth");

const app = express();
const port = 3000;

app.use(cookieParser());
app.use(express.json());

app.get("/hello", (req, res) => {
  res.send("HELLOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO");
});

app.get("/", authenticateJWT, (req, res) => {
  res.sendFile("/Users/vaibhav/Desktop/backend/lab1/main.html");
});

app.get("/login", (req, res) => {
  res.sendFile("/Users/vaibhav/Desktop/backend/lab2/login.html");
});

// Improved OTP route with better error handling
app.post("/otp", upload.none(), (req, res) => {
  let mobile = "+91" + req.body.mobile;
  let otp = crypto.randomInt(100000, 999999);
  console.log("Sending OTP to", mobile);

  twilio_client.messages
    .create({
      messagingServiceSid: "MGd172af2c478762d5d35f1582141bb509", // Replace with your actual Messaging Service SID
      to: mobile,
      body: `Your OTP code is: ${otp}`,
    })
    .then((message) => {
      console.log("OTP sent successfully:", message.sid);
      otpColl.insertOne({ otp: otp, mobile: mobile }, (err, result) => {
        if (err) {
          console.error("Error inserting OTP into the database:", err);
          return res.status(500).json({ message: "Error storing OTP in database" });
        }
        console.log("OTP saved to database");
        res.sendStatus(200);
      });
    })
    .catch((error) => {
      console.error("Error sending OTP via Twilio:", error);
      return res.status(500).json({ message: "Error sending OTP" });
    });
});

app.post("/loginreq", async (req, res) => {
  try {
    let username = req.body.username;
    let password = req.body.password;

    let user = await authdb.findOne({ username: username });

    if (!user) {
      const token = generateToken(username, password);

      await authdb.insertOne({
        username: username,
        password: password,
        jwtToken: token,
      });

      res.cookie("token", token, {
        httpOnly: true,
        secure: false,
        maxAge: 3600000,
      });

      return res.status(201).json({ message: "User created and logged in" });
    }

    if (user.password === password) {
      const token = generateToken(user.username, user.password);

      await authdb.updateOne(
        { username: username },
        { $set: { jwtToken: token } }
      );

      res.cookie("token", token, {
        httpOnly: true,
        secure: false,
        maxAge: 3600000,
      });

      return res.status(200).json({ message: "Login successful" });
    } else {
      return res.status(401).json({ message: "Invalid password" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.delete("/delete/:id", authenticateJWT, async (req, res) => {
  let oid = req.params.id;
  let result = await collection.deleteOne({ _id: new ObjectId(oid) });
  if (result.deletedCount >= 1) {
    return res.sendStatus(200);
  } else {
    return res.sendStatus(500);
  }
});

app.put("/registrations/update/:id", authenticateJWT, async (req, res) => {
  let oid = req.params.id;
  const filter = { _id: new ObjectId(oid) };
  const options = { upsert: false };

  const updateDoc = {
    $set: {
      name: req.body.name,
      dob: req.body.dob,
      address: req.body.address,
      subject: req.body.subject,
    },
  };

  let result = await collection.updateOne(filter, updateDoc, options);
  if (result.matchedCount == 0) {
    return res.sendStatus(404);
  } else {
    return res.sendStatus(200);
  }
});

app.post(
  "/uploadDetails",
  authenticateJWT,
  upload.single("mediaImage"),
  async (req, res) => {
    try {
      let mobile = req.body.mobile;
      let otp = req.body.otp;

      otpColl.findOne({ mobile: mobile, otp: otp }, (err, record) => {
        if (err) {
          return res.status(401).send("Incorrect Auth");
        }
      });

      var fileUrl;
      if (req.file) {
        const fileSizeInKB = req.file.size / 1024;

        if (fileSizeInKB < 5 || fileSizeInKB > 5000) {
          return res
            .status(400)
            .json({ error: "File size must be between 5 KB and 50 KB." });
        }

        const uniqueFileName = uuid.v4() + path.extname(req.file.originalname);
        const filePath = path.join(imageDirectory, uniqueFileName);

        fs.writeFileSync(filePath, req.file.buffer);

        fileUrl = `/uploads/${uniqueFileName}`;
      } else {
        return res.status(400).json({ error: "No file uploaded." });
      }

      let newDocument = {
        ...req.body,
        imageUrl: fileUrl,
      };

      let result = await collection.insertOne(newDocument);

      res.status(200).json({
        message: "New entry inserted successfully",
        fileUrl,
      });
    } catch (error) {
      console.error("Error:", error);
      res.status(500).send("Internal Server Error");
    }
  }
);

const weatherURL = `http://api.openweathermap.org/data/2.5/weather?q=London,uk&appid=70c0bc45a11e0719a8da7249bb2adb9b`;
app.get("/weather", async (req, res) => {
  try {
    const response = await axios.get(weatherURL);

    res.json(response.data);
  } catch (error) {
    console.error("Error fetching weather data:", error);
    res.status(500).json({ message: "Error fetching weather data" });
  }
});

// Serve the uploads directory statically
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

app.get("/registrations", authenticateJWT, async (req, res) => {
  let results = await collection.find({}).limit(50).toArray();
  res.send(results);
});

app.get("/update", authenticateJWT, (req, res) => {
  res.sendFile("/Users/vaibhav/Desktop/backend/lab1/update.html");
});

app.get("/search", authenticateJWT, (req, res) => {
  res.sendFile("/Users/vaibhav/Desktop/backend/lab1/search.html");
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
