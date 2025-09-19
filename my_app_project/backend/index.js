
const express = require('express');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const { GridFSBucket } = require('mongodb');

dotenv.config();
const app = express();
const port = process.env.PORT || 3000;

const uri = process.env.MONGODB_URI || "mongodb://storedata:Brandmystore0102@3.109.161.66:5555/bms";
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: uri,
    collectionName: 'sessions'
  }),
  cookie: {
    maxAge: 1000 * 60 * 60 * 24,
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true
  }
}));

const isAuthenticated = (req, res, next) => {
  if (req.session.userId) {
    return next();
  }
  return res.status(401).json({ success: false, error: 'Not authenticated' });
};

let db;
let mongoInitialized = false;
let gridFSBucket;

let elementDb;
let elementDbInitialized = false;
let elementGridFSBucket;

async function initializeMongoDB() {
  if (mongoInitialized) return true;
  try {
    await client.connect();
    console.log('Connected to MongoDB');
    db = client.db("element");
    gridFSBucket = new GridFSBucket(db, {
      bucketName: 'uploads'
    });
    mongoInitialized = true;
    console.log('MongoDB initialized successfully');
    return true;
  } catch (error) {
    console.error('Failed to initialize MongoDB:', error.message);
    mongoInitialized = false;
    return false;
  }
}

async function initializeElementDB() {
  if (elementDbInitialized) return true;
  try {
    elementDb = client.db("element");
    elementGridFSBucket = new GridFSBucket(elementDb, {
      bucketName: 'uploads'
    });
    elementDbInitialized = true;
    console.log('Element database initialized successfully');
    return true;
  } catch (error) {
    console.error('Failed to initialize element database:', error.message);
    elementDbInitialized = false;
    return false;
  }
}

app.post('/register', async (req, res) => {
  if (!mongoInitialized) {
    const initialized = await initializeMongoDB();
    if (!initialized) {
      return res.status(500).json({
        success: false,
        error: 'MongoDB not initialized'
      });
    }
  }
  try {
    console.log('Received registration data:', req.body);
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: username, email, password'
      });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid email format'
      });
    }
    const usersCollection = db.collection("users");
    const existingUser = await usersCollection.findOne({
      $or: [{ username }, { email }]
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: 'Username or email already exists'
      });
    }
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const userData = {
      username,
      email,
      password: hashedPassword,
      createdAt: new Date(),
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    };
    const result = await usersCollection.insertOne(userData);
    console.log('User registered with ID:', result.insertedId);
    req.session.userId = result.insertedId.toString();
    req.session.username = username;
    res.status(200).json({
      success: true,
      id: result.insertedId.toString(),
      username: username,
      message: 'Registration successful'
    });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.post('/login', async (req, res) => {
  if (!mongoInitialized) {
    const initialized = await initializeMongoDB();
    if (!initialized) {
      return res.status(500).json({
        success: false,
        error: 'MongoDB not initialized'
      });
    }
  }
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: 'Username and password are required'
      });
    }
    const usersCollection = db.collection("users");
    const user = await usersCollection.findOne({ username });

    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Invalid username or password'
      });
    }
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        error: 'Invalid username or password'
      });
    }
    req.session.userId = user._id.toString();
    req.session.username = user.username;
    res.status(200).json({
      success: true,
      id: user._id.toString(),
      username: user.username,
      message: 'Login successful'
    });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({
        success: false,
        error: 'Failed to logout'
      });
    }
    res.clearCookie('connect.sid');
    res.status(200).json({
      success: true,
      message: 'Logout successful'
    });
  });
});

app.get('/profile', isAuthenticated, async (req, res) => {
  try {
    const usersCollection = db.collection("users");
    const user = await usersCollection.findOne(
      { _id: new ObjectId(req.session.userId) },
      { projection: { password: 0 } }
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      user: {
        id: user._id.toString(),
        username: user.username,
        email: user.email,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.post('/submit-form', async (req, res) => {
  if (!mongoInitialized) {
    const initialized = await initializeMongoDB();
    if (!initialized) {
      return res.status(500).json({
        success: false,
        error: 'MongoDB not initialized'
      });
    }
  }
  try {
    console.log('Received form data:', req.body);
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: username, email, password'
      });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid email format'
      });
    }
    const formData = {
      ...req.body,
      submittedAt: new Date(),
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    };
    const collection = db.collection("signup");
    const result = await collection.insertOne(formData);
    console.log('Form submitted with ID:', result.insertedId);
    res.status(200).json({
      success: true,
      id: result.insertedId.toString(),
      message: 'Form submitted successfully'
    });
  } catch (error) {
    console.error('Error submitting form:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.post('/save-element-data', async (req, res) => {
  if (!elementDbInitialized) {
    const initialized = await initializeElementDB();
    if (!initialized) {
      return res.status(500).json({
        success: false,
        error: 'Element database not initialized'
      });
    }
  }
  try {
    console.log('Received element data:', req.body);
    const { elementData, userId } = req.body;
    if (!elementData) {
      return res.status(400).json({
        success: false,
        error: 'Element data is required'
      });
    }

    const processedElementData = Array.isArray(elementData)
      ? elementData.map(element => ({
          ...element,
          elementId: new ObjectId().toString()
        }))
      : {
          ...elementData,
          elementId: new ObjectId().toString()
        };

    const document = {
      elementData: processedElementData,
      userId: userId || null,
      createdAt: new Date(),
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    };

    const collection = elementDb.collection("user_element_screen");
    const result = await collection.insertOne(document);
    console.log('Element data saved with ID:', result.insertedId);

    res.status(200).json({
      success: true,
      id: result.insertedId.toString(),
      message: 'Element data saved successfully'
    });
  } catch (error) {
    console.error('Error saving element data:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.post('/upload-image', async (req, res) => {
  if (!elementDbInitialized) {
    const initialized = await initializeElementDB();
    if (!initialized) {
      return res.status(500).json({
        success: false,
        error: 'Element database not initialized'
      });
    }
  }
  try {
    const { imageData, elementData, userId } = req.body;

    if (!imageData || !elementData) {
      return res.status(400).json({
        success: false,
        error: 'Image data and element data are required'
      });
    }

    const processedElementData = Array.isArray(elementData)
      ? elementData.map(element => ({
          ...element,
          elementId: new ObjectId().toString()
        }))
      : {
          ...elementData,
          elementId: new ObjectId().toString()
        };

    const base64Data = imageData.replace(/^data:image\/\w+;base64,/, '');
    const buffer = Buffer.from(base64Data, 'base64');

    const filename = `image_${Date.now()}_${Math.random().toString(36).substring(2, 15)}.png`;

    const uploadStream = elementGridFSBucket.openUploadStream(filename, {
      contentType: 'image/png',
      metadata: {
        userId: userId || null,
        uploadedAt: new Date()
      }
    });

    uploadStream.end(buffer);

    uploadStream.on('finish', async () => {
      const fileId = uploadStream.id;

      processedElementData.imageFileId = fileId.toString();
      processedElementData.imageUrl = imageData;

      const document = {
        elementData: processedElementData,
        userId: userId || null,
        createdAt: new Date(),
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      };

      const collection = elementDb.collection("user_element_screen");
      const result = await collection.insertOne(document);
      console.log('Image uploaded and element data saved with ID:', result.insertedId);

      res.status(200).json({
        success: true,
        id: result.insertedId.toString(),
        fileId: fileId.toString(),
        message: 'Image uploaded and element data saved successfully'
      });
    });

    uploadStream.on('error', (error) => {
      console.error('Error uploading image:', error);
      res.status(500).json({
        success: false,
        error: 'Error uploading image'
      });
    });
  } catch (error) {
    console.error('Error processing image upload:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.post('/save-element-data-edit', async (req, res) => {
  if (!elementDbInitialized) {
    const initialized = await initializeElementDB();
    if (!initialized) {
      return res.status(500).json({
        success: false,
        error: 'Element database not initialized'
      });
    }
  }
  try {
    console.log('Received element data for edit:', req.body);
    const { elementData, userId, inputFields } = req.body;

    if (!elementData) {
      return res.status(400).json({
        success: false,
        error: 'Element data is required'
      });
    }

    const processedElementData = Array.isArray(elementData)
      ? elementData.map(element => ({
          ...element,
          elementId: new ObjectId().toString()
        }))
      : {
          ...elementData,
          elementId: new ObjectId().toString()
        };

    const document = {
      elementData: processedElementData,
      inputFields: inputFields || {},
      userId: userId || null,
      createdAt: new Date(),
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    };

    const collection = elementDb.collection("user_edit_screen");
    const result = await collection.insertOne(document);
    console.log('Element data saved to user_edit_screen with ID:', result.insertedId);

    res.status(200).json({
      success: true,
      id: result.insertedId.toString(),
      message: 'Element data saved successfully to user_edit_screen'
    });
  } catch (error) {
    console.error('Error saving element data to user_edit_screen:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.post('/upload-image-edit', async (req, res) => {
  if (!elementDbInitialized) {
    const initialized = await initializeElementDB();
    if (!initialized) {
      return res.status(500).json({
        success: false,
        error: 'Element database not initialized'
      });
    }
  }
  try {
    const { imageData, elementData, userId, inputFields } = req.body;

    if (!imageData || !elementData) {
      return res.status(400).json({
        success: false,
        error: 'Image data and element data are required'
      });
    }

    const processedElementData = Array.isArray(elementData)
      ? elementData.map(element => ({
          ...element,
          elementId: new ObjectId().toString()
        }))
      : {
          ...elementData,
          elementId: new ObjectId().toString()
        };

    const base64Data = imageData.replace(/^data:image\/\w+;base64,/, '');
    const buffer = Buffer.from(base64Data, 'base64');

    const filename = `image_${Date.now()}_${Math.random().toString(36).substring(2, 15)}.png`;

    const uploadStream = elementGridFSBucket.openUploadStream(filename, {
      contentType: 'image/png',
      metadata: {
        userId: userId || null,
        uploadedAt: new Date()
      }
    });

    uploadStream.end(buffer);

    uploadStream.on('finish', async () => {
      const fileId = uploadStream.id;

      processedElementData.imageFileId = fileId.toString();
      processedElementData.imageUrl = imageData;

      const document = {
        elementData: processedElementData,
        inputFields: inputFields || {},
        userId: userId || null,
        createdAt: new Date(),
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      };

      const collection = elementDb.collection("user_edit_screen");
      const result = await collection.insertOne(document);
      console.log('Image uploaded and element data saved to user_edit_screen with ID:', result.insertedId);

      res.status(200).json({
        success: true,
        id: result.insertedId.toString(),
        fileId: fileId.toString(),
        message: 'Image uploaded and element data saved successfully to user_edit_screen'
      });
    });

    uploadStream.on('error', (error) => {
      console.error('Error uploading image to element database:', error);
      res.status(500).json({
        success: false,
        error: 'Error uploading image'
      });
    });
  } catch (error) {
    console.error('Error processing image upload to element database:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.get('/form-submissions', async (req, res) => {
  if (!mongoInitialized) {
    const initialized = await initializeMongoDB();
    if (!initialized) {
      return res.status(500).json({
        success: false,
        error: 'MongoDB not initialized'
      });
    }
  }
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;
    const collection = db.collection("signup");
    const totalCount = await collection.countDocuments();
    const submissions = await collection.find({})
      .sort({ submittedAt: -1 })
      .skip(offset)
      .limit(limit)
      .toArray();
    const formattedSubmissions = submissions.map(submission => ({
      ...submission,
      _id: submission._id.toString()
    }));
    res.status(200).json({
      success: true,
      submissions: formattedSubmissions,
      pagination: {
        totalCount,
        currentPage: page,
        totalPages: Math.ceil(totalCount / limit),
        limit
      }
    });
  } catch (error) {
    console.error('Error fetching form submissions:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    mongo: mongoInitialized ? 'Initialized' : 'Not initialized',
    elementDb: elementDbInitialized ? 'Initialized' : 'Not initialized',
    session: req.session.userId ? 'Active' : 'Inactive'
  });
});

initializeMongoDB().then(() => {
  initializeElementDB().then(() => {
    app.listen(port, () => {
      console.log(`Server running at http://localhost:${port}`);
    });
  }).catch((error) => {
    console.error('Failed to initialize element database:', error.message);
    process.exit(1);
  });
}).catch((error) => {
  console.error('Failed to start server:', error.message);
  process.exit(1);
}
);