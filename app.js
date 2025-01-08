const express = require("express");
// ... other imports

const app = express();

// Trust proxy - add this before other middleware
app.set('trust proxy', 1);

// ... rest of your middleware and routes 