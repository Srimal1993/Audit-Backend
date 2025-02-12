// Required Modules
const express = require("express");
const mysql = require("mysql");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcrypt");
const validator = require("validator");

const app = express();
const port = 8081;


// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Ensure upload directory exists
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const rateLimit = require("express-rate-limit");

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again later",
});

app.use(limiter);



// Configure multer for multiple files
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, `${uniqueSuffix}-${file.originalname}`);
  },
});

const upload = multer({ storage });


// Database connection
require("dotenv").config();

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});


db.connect((err) => {
  if (err) {
    console.error("Database connection failed:", err.message);
    return setTimeout(() => db.connect(), 5000); // Retry after 5s
  }
  console.log("Connected to the database.");
});





// ------------------------- User Routes -------------------------

// Get all users
app.get("/users", (req, res) => {
  const sql = "SELECT * FROM users";
  db.query(sql, (err, data) => {
    if (err) {
      console.error("Error fetching users:", err);
      return res.status(500).json({ error: err.message });
    }
    res.json(data);
  });
});

// Register a new user
app.post("/users", async (req, res) => {
  const {
    accountType,
    firstName,
    lastName,
    company,
    address,
    phoneNumber,
    emailAddress,
    password,
    plan,
    country,
  } = req.body;

  if (!firstName || !lastName || !emailAddress || !password || !country) {
    return res.status(400).json({ message: "All required fields must be provided." });
  }

  if (!validator.isStrongPassword(password)) {
    return res.status(400).json({
      message:
        "Password must be at least 8 characters long and contain uppercase, lowercase, a number, and a special character.",
    });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const checkCodeSql = `
      SELECT MAX(CAST(SUBSTRING_INDEX(CompanyCode, '-', -1) AS UNSIGNED)) AS maxCode
      FROM users
      WHERE CompanyCode LIKE ?`;
    const countryCode = `${country}-%`;

    db.query(checkCodeSql, [countryCode], (err, result) => {
      if (err) {
        console.error("Error fetching CompanyCode:", err);
        return res.status(500).json({ error: err.message });
      }

      const maxCode = result[0]?.maxCode || 999;
      const nextCode = maxCode + 1;
      const CompanyCode = `${country}-${nextCode}`;

      const sql = `
        INSERT INTO users (
          accountType, firstName, lastName, company, address, phoneNumber,
          emailAddress, password, plan, country, CompanyCode
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

      db.query(
        sql,
        [
          accountType,
          firstName,
          lastName,
          company,
          address,
          phoneNumber,
          emailAddress,
          hashedPassword,
          plan,
          country,
          CompanyCode,
        ],
        (err) => {
          if (err) {
            console.error("Error registering user:", err);
            return res.status(500).json({ error: err.message });
          }
          res.status(201).json({ message: "User registered successfully.", CompanyCode });
        }
      );
    });
  } catch (err) {
    console.error("Error hashing password:", err);
    res.status(500).json({ error: "Internal server error." });
  }
});


// User login...............................

app.post("/api/login", (req, res) => {
  const { emailAddress, password } = req.body;

  if (!emailAddress || !password) {
    return res.status(400).json({ message: "Email and password are required." });
  }

  const sql = "SELECT * FROM users WHERE emailAddress = ?";
  db.query(sql, [emailAddress], async (err, result) => {
    if (err) {
      console.error("Error fetching user for login:", err);
      return res.status(500).json({ error: err.message });
    }

    if (result.length === 0) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const user = result[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    res.json({ message: "Login successful.", user });
  });
});


// ------------------------- Company Routes -------------------------

// Get all companies
app.get("/companies", (req, res) => {
  const sql = "SELECT * FROM companies";
  db.query(sql, (err, data) => {
    if (err) {
      console.error("Error fetching companies:", err);
      return res.status(500).json({ error: err.message });
    }
    res.json(data);
  });
});

// Add a new company
app.post("/api/add-company", (req, res) => {
  const { companyName, description, CompanyCode } = req.body;

  if (!companyName || !description || !CompanyCode) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const query = "INSERT INTO companies (companyName, description, CompanyCode) VALUES (?, ?, ?)";
  db.query(query, [companyName, description, CompanyCode], (err, result) => {
    if (err) {
      console.error("Error inserting company:", err);
      return res.status(500).json({ error: "Failed to add company" });
    }
    res.status(201).json({ message: "Company added successfully", companyId: result.insertId });
  });
});

// Update a company
app.put("/api/update-company/:id", (req, res) => {
  const { companyName, description, CompanyCode } = req.body;
  const companyId = req.params.id;

  if (!companyName || !description || !CompanyCode) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const query = "UPDATE companies SET companyName = ?, description = ?, CompanyCode = ? WHERE id = ?";
  db.query(query, [companyName, description, CompanyCode, companyId], (err, result) => {
    if (err) {
      console.error("Error updating company:", err);
      return res.status(500).json({ error: "Failed to update company" });
    }
    res.status(200).json({ message: "Company updated successfully" });
  });
});

// Delete a company
app.delete("/api/delete-company/:id", (req, res) => {
  const { id } = req.params;

  const sql = "DELETE FROM companies WHERE id = ?";
  db.query(sql, [id], (err) => {
    if (err) {
      console.error("Error deleting company:", err);
      return res.status(500).json({ error: err.message });
    }
    res.json({ message: "Company deleted successfully." });
  });
});


// ------------------------- Branch Routes -------------------------
// Get all companies SELECT companyName
app.get("/companies", (req, res) => {
  const sql = "SELECT id, companyName FROM companies"; // Only selecting the necessary columns
  db.query(sql, (err, data) => {
    if (err) {
      console.error("Error fetching companies:", err);
      return res.status(500).json({ error: err.message });
    }
    res.json(data);
  });
});


// Get all branches
app.get("/branches", (req, res) => {
  const { companyCode } = req.query; // Get companyCode from query parameters
  let sql = "SELECT * FROM branches";

  if (companyCode) {
    sql += " WHERE companyCode = ?";
  }

  db.query(sql, [companyCode], (err, data) => {
    if (err) {
      console.error("Error fetching branches:", err);
      return res.status(500).json({ error: err.message });
    }
    res.json(data);
  });
});


// Add a new branch (include companyCode and companyName)
app.post("/api/add-branch", (req, res) => {
  const { branchName, description, companyCode, companyName } = req.body; // Receive both companyCode and companyName

  if (!branchName || !description || !companyCode || !companyName) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const query = "INSERT INTO branches (branchName, description, companyCode, companyName) VALUES (?, ?, ?, ?)";
  db.query(query, [branchName, description, companyCode, companyName], (err, result) => {
    if (err) {
      console.error("Error inserting branch:", err);
      return res.status(500).json({ error: "Failed to add branch" });
    }
    res.status(201).json({
      message: "Branch added successfully",
      branchId: result.insertId,
    });
  });
});

// Update a branch (include companyCode and companyName)
app.put("/api/update-branch/:id", (req, res) => {
  const { branchName, description, companyCode, companyName } = req.body;
  const branchId = req.params.id;

  if (!branchName || !description || !companyCode || !companyName) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const query = "UPDATE branches SET branchName = ?, description = ?, companyCode = ?, companyName = ? WHERE id = ?";
  db.query(query, [branchName, description, companyCode, companyName, branchId], (err, result) => {
    if (err) {
      console.error("Error updating branch:", err);
      return res.status(500).json({ error: "Failed to update branch" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Branch not found" });
    }

    res.status(200).json({ message: "Branch updated successfully" });
  });
});

// Delete a branch
app.delete("/api/delete-branch/:id", (req, res) => {
  const { id } = req.params;

  const sql = "DELETE FROM branches WHERE id = ?";
  db.query(sql, [id], (err, result) => {
    if (err) {
      console.error("Error deleting branch:", err);
      return res.status(500).json({ error: "Failed to delete branch" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Branch not found" });
    }

    res.json({ message: "Branch deleted successfully" });
  });
});


// ------------------------- Department Routes -------------------------

// Get all departments
app.get("/departments", (req, res) => {
  const { companyCode } = req.query; // Get companyCode from query parameters
  let sql = "SELECT * FROM departments";

  if (companyCode) {
    sql += " WHERE companyCode = ?";
  }

  db.query(sql, [companyCode], (err, data) => {
    if (err) {
      console.error("Error fetching departments:", err);
      return res.status(500).json({ error: err.message });
    }
    res.json(data);
  });
});

// Add a new department (include companyCode and companyName)
app.post("/api/add-department", (req, res) => {
  const { departmentName, description, companyCode, companyName } = req.body; // Receive both companyCode and companyName

  if (!departmentName || !description || !companyCode || !companyName) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const query = "INSERT INTO departments (departmentName, description, companyCode, companyName) VALUES (?, ?, ?, ?)";
  db.query(query, [departmentName, description, companyCode, companyName], (err, result) => {
    if (err) {
      console.error("Error inserting department:", err);
      return res.status(500).json({ error: "Failed to add department" });
    }
    res.status(201).json({
      message: "Department added successfully",
      departmentId: result.insertId,
    });
  });
});

// Update a department (include companyCode and companyName)
app.put("/api/update-department/:id", (req, res) => {
  const { departmentName, description, companyCode, companyName } = req.body;
  const departmentId = req.params.id;

  if (!departmentName || !description || !companyCode || !companyName) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const query = "UPDATE departments SET departmentName = ?, description = ?, companyCode = ?, companyName = ? WHERE id = ?";
  db.query(query, [departmentName, description, companyCode, companyName, departmentId], (err, result) => {
    if (err) {
      console.error("Error updating department:", err);
      return res.status(500).json({ error: "Failed to update department" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Department not found" });
    }

    res.status(200).json({ message: "Department updated successfully" });
  });
});

// Delete a department
app.delete("/api/delete-department/:id", (req, res) => {
  const { id } = req.params;

  const sql = "DELETE FROM departments WHERE id = ?";
  db.query(sql, [id], (err, result) => {
    if (err) {
      console.error("Error deleting department:", err);
      return res.status(500).json({ error: "Failed to delete department" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Department not found" });
    }

    res.json({ message: "Department deleted successfully" });
  });
});

// ------------------------- company_structure Routes -------------------------

// Get all companies with optional filtering by companyCode
app.get("/companies", (req, res) => {
  const { companyCode } = req.query; // Get companyCode from query parameters
  console.log("Received companyCode:", companyCode); // Add this log for debugging

  let sql = "SELECT * FROM companies";
  const queryParams = [];

  // Add filtering if companyCode is provided
  if (companyCode) {
      sql += " WHERE CompanyCode = ?";
      queryParams.push(companyCode);
  }

  db.query(sql, queryParams, (err, data) => {
      if (err) {
          console.error("Error fetching companies:", err);
          return res.status(500).json({ error: "Internal server error", details: err.message });
      }
      console.log("Filtered companies:", data); // Log the filtered results
      res.json(data);
  });
});



// Get all branches with optional filtering by companyName
app.get("/branches", (req, res) => {
  const { companyName } = req.query; // Get companyName from query parameters
  let sql = "SELECT * FROM branches";
  const params = [];

  if (companyName) {
    sql += " WHERE companyName = ?";
    params.push(companyName);
  }

  db.query(sql, params, (err, data) => {
    if (err) {
      console.error("Error fetching branches:", err);
      return res.status(500).json({ error: "Internal server error", details: err.message });
    }
    res.json(data);
  });
});

// Get company structure data
app.get("/api/company-structure", (req, res) => {
  const sql = "SELECT * FROM company_structure";
  db.query(sql, (err, data) => {
    if (err) {
      console.error("Error fetching company structure:", err);
      return res.status(500).json({ error: err.message });
    }

    // Parse departments string into array if necessary
    data.forEach(item => {
      item.departments = JSON.parse(item.departments);
    });

    res.json(data);
  });
});

// Save new company structure
app.post("/api/company-structure", (req, res) => {
  const { companyName, branchName, departments, companyCode } = req.body;

  const sql =
    "INSERT INTO company_structure (companyName, branchName, departments, companyCode) VALUES (?, ?, ?, ?)";
  db.query(
    sql,
    [companyName, branchName, JSON.stringify(departments), companyCode],
    (err, result) => {
      if (err) {
        console.error("Error saving company structure:", err);
        return res.status(500).json({ error: "Internal server error", details: err.message });
      }
      res.json({ message: "Company structure saved successfully!" });
    }
  );
});

// Update existing company structure
app.put("/api/company-structure/:id", (req, res) => {
  const { id } = req.params;
  const { companyName, branchName, departments, companyCode } = req.body;

  if (!id || !companyName || !branchName || !Array.isArray(departments) || !companyCode) {
    return res.status(400).json({ error: "Missing or invalid data to update." });
  }

  const sql = `
    UPDATE company_structure 
    SET companyName = ?, branchName = ?, departments = ?, companyCode = ? 
    WHERE id = ?`;

  db.query(
    sql,
    [companyName, branchName, JSON.stringify(departments), companyCode, id],
    (err, result) => {
      if (err) {
        console.error("Error updating company structure:", err);
        return res.status(500).json({ error: "Internal server error", details: err.message });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({ error: "No record found to update." });
      }

      res.json({ message: "Company structure updated successfully!" });
    }
  );
});

// Delete company structure
app.delete("/api/company-structure/:id", (req, res) => {
  const { id } = req.params;
  
  if (!id) {
    return res.status(400).json({ error: "Missing ID parameter" });
  }

  const sql = "DELETE FROM company_structure WHERE id = ?";
  db.query(sql, [id], (err, result) => {
    if (err) {
      console.error("Error deleting data:", err); // More detailed logging
      return res.status(500).json({ error: "Error deleting data", details: err.message });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "No record found with this ID" });
    }

    res.json({ message: "Company structure deleted successfully!" });
  });
});

// ------------------------- Question Routes -------------------------

// Get all questions
app.get("/questions", (req, res) => {
  const { companyCode } = req.query;
  let sql = "SELECT * FROM questions";
  
  if (companyCode) {
    sql += " WHERE CompanyCode = ?";
  }
  
  db.query(sql, [companyCode], (err, data) => {
    if (err) {
      console.error("Error fetching questions:", err);
      return res.status(500).json({ error: err.message });
    }
    res.json(data);
  });
});

// Add a new question
app.post("/api/add-question", (req, res) => {
  const { questionText, answerType, answerOptions, optionPoints, CompanyCode } = req.body;
  
  if (!questionText || !answerType || !CompanyCode) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  let pointsToStore = null;
  
  if (answerType !== "FreeText") {
    if (!optionPoints) {
      return res.status(400).json({ error: "Points are required for this answer type" });
    }

    try {
      // Handle both string and array inputs for optionPoints
      const pointsArray = Array.isArray(optionPoints)
        ? optionPoints.map(Number)
        : String(optionPoints).split(',').map(Number);

      if (pointsArray.some(isNaN)) {
        return res.status(400).json({ error: "Invalid point values" });
      }

      const totalPoints = pointsArray.reduce((sum, point) => sum + point, 0);
      
      if (totalPoints !== 10) {
        return res.status(400).json({ error: "Total points must equal 10" });
      }

      pointsToStore = pointsArray.join(',');
    } catch (error) {
      return res.status(400).json({ error: "Invalid points format" });
    }
  }

  const query = `
    INSERT INTO questions 
    (questionText, answerType, answerOptions, optionPoints, CompanyCode) 
    VALUES (?, ?, ?, ?, ?)
  `;
  
  db.query(
    query,
    [questionText, answerType, answerOptions, pointsToStore, CompanyCode],
    (err, result) => {
      if (err) {
        console.error("Error inserting question:", err);
        return res.status(500).json({ error: "Failed to add question" });
      }
      res.status(201).json({
        message: "Question added successfully",
        questionId: result.insertId,
      });
    }
  );
});

// Update a question
app.put("/api/update-question/:id", (req, res) => {
  const { questionText, answerType, answerOptions, optionPoints, CompanyCode } = req.body;
  const questionId = req.params.id;
  
  if (!questionText || !answerType || !CompanyCode) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  let pointsToStore = null;
  
  if (answerType !== "FreeText") {
    if (!optionPoints) {
      return res.status(400).json({ error: "Points are required for this answer type" });
    }

    try {
      // Handle both string and array inputs for optionPoints
      const pointsArray = Array.isArray(optionPoints)
        ? optionPoints.map(Number)
        : String(optionPoints).split(',').map(Number);

      if (pointsArray.some(isNaN)) {
        return res.status(400).json({ error: "Invalid point values" });
      }

      const totalPoints = pointsArray.reduce((sum, point) => sum + point, 0);
      
      if (totalPoints !== 10) {
        return res.status(400).json({ error: "Total points must equal 10" });
      }

      pointsToStore = pointsArray.join(',');
    } catch (error) {
      return res.status(400).json({ error: "Invalid points format" });
    }
  }

  const query = `
    UPDATE questions 
    SET questionText = ?, 
        answerType = ?, 
        answerOptions = ?, 
        optionPoints = ?,
        CompanyCode = ? 
    WHERE id = ?
  `;
  
  db.query(
    query,
    [questionText, answerType, answerOptions, pointsToStore, CompanyCode, questionId],
    (err, result) => {
      if (err) {
        console.error("Error updating question:", err);
        return res.status(500).json({ error: "Failed to update question" });
      }
      
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: "Question not found" });
      }
      
      res.status(200).json({ message: "Question updated successfully" });
    }
  );
});


// Delete a question (unchanged)
app.delete("/api/delete-question/:id", (req, res) => {
  const { id } = req.params;
  
  const sql = "DELETE FROM questions WHERE id = ?";
  db.query(sql, [id], (err, result) => {
    if (err) {
      console.error("Error deleting question:", err);
      return res.status(500).json({ error: "Failed to delete question" });
    }
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Question not found" });
    }
    
    res.json({ message: "Question deleted successfully" });
  });
});


// ------------------------- checklist Routes-------------------------


// ------------------------- VIEW questions -------------------------
app.get("/api/get-questions", async (req, res) => {
  const { companyCode } = req.query;

  if (!companyCode) {
    return res.status(400).json({ error: "CompanyCode is required" });
  }

  const sql = "SELECT questionText, answerOptions, id, CompanyCode FROM questions WHERE CompanyCode = ?";

  db.query(sql, [companyCode], (err, data) => {
    if (err) {
      console.error("Error fetching questions:", err);
      return res.status(500).json({ error: "Failed to fetch questions" });
    }

    if (data.length === 0) {
      return res.status(404).json({ error: "No questions found for this company code" });
    }

    return res.status(200).json({ success: true, data });
  });
});

//...............................add-checklist...............................................

app.post('/api/add-checklist', upload.single('file'), (req, res) => {
  const { checklistName, description, sections, selectedQuestions, companyCode } = req.body;
  const filePath = req.file ? `/uploads/${req.file.filename}` : null; // File path if file is uploaded

  if (!checklistName || !description || !sections || !companyCode) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  // Parse sections to ensure JSON format
  let parsedSections;
  try {
    parsedSections = JSON.parse(sections);
  } catch (err) {
    return res.status(400).json({ error: 'Invalid sections format' });
  }

  // Validate that at least one question is assigned in sections or subsections
  const hasQuestions = parsedSections.some((section) => {
    if (section.questions && section.questions.length > 0) return true;
    return section.subsections.some((subsection) => subsection.questions && subsection.questions.length > 0);
  });

  if (!hasQuestions) {
    return res.status(400).json({ error: 'Please assign at least one question to a section or subsection.' });
  }

  const sql = `
    INSERT INTO checklists (checklist_name, description, sections, selected_questions, file_path, company_code)
    VALUES (?, ?, ?, ?, ?, ?)
  `;
  db.query(
    sql,
    [
      checklistName,
      description,
      JSON.stringify(parsedSections), // Ensure proper JSON format
      JSON.stringify(JSON.parse(selectedQuestions)), // Ensure proper JSON format
      filePath,
      companyCode,
    ],
    (err, result) => {
      if (err) {
        console.error('Error inserting checklist:', err);
        return res.status(500).json({ error: 'Failed to save checklist' });
      }
      res.status(201).json({
        message: 'Checklist saved successfully!',
        checklistId: result.insertId,
      });
    }
  );
});


//...................View Data Tabale ............................
app.get("/api/get-checklists", (req, res) => {
  const { companyCode } = req.query;
  if (!companyCode) {
    return res.status(400).json({ error: "Company code is required" });
  }
  const sql = "SELECT id, checklist_name, description FROM checklists WHERE company_code = ?";
  db.query(sql, [companyCode], (err, data) => {
    if (err) {
      console.error("Error fetching checklists:", err);
      return res.status(500).json({ error: "Failed to fetch checklists" });
    }
    res.json(data);
  });
});

//...................delete ............................
app.delete("/api/delete-checklist/:id", (req, res) => {
  const { id } = req.params;
  if (!id) {
    return res.status(400).json({ error: "Checklist ID is required" });
  }
  const sql = "DELETE FROM checklists WHERE id = ?";
  db.query(sql, [id], (err, result) => {
    if (err) {
      console.error("Error deleting checklist:", err);
      return res.status(500).json({ error: "Failed to delete checklist" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Checklist not found" });
    }
    res.status(200).json({ message: "Checklist deleted successfully" });
  });
});


//.........edit checklist.........

app.get("/api/get-checklist/:id", (req, res) => {
  const { id } = req.params;
  const sql = "SELECT * FROM checklists WHERE id = ?";
  db.query(sql, [id], (err, data) => {
    if (err) {
      console.error("Error fetching checklist:", err);
      return res.status(500).json({ error: "Failed to fetch checklist" });
    }
    if (data.length === 0) {
      return res.status(404).json({ error: "Checklist not found" });
    }
    res.json(data[0]);
  });
});

//............................

app.put("/api/update-checklist/:id", upload.single('file'), (req, res) => {
  const { id } = req.params;
  const { checklistName, description, sections, selectedQuestions, companyCode } = req.body;
  
  // Get the file path if a new file is uploaded
  const filePath = req.file ? `/uploads/${req.file.filename}` : null;

  if (!checklistName || !description || !sections || !selectedQuestions || !companyCode) {
    return res.status(400).json({ error: "All fields are required" });
  }

  // Prepare the SQL query for update
  const sql = filePath
    ? `
      UPDATE checklists 
      SET checklist_name = ?, description = ?, sections = ?, selected_questions = ?, company_code = ?, file_path = ?
      WHERE id = ?
    `
    : `
      UPDATE checklists 
      SET checklist_name = ?, description = ?, sections = ?, selected_questions = ?, company_code = ?
      WHERE id = ?
    `;

  // Prepare parameters based on whether a file is uploaded
  const params = filePath
    ? [checklistName, description, sections, selectedQuestions, companyCode, filePath, id]
    : [checklistName, description, sections, selectedQuestions, companyCode, id];

  db.query(sql, params, (err, result) => {
    if (err) {
      console.error("Error updating checklist:", err);
      return res.status(500).json({ error: "Failed to update checklist" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Checklist not found" });
    }
    res.status(200).json({ message: "Checklist updated successfully" });
  });
});


// ------------------------- User Profile Routes -------------------------
app.get("/api/user/:id", (req, res) => {
  const userId = parseInt(req.params.id, 10);

  if (isNaN(userId) || userId <= 0) {
    return res.status(400).json({ message: "Invalid user ID" });
  }

  const sql = "SELECT * FROM users WHERE id = ?";
  db.query(sql, [userId], (err, result) => {
    if (err) {
      console.error("Error fetching user:", err);
      return res.status(500).json({ error: "Failed to fetch user" });
    }

    if (result.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(result[0]);  // Send back the first result
  });
});


// Update user details (including profileImage if updated)
app.put("/api/user/:id", upload.single("profileImage"), (req, res) => {
  const userId = parseInt(req.params.id, 10);

  if (isNaN(userId) || userId <= 0) {
    return res.status(400).json({ message: "Invalid user ID" });
  }

  const { firstName, lastName, phoneNumber, emailAddress } = req.body;
  const profileImage = req.file ? `/uploads/${req.file.filename}` : null;

  if (!firstName || !lastName || !emailAddress) {
    return res.status(400).json({
      message: "First name, last name, and email address are required.",
    });
  }

  const sql = profileImage
    ? `UPDATE users 
       SET firstName = ?, lastName = ?, phoneNumber = ?, emailAddress = ?, profileImage = ? 
       WHERE id = ?`
    : `UPDATE users 
       SET firstName = ?, lastName = ?, phoneNumber = ?, emailAddress = ? 
       WHERE id = ?`;

  const params = profileImage
    ? [firstName, lastName, phoneNumber, emailAddress, profileImage, userId]
    : [firstName, lastName, phoneNumber, emailAddress, userId];

  db.query(sql, params, (err, result) => {
    if (err) {
      console.error("Error updating user:", err);
      return res.status(500).json({ error: "Failed to update user." });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    res.json({ message: "User updated successfully." }); // Ensure correct response
  });
});


// ------------------------- CompanyUsers Routes -------------------------

// Get all CompanyUsers
app.get("/CompanyUsers", (req, res) => {
  const { companyCode } = req.query;
  let sql = "SELECT * FROM users";

  if (companyCode) {
    sql += " WHERE CompanyCode = ?";
  }

  db.query(sql, [companyCode], (err, data) => {
    if (err) {
      console.error("Error fetching Company Users:", err);
      return res.status(500).json({ error: err.message });
    }
    res.json(data);
  });
});

// Add a new CompanyUser
app.post("/api/add-CompanyUsers", async (req, res) => {
  const { firstName, lastName, phoneNumber, emailAddress, password, role, CompanyCode } = req.body;

  if (!firstName || !lastName || !emailAddress || !password || !role || !CompanyCode) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = `
      INSERT INTO users (firstName, lastName, phoneNumber, emailAddress, password, role, CompanyCode)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `;

    db.query(
      sql,
      [firstName, lastName, phoneNumber, emailAddress, hashedPassword, role, CompanyCode],
      (err, result) => {
        if (err) {
          console.error("Error adding Company User:", err);
          return res.status(500).json({ error: "Failed to add Company User" });
        }
        res.status(201).json({ message: "Company User added successfully", userId: result.insertId });
      }
    );
  } catch (err) {
    console.error("Error hashing password:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Update a CompanyUser
app.put("/api/update-CompanyUsers/:id", async (req, res) => {
  const { id } = req.params;
  const { firstName, lastName, phoneNumber, emailAddress, password, role } = req.body;

  if (!firstName || !lastName || !emailAddress || !role) {
    return res.status(400).json({ error: "All fields except password are required" });
  }

  try {
    // Prepare SQL statement and fields to update
    let sql = `
      UPDATE users 
      SET firstName = ?, lastName = ?, phoneNumber = ?, emailAddress = ?, role = ?
    `;
    const fields = [firstName, lastName, phoneNumber, emailAddress, role];

    // Only update password if it is provided
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      sql += `, password = ?`;
      fields.push(hashedPassword);
    }

    // Complete SQL statement with WHERE clause
    sql += ` WHERE id = ?`;
    fields.push(id);

    // Execute query
    db.query(sql, fields, (err, result) => {
      if (err) {
        console.error("Error updating Company User:", err);
        return res.status(500).json({ error: "Failed to update Company User" });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({ error: "User not found" });
      }

      res.json({ message: "Company User updated successfully" });
    });
  } catch (err) {
    console.error("Error hashing password:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});


// Delete a CompanyUser
app.delete("/api/delete-CompanyUsers/:id", (req, res) => {
  const { id } = req.params;

  if (!id) {
    return res.status(400).json({ error: "User ID is required" });
  }

  const sql = "DELETE FROM users WHERE id = ?";
  db.query(sql, [id], (err, result) => {
    if (err) {
      console.error("Error deleting Company User:", err);
      return res.status(500).json({ error: "Failed to delete Company User" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ message: "Company User deleted successfully" });
  });
});

//..............................
// Assign Checklist to Auditors
app.get("/api/get-auditors/:companyCode", (req, res) => {
  const { companyCode } = req.params;

  if (!companyCode) {
    return res.status(400).json({ error: "Company Code is required" });
  }

  const sql = `
    SELECT id, firstName, lastName 
    FROM users 
    WHERE role = 'Auditor' AND CompanyCode = ?
  `;

  db.query(sql, [companyCode], (err, result) => {
    if (err) {
      console.error("Error fetching auditors:", err);
      return res.status(500).json({ error: "Failed to fetch auditors" });
    }

    // Ensure we return an array, even if there are no results
    res.json(result || []);
  });
});

// Assign Checklist
app.post("/api/assign-checklist", (req, res) => {
  const { checklistId, auditors, branches, company, status } = req.body;

  if (!checklistId || !Array.isArray(auditors) || !auditors.length || !branches || !company) {
    return res
      .status(400)
      .json({ error: "Checklist ID, auditors, branches, and company are required" });
  }

  const defaultStatus = status || "Pending"; // Default to Pending if not provided

  const values = auditors.map((auditorId) => [
    checklistId,
    auditorId,
    company,
    JSON.stringify(branches), // Store branch names as a JSON string
    defaultStatus,
  ]);

  const sql = `
    INSERT INTO assigned_checklists (checklist_id, auditor_id, company, branches, status)
    VALUES ?
  `;

  db.query(sql, [values], (err) => {
    if (err) {
      console.error("Error assigning checklist:", err);
      return res.status(500).json({ error: "Failed to assign checklist" });
    }
    res.status(200).json({ message: "Checklist assigned successfully" });
  });
});

// Fetch Assigned Checklists
app.get("/api/get-assigned-checklists/:auditorId", (req, res) => {
  const { auditorId } = req.params;

  if (!auditorId) {
    return res.status(400).json({ error: "Auditor ID is required" });
  }

  const sql = `
    SELECT 
      ac.id AS assigned_id, 
      ac.checklist_id,
      ac.company,
      ac.branches,
      ac.status,
      c.checklist_name, 
      c.description, 
      c.created_at, 
      c.updated_at 
    FROM assigned_checklists ac
    JOIN checklists c ON ac.checklist_id = c.id
    WHERE ac.auditor_id = ?
  `;

  db.query(sql, [auditorId], (err, results) => {
    if (err) {
      console.error("Error fetching assigned checklists:", err);
      return res.status(500).json({ error: "Failed to fetch assigned checklists" });
    }

    // Parse branches from JSON string to an array before sending the response
    const parsedResults = results.map((row) => ({
      ...row,
      branches: JSON.parse(row.branches || "[]"), // Default to an empty array if null
    }));

    res.json(parsedResults || []);
  });
});

// Fetch Checklist Questions Endpoint
app.get("/api/get-checklist-questions/:checklistId", (req, res) => {
  const { checklistId } = req.params;

  // Step 1: Retrieve sections and selected_questions fields from the checklist table
  const checklistQuery = `
    SELECT sections, selected_questions 
    FROM checklists 
    WHERE id = ?;
  `;

  db.query(checklistQuery, [checklistId], (err, results) => {
    if (err) {
      console.error("Error fetching checklist:", err);
      return res.status(500).json({
        error: "Failed to fetch checklist",
        details: err.message,
      });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: "Checklist not found" });
    }

    const { sections, selected_questions } = results[0];

    // Parse sections and selected_questions fields
    let parsedSections, questionIds;
    try {
      parsedSections = sections ? JSON.parse(sections) : [];
      questionIds = selected_questions ? JSON.parse(selected_questions) : [];
    } catch (parseError) {
      console.error("Error parsing checklist data:", parseError);
      return res.status(500).json({
        error: "Failed to parse checklist data",
        details: parseError.message,
      });
    }

    if (!Array.isArray(questionIds) || questionIds.length === 0) {
      return res.status(404).json({
        error: "No questions found for the given checklist",
      });
    }

    // Step 2: Fetch questions from the questions table
    const questionsQuery = `
      SELECT 
        id AS question_id, 
        questionText, 
        answerType, 
        answerOptions 
      FROM questions 
      WHERE id IN (?);
    `;

    db.query(questionsQuery, [questionIds], (err, questionResults) => {
      if (err) {
        console.error("Error fetching questions:", err);
        return res.status(500).json({
          error: "Failed to fetch questions",
          details: err.message,
        });
      }

      if (questionResults.length === 0) {
        return res.status(404).json({
          error: "No questions found for the provided IDs",
        });
      }

      // Map questions to their respective sections
      const mapQuestionsToSections = (sections, questions) => {
        const questionMap = new Map(
          questions.map((q) => [q.question_id, q])
        );

        const mapSectionQuestions = (section) => {
          section.questions = section.questions.map(
            (id) => questionMap.get(id) || { question_id: id, error: "Not found" }
          );
          if (section.subsections) {
            section.subsections = section.subsections.map(mapSectionQuestions);
          }
          return section;
        };

        return sections.map(mapSectionQuestions);
      };

      const enrichedSections = mapQuestionsToSections(parsedSections, questionResults);

      // Return the enriched sections and questions
      res.status(200).json({ sections: enrichedSections });
    });
  });
});

// Modified save-answers endpoint to handle multiple files
app.post("/api/save-answers", upload.any(), async (req, res) => {
  try {
    // Parse the JSON data from the form
    const { checklistId, answers } = JSON.parse(req.body.data);

    if (!checklistId || !Array.isArray(answers) || answers.length === 0) {
      return res.status(400).json({ 
        error: "❌ Invalid checklist ID or answers array is empty." 
      });
    }

    const insertOrUpdateQuery = `
      INSERT INTO responses 
        (checklist_id, section, question_id, answer, remarks, media_file)
      VALUES 
        (?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        answer = VALUES(answer),
        remarks = VALUES(remarks),
        media_file = VALUES(media_file);
    `;

    const dbPromises = answers.map(answer => {
      return new Promise((resolve, reject) => {
        // Find the corresponding file for this question
        const mediaFile = req.files?.find(file => 
          file.fieldname === `mediaFile_${answer.questionId}`
        );
        
        const mediaFileName = mediaFile ? mediaFile.filename : answer.mediaFile;
        
        db.query(
          insertOrUpdateQuery,
          [
            checklistId, 
            answer.section, 
            answer.questionId, 
            answer.answer, 
            answer.remarks,
            mediaFileName
          ],
          (err, result) => {
            if (err) reject(err);
            else resolve(result);
          }
        );
      });
    });

    await Promise.all(dbPromises);
    res.status(200).json({ 
      message: "✅ Answers saved successfully!",
      files: req.files?.map(f => f.filename) || []
    });

  } catch (error) {
    console.error("❌ Error saving answers:", error);
    res.status(500).json({ error: "❌ Failed to save answers." });
  }
});







// ------------------------- Start Server -------------------------

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
