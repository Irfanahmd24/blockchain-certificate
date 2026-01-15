/**
 * Node.js Server for Student Certificate Verification
 * * This server handles API requests, file uploads, hashing, and interaction 
 * with the Ethereum blockchain (Ganache) via web3.js.
 */

// -----------------------------------------------------------
// CORE SERVER SETUP AND DEPENDENCIES
// -----------------------------------------------------------
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const QRCode = require('qrcode');
const Web3 = require('web3').default;
const bcrypt = require('bcrypt');

const connectDB = require('./db'); // ✅ FIXED

const app = express();
connectDB();

const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;


// Middleware Setup
app.use(bodyParser.json());
// Ensure 'public' directory is available for static file serving (HTML, images, PDFs)
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));

// -----------------------------------------------------------
// BLOCKCHAIN AND WEB3 SETUP
// -----------------------------------------------------------
const SEPOLIA_RPC = process.env.SEPOLIA_RPC_URL;
// Initialize Web3 instance
const web3 = new Web3(SEPOLIA_RPC);
// !!! DEPLOYMENT DETAILS - IMPORTANT: Update these based on your deployed contract !!!
// IMPORTANT: These must match the address of your deployed CertificateRegistry contract
const CONTRACT_ADDRESS = '0xcdc798b52c7feac10cf67696d97ecec321ebf46b';
const ADMIN_WALLET = '0x89E6BDb6d3B9f79d4d82E032C3eC7C67D8F4cD10';
 // Admin's public key (must match contract owner)
const ADMIN_PRIVATE_KEY = process.env.PRIVATE_KEY;
if (
  !ADMIN_PRIVATE_KEY ||
  typeof ADMIN_PRIVATE_KEY !== "string" ||
  !ADMIN_PRIVATE_KEY.startsWith("0x") ||
  ADMIN_PRIVATE_KEY.length !== 66
) {
  throw new Error("INVALID or MISSING PRIVATE_KEY in .env file");
}
 // Admin's private key for signing transactions

let registryContract;

// Load Contract ABI (Sepolia – clean ABI file)
// Load Contract ABI (Sepolia – clean ABI file)
try {
    const CertificateRegistryABI = require('./abi/CertificateRegistry.json');
    registryContract = new web3.eth.Contract(
        CertificateRegistryABI,
        CONTRACT_ADDRESS
    );
    console.log('[Web3] Contract loaded successfully (Sepolia).');
} catch (e) {
    console.error('[Web3] ERROR: Could not load contract ABI from abi folder.', e);
}
// -----------------------------------------------------------
// SIMULATED DATABASE SETUP (for Student Accounts and Certificate Metadata)
// -----------------------------------------------------------
const STUDENT_DB_PATH = path.join(__dirname, 'student_db.json');
let studentDB = {}; // Global variable to hold in-memory database

function loadStudents() {
    try {
        console.log(`[DB Path] Checking: ${STUDENT_DB_PATH}`);
        if (fs.existsSync(STUDENT_DB_PATH)) {
            const data = fs.readFileSync(STUDENT_DB_PATH, 'utf8');
            studentDB = data ? JSON.parse(data) : {};
            console.log(`[DB] Loaded ${Object.keys(studentDB).length} student records from file.`);
        } else {
            fs.writeFileSync(STUDENT_DB_PATH, JSON.stringify({}), 'utf8');
            console.log(`[DB] Created empty student database file.`);
        }
    } catch (e) {
        console.error('[DB] CRITICAL ERROR loading student database:', e);
        studentDB = {};
    }
}

function saveStudents() {
    try {
        fs.writeFileSync(STUDENT_DB_PATH, JSON.stringify(studentDB, null, 4), 'utf8');
        console.log(`[DB] Successfully saved ${Object.keys(studentDB).length} student records to file.`);
    } catch (e) {
        console.error('[DB] CRITICAL ERROR saving student database:', e);
    }
}

loadStudents(); // Initialize the database on server start

// -----------------------------------------------------------
// FILE STORAGE CONFIGURATION
// -----------------------------------------------------------
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const certsDir = path.join(__dirname, 'public/certificates');
        const imgsDir = path.join(__dirname, 'public/imgs');
        const qrDir = path.join(__dirname, 'public/imgs/qrcodes');

        [certsDir, imgsDir, qrDir].forEach(dir => {
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
        });

        if (file.fieldname === 'pdfFile') {
            cb(null, certsDir);
        } else if (file.fieldname === 'studentPhoto') {
            cb(null, imgsDir);
        }
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname.replace(/ /g, '_'));
    }
});
const upload = multer({ storage: storage });

// -----------------------------------------------------------
// HELPER FUNCTIONS
// -----------------------------------------------------------
function hashFile(filePath) {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash('sha256');
        const stream = fs.createReadStream(filePath);
        stream.on('error', err => reject(err));
        stream.on('data', chunk => hash.update(chunk));
        stream.on('end', () => resolve(hash.digest('hex')));
    });
}

// -----------------------------------------------------------
// ADMIN API ENDPOINTS
// -----------------------------------------------------------
app.post('/api/admin/create-student-account', async (req, res) => {
    const { rollNumber, mailId, password, studentName, studentClass, department, yearOfPass, percentage } = req.body;

    if (!rollNumber || !mailId || !password || !studentName) {
        return res.status(400).json({ success: false, message: 'Missing required fields: Roll Number, Email, Password, or Student Name.' });
    }

    if (studentDB[rollNumber]) {
        return res.status(409).json({ success: false, message: `Student with Roll Number ${rollNumber} already exists.` });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        studentDB[rollNumber] = {
            mailId: mailId,
            hashedPassword: hashedPassword,
            studentName: studentName,
            studentClass: studentClass || 'N/A',
            department: department || 'N/A',
            yearOfPass: yearOfPass ? parseInt(yearOfPass) : 'N/A',
            percentage: percentage || 'N/A',
            certificates: []
        };
        saveStudents();
        console.log(`[API] Successfully created student account for: ${rollNumber}`);
        res.json({ success: true, message: `Student ${rollNumber} account created successfully.` });
    } catch (error) {
        console.error('Student Account Creation Error:', error);
        res.status(500).json({ success: false, message: 'Failed to create student account due to a server error.' });
    }
});

app.post('/api/admin/issue-certificate', upload.fields([{ name: 'pdfFile', maxCount: 1 }, { name: 'studentPhoto', maxCount: 1 }]), async (req, res) => {
    if (!req.files || !req.files['pdfFile'] || !req.files['studentPhoto']) {
        return res.status(400).json({ success: false, message: 'Both PDF certificate and student photo must be uploaded.' });
    }

    const { studentId } = req.body;

    if (!studentDB[studentId]) {
        if (fs.existsSync(req.files['pdfFile'][0].path)) fs.unlinkSync(req.files['pdfFile'][0].path);
        if (fs.existsSync(req.files['studentPhoto'][0].path)) fs.unlinkSync(req.files['studentPhoto'][0].path);
        return res.status(404).json({ success: false, message: `Student with ID ${studentId} must be registered first via the 'Create Student Account' page.` });
    }

    const pdfPath = req.files['pdfFile'][0].path;
    const photoPath = req.files['studentPhoto'][0].path;
    let certHash;
    const qrDir = path.join(__dirname, 'public/imgs/qrcodes');
    let qrCodeFilename = `${studentId}-${Date.now()}.png`;
    let qrCodeRelativePath = `imgs/qrcodes/${qrCodeFilename}`;
    let qrCodeFullPath = path.join(qrDir, qrCodeFilename);

    try {
        const hashHex = await hashFile(pdfPath);
        certHash = '0x' + hashHex;
        // 🔴 PREVENT DUPLICATE CERTIFICATES (IMPORTANT)
const alreadyIssued = await registryContract.methods
    .verifyCertificate(certHash)
    .call();

if (alreadyIssued) {
    // Cleanup uploaded files
    if (fs.existsSync(pdfPath)) fs.unlinkSync(pdfPath);
    if (fs.existsSync(photoPath)) fs.unlinkSync(photoPath);
    if (qrCodeFullPath && fs.existsSync(qrCodeFullPath)) fs.unlinkSync(qrCodeFullPath);

    return res.status(400).json({
        success: false,
        message: 'Certificate already issued'
    });
}

        await QRCode.toFile(qrCodeFullPath, certHash);

        if (!registryContract) {
            throw new Error("Blockchain contract not initialized. Check Web3 setup.");
        }

        const txData = registryContract.methods.issueCertificate(certHash, studentId).encodeABI();
        const gasEstimate = await web3.eth.estimateGas({ from: ADMIN_WALLET, to: CONTRACT_ADDRESS, data: txData });
        const tx = {
  from: ADMIN_WALLET,
  to: CONTRACT_ADDRESS,
  data: txData,
  gas: gasEstimate,

  //  EIP-1559 gas (FIXES revert error)
  maxFeePerGas: web3.utils.toWei('3', 'gwei'),
  maxPriorityFeePerGas: web3.utils.toWei('2', 'gwei')
};
        const signedTx = await web3.eth.accounts.signTransaction(tx, ADMIN_PRIVATE_KEY);

//  send tx but do NOT wait
web3.eth.sendSignedTransaction(signedTx.rawTransaction)
  .on('transactionHash', (txHash) => {
    console.log('Transaction sent:', txHash);
  })
  .on('error', (err) => {
    console.error('Blockchain error:', err);
  });

//  prepare paths
const pdfPublicPath = path.relative(
  path.join(__dirname, 'public'),
  pdfPath
);

const photoPublicPath = path.relative(
  path.join(__dirname, 'public'),
  photoPath
);

//  save immediately (no receipt)
studentDB[studentId].certificates.push({
  certificateHash: certHash,
  pdfFilePath: `/${pdfPublicPath.replace(/\\/g, '/')}`,
  photoFilePath: `/${photoPublicPath.replace(/\\/g, '/')}`,
  qrCodePath: `/${qrCodeRelativePath.replace(/\\/g, '/')}`,
  blockchainTxHash: 'pending',
  issueTimestamp: new Date().toISOString()
});

saveStudents();

//  respond ONCE and END
return res.json({
  success: true,
  message: 'Certificate submitted to blockchain (confirmation pending)',
  hash: certHash,
  txHash: 'pending',
  qrCodePath: `/${qrCodeRelativePath.replace(/\\/g, '/')}`
});
    } catch (error) {
        console.error('Certificate Issuance Error:', error);
        if (pdfPath && fs.existsSync(pdfPath)) fs.unlinkSync(pdfPath);
        if (photoPath && fs.existsSync(photoPath)) fs.unlinkSync(photoPath);
        if (qrCodeFullPath && fs.existsSync(qrCodeFullPath)) fs.unlinkSync(qrCodeFullPath);
        res.status(500).json({ success: false, message: `Failed to issue certificate. Details: ${error.message}` });
    }
});

// -----------------------------------------------------------
// STUDENT LOGIN AND RETRIEVAL API
// -----------------------------------------------------------
app.post('/api/student/login', async (req, res) => {
    const { rollNumber, password } = req.body;
    if (!rollNumber || !password) {
        return res.status(400).json({ success: false, message: 'Roll Number and Password are required.' });
    }
    const studentRecord = studentDB[rollNumber];
    if (!studentRecord) {
        return res.status(404).json({ success: false, message: 'Invalid Roll Number or account not found.' });
    }
    try {
        const isMatch = await bcrypt.compare(password, studentRecord.hashedPassword);
        if (isMatch) {
            res.json({
                success: true,
                message: 'Login successful.',
                rollNumber: rollNumber,
                studentName: studentRecord.studentName
            });
        } else {
            res.status(401).json({ success: false, message: 'Invalid Roll Number or password.' });
        }
    } catch (error) {
        console.error('Login Error:', error);
        res.status(500).json({ success: false, message: 'An internal error occurred during login.' });
    }
});

app.get('/api/student/certificates/:rollNumber', async (req, res) => {
    const rollNumber = req.params.rollNumber;
    try {
        const studentRecord = studentDB[rollNumber];
        if (!studentRecord) {
            return res.status(404).json({ success: false, message: 'Student roll number not found.' });
        }
        const safeCertificates = (studentRecord.certificates || []).map(cert => ({
            id: cert.certificateHash,
            name: studentRecord.studentName,
            pdfDownloadUrl: cert.pdfFilePath,
            photoFilePath: cert.photoFilePath,
            qrCodePath: cert.qrCodePath,
            blockchainTxHash: cert.blockchainTxHash,
            issueTimestamp: cert.issueTimestamp,
            department: studentRecord.department,
            yearOfPass: studentRecord.yearOfPass,
            studentClass: studentRecord.studentClass,
            percentage: studentRecord.percentage
        }));
        const studentProfile = {
            rollNumber: rollNumber,
            name: studentRecord.studentName,
            department: studentRecord.department,
            yearOfPass: studentRecord.yearOfPass,
            class: studentRecord.studentClass,
            percentage: studentRecord.percentage,
            mailId: studentRecord.mailId
        };
        res.json({ success: true, profile: studentProfile, certificates: safeCertificates });
    } catch (error) {
        console.error('Student certificate retrieval error:', error);
        res.status(500).json({ success: false, message: 'Failed to retrieve certificates.' });
    }
});



app.get('/api/admin/all-records', async (req, res) => {
    try {
        // We convert the studentDB object into an array for easier use on the frontend.
        // We also remove the sensitive hashedPassword from the response.
        const records = Object.values(studentDB).map(student => {
            const { hashedPassword, ...safeData } = student;
            // We need to add the rollNumber to each student object since it's the key in the DB
            const studentWithRoll = Object.values(studentDB).find(s => s.studentName === safeData.studentName);
            if (studentWithRoll) {
                const rollNumber = Object.keys(studentDB).find(key => studentDB[key] === studentWithRoll);
                safeData.rollNumber = rollNumber;
            }
            return safeData;
        });

        res.json({ success: true, records });

    } catch (error) {
        console.error('Error fetching all records:', error);
        res.status(500).json({ success: false, message: 'Failed to retrieve records from the server.' });
    }
});


// -----------------------------------------------------------
// VERIFIER API ENDPOINT
// -----------------------------------------------------------
app.post('/api/verifier/verify-hash', async (req, res) => {
    const { certificateHash } = req.body;
    if (!certificateHash || certificateHash.length !== 66 || !certificateHash.startsWith('0x')) {
        return res.status(400).json({ success: false, message: 'Invalid certificate hash format. Must be a 0x-prefixed bytes32 hex string (66 characters long).' });
    }
    try {
        if (!registryContract) {
            throw new Error("Blockchain contract not initialized. Check Web3 setup.");
        }

        const details = await registryContract.methods.getCertificateDetails(certificateHash).call();
        
        // START: === CORRECTED CODE ===
        // Use named property destructuring for clarity and safety with web3.js v4
        const { issuer, timestamp, isValid, studentId } = details;

        let status;
        let dbDetails = null;

        if (issuer !== '0x0000000000000000000000000000000000000000' && isValid) {
            status = 'VALID';
            const studentRecord = studentDB[studentId];
            if (studentRecord) {
                const cert = (studentRecord.certificates || []).find(c => c.certificateHash === certificateHash);
                
                // Safely convert the BigInt timestamp to a Number for the Date constructor
                const issueDate = new Date(parseInt(timestamp.toString()) * 1000).toLocaleString();

                dbDetails = {
                    studentId: studentId,
                    studentName: studentRecord.studentName,
                    department: studentRecord.department,
                    yearOfPass: studentRecord.yearOfPass,
                    issueDate: issueDate,
                    pdfDownloadUrl: cert ? cert.pdfFilePath : 'N/A',
                    photoFilePath: cert ? cert.photoFilePath : 'N/A'
                };
            }
        } else {
            status = 'INVALID';
        }

        res.json({
            success: true,
            status: status,
            blockchainDetails: {
                issuer: issuer,
                // Safely convert BigInt to string for JSON transport
                timestamp: timestamp.toString(),
                isValid: isValid,
                studentId: studentId
            },
            metadata: dbDetails
        });
        // END: === CORRECTED CODE ===

    } catch (error) {
        console.error('Certificate Verification Error:', error);
        res.status(500).json({ success: false, message: 'Failed to verify hash. Check network connection or server logs.' });
    }
});

// -----------------------------------------------------------
// START SERVER
// -----------------------------------------------------------
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
    console.log(`Public files served from: ${path.join(__dirname, 'public')}`);
});