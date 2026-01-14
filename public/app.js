let web3;

// Check if Web3 is injected by Metamask
if (typeof window.ethereum !== "undefined") {
  web3 = new Web3(window.ethereum);
  // Request account access if needed
  // Using eth_requestAccounts instead of ethereum.enable() for modern compatibility
  window.ethereum.request({ method: 'eth_requestAccounts' })
    .catch((error) => {
      console.error("Error enabling Metamask accounts:", error.message);
      displayMessage("Failed to connect MetaMask. Please allow access to your accounts.");
    });
} else {
  // Handle the case where the user doesn't have Metamask installed or not connected to the Ethereum network
  // Using a custom modal/message instead of alert()
  displayMessage("Please install Metamask to use this application.");
}


// Contract Address and ABI (replace with your actual deployed contract address and ABI)
const contractAddress = "0xbde7b241fEBEcA508060301F4C265d26537691A7"; // Ensure this is your deployed contract address
const contractABI = [
  {
    inputs: [],
    stateMutability: "nonpayable",
    type: "constructor",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "address",
        name: "admin",
        type: "address",
      },
    ],
    name: "AdminLoggedIn",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "address",
        name: "donor",
        type: "address",
      },
      {
        indexed: false,
        internalType: "enum BloodBank.BloodType",
        name: "bloodType",
        type: "uint8",
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "amount",
        type: "uint256",
      },
    ],
    name: "BloodDonated",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "address",
        name: "patient",
        type: "address",
      },
      {
        // Simplified BloodRequested event to match the struct in the contract
        components: [
          {
            internalType: "bool",
            name: "isResponded",
            type: "bool",
          },
          {
            internalType: "enum BloodBank.BloodType",
            name: "bloodType",
            type: "uint8",
          },
          {
            internalType: "uint256",
            name: "amount",
            type: "uint256",
          },
          {
            internalType: "bool",
            name: "response",
            type: "bool",
          },
        ],
        indexed: false,
        internalType: "struct BloodBank.Request",
        name: "request",
        type: "tuple",
      },
    ],
    name: "BloodRequested",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "address",
        name: "donor",
        type: "address",
      },
    ],
    name: "DonorPermissionGranted",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "address",
        name: "donor",
        type: "address",
      },
    ],
    name: "DonorPermissionRevoked",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "address",
        name: "donor",
        type: "address",
      },
      {
        indexed: false,
        internalType: "string",
        name: "name",
        type: "string",
      },
      {
        indexed: false,
        internalType: "enum BloodBank.BloodType",
        name: "bloodType",
        type: "uint8",
      },
    ],
    name: "DonorRegistered",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "address",
        name: "hospital",
        type: "address",
      },
      {
        indexed: false,
        internalType: "string",
        name: "name",
        type: "string",
      },
      {
        indexed: false,
        internalType: "address",
        name: "location",
        type: "address",
      },
    ],
    name: "HospitalRegistered",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "address",
        name: "patient",
        type: "address",
      },
    ],
    name: "PatientPermissionGranted",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "address",
        name: "patient",
        type: "address",
      },
    ],
    name: "PatientPermissionRevoked",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "address",
        name: "patient",
        type: "address",
      },
      {
        indexed: false,
        internalType: "string",
        name: "name",
        type: "string",
      },
      {
        indexed: false,
        internalType: "enum BloodBank.BloodType",
        name: "bloodType",
        type: "uint8",
      },
    ],
    name: "PatientRegistered",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "address",
        name: "patient",
        type: "address",
      },
      {
        indexed: false,
        internalType: "bool",
        name: "response",
        type: "bool",
      },
      {
        indexed: false,
        internalType: "enum BloodBank.BloodType",
        name: "bloodType",
        type: "uint8",
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "amount",
        type: "uint256",
      },
    ],
    name: "RequestResponded",
    type: "event",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "hospitalAddress",
        type: "address",
      },
      {
        internalType: "string",
        name: "name",
        type: "string",
      },
      {
        internalType: "address",
        name: "location",
        type: "address",
      },
    ],
    name: "addHospital",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "patientAddress",
        type: "address",
      },
      {
        internalType: "string",
        name: "name",
        type: "string",
      },
      {
        internalType: "enum BloodBank.BloodType",
        name: "bloodType",
        type: "uint8",
      },
    ],
    name: "addPatient",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "admin",
    outputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "adminLogin",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    name: "allowedDonors",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    name: "allowedPatients",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "enum BloodBank.BloodType",
        name: "",
        type: "uint8",
      },
    ],
    name: "bloodInventory",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    name: "bloodRequests",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "enum BloodBank.BloodType",
        name: "bloodType",
        type: "uint8",
      },
      {
        internalType: "uint256",
        name: "amount",
        type: "uint256",
      },
    ],
    name: "donateBlood",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    name: "donorAddresses",
    outputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
      {
        internalType: "enum BloodBank.BloodType",
        name: "",
        type: "uint8",
      },
    ],
    name: "donorBalances",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    name: "donors",
    outputs: [
      {
        internalType: "string",
        name: "name",
        type: "string",
      },
      {
        internalType: "enum BloodBank.BloodType",
        name: "bloodType",
        type: "uint8",
      },
      {
        internalType: "bool",
        name: "isRegistered",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "enum BloodBank.BloodType",
        name: "bloodType",
        type: "uint8",
      },
    ],
    name: "getBloodInventory",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "patientAddress",
        type: "address",
      },
      {
        internalType: "enum BloodBank.BloodType",
        name: "bloodType",
        type: "uint8",
      },
    ],
    name: "getPatientRequests",
    outputs: [
      {
        components: [
          {
            internalType: "bool",
            name: "isResponded",
            type: "bool",
          },
          {
            internalType: "enum BloodBank.BloodType",
            name: "bloodType",
            type: "uint8",
          },
          {
            internalType: "uint256",
            name: "amount",
            type: "uint256",
          },
          {
            internalType: "bool",
            name: "response",
            type: "bool",
          },
        ],
        internalType: "struct BloodBank.Request[]",
        name: "",
        type: "tuple[]",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "patientAddress",
        type: "address",
      },
    ],
    name: "getPatientResponses",
    outputs: [
      {
        components: [
          {
            internalType: "bool",
            name: "isResponded",
            type: "bool",
          },
          {
            internalType: "enum BloodBank.BloodType",
            name: "bloodType",
            type: "uint8",
          },
          {
            internalType: "uint256",
            name: "amount",
            type: "uint256",
          },
          {
            internalType: "bool",
            name: "response",
            type: "bool",
          },
        ],
        internalType: "struct BloodBank.Request[]",
        name: "",
        type: "tuple[]",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "getRegisteredUsers",
    outputs: [
      {
        internalType: "address[]",
        name: "registeredDonors",
        type: "address[]",
      },
      {
        internalType: "address[]",
        name: "registeredPatients",
        type: "address[]",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "getTotalBloodDonated",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "donorAddress",
        type: "address",
      },
    ],
    name: "grantDonorPermission",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "patientAddress",
        type: "address",
      },
    ],
    name: "grantPatientPermission",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    name: "hospitals",
    outputs: [
      {
        internalType: "string",
        name: "name",
        type: "string",
      },
      {
        internalType: "address",
        name: "location",
        type: "address",
      },
      {
        internalType: "bool",
        name: "isRegistered",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "donorAddress",
        type: "address",
      },
    ],
    name: "isDonorAllowed",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "patientAddress",
        type: "address",
      },
    ],
    name: "isPatientAllowed",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "hospitalAddress",
        type: "address",
      },
    ],
    name: "locateHospitalToDonate",
    outputs: [
      {
        internalType: "string",
        name: "name",
        type: "string",
      },
      {
        internalType: "address",
        name: "location",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    name: "patientAddresses",
    outputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
      {
        internalType: "enum BloodBank.BloodType",
        name: "",
        type: "uint8",
      },
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    name: "patientRequests",
    outputs: [
      {
        internalType: "bool",
        name: "isResponded",
        type: "bool",
      },
      {
        internalType: "enum BloodBank.BloodType",
        name: "bloodType",
        type: "uint8",
      },
      {
        internalType: "uint256",
        name: "amount",
        type: "uint256",
      },
      {
        internalType: "bool",
        name: "response",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    name: "patientResponses",
    outputs: [
      {
        internalType: "bool",
        name: "isResponded",
        type: "bool",
      },
      {
        internalType: "enum BloodBank.BloodType",
        name: "bloodType",
        type: "uint8",
      },
      {
        internalType: "uint256",
        name: "amount",
        type: "uint256",
      },
      {
        internalType: "bool",
        name: "response",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    name: "patients",
    outputs: [
      {
        internalType: "string",
        name: "name",
        type: "string",
      },
      {
        internalType: "enum BloodBank.BloodType",
        name: "bloodType",
        type: "uint8",
      },
      {
        internalType: "bool",
        name: "isRegistered",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "string",
        name: "name",
        type: "string",
      },
      {
        internalType: "enum BloodBank.BloodType",
        name: "bloodType",
        type: "uint8",
      },
    ],
    name: "registerAsDonor",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "string",
        name: "name",
        type: "string",
      },
      {
        internalType: "enum BloodBank.BloodType",
        name: "bloodType",
        type: "uint8",
      },
    ],
    name: "registerAsPatient",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "enum BloodBank.BloodType",
        name: "bloodType",
        type: "uint8",
      },
      {
        internalType: "uint256",
        name: "amount",
        type: "uint256",
      },
    ],
    name: "requestBlood",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "patientAddress",
        type: "address",
      },
      {
        internalType: "enum BloodBank.BloodType",
        name: "bloodType",
        type: "uint8",
      },
      {
        internalType: "bool",
        name: "response",
        type: "bool",
      },
    ],
    name: "respondToRequest",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "donorAddress",
        type: "address",
      },
    ],
    name: "revokeDonorPermission",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "patientAddress",
        type: "address",
      },
    ],
    name: "revokePatientPermission",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "totalBloodDonated",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "totalDonors",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "totalHospitals",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "totalPatients",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
];
const bloodBankContract = new web3.eth.Contract(contractABI, contractAddress);

// Custom message box function instead of alert()
function displayMessage(message) {
  const messageBox = document.createElement('div');
  messageBox.style.cssText = `
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background-color: #f0f0f0;
    border: 1px solid #ccc;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    z-index: 1000;
    font-family: Arial, sans-serif;
    color: #333;
    text-align: center;
  `;
  messageBox.innerHTML = `
    <p style="color: #333;">${message}</p>
    <button onclick="this.parentNode.remove()" style="
      background-color: #3498db;
      color: white;
      border: none;
      padding: 8px 16px;
      margin-top: 10px;
      border-radius: 4px;
      cursor: pointer;
    ">OK</button>
  `;
  document.body.appendChild(messageBox);
}

// Custom confirmation box function instead of confirm()
function displayConfirm(message, callback) {
    const confirmBox = document.createElement('div');
    confirmBox.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background-color: #f0f0f0;
        border: 1px solid #ccc;
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        z-index: 1000;
        font-family: Arial, sans-serif;
        color: #333;
        text-align: center;
    `;
    confirmBox.innerHTML = `
        <p style="color: #333;">${message}</p>
        <button id="confirmYes" style="
            background-color: #3498db;
            color: white;
            border: none;
            padding: 8px 16px;
            margin-top: 10px;
            margin-right: 10px;
            border-radius: 4px;
            cursor: pointer;
        ">Yes</button>
        <button id="confirmNo" style="
            background-color: #e74c3c;
            color: white;
            border: none;
            padding: 8px 16px;
            margin-top: 10px;
            border-radius: 4px;
            cursor: pointer;
        ">No</button>
    `;
    document.body.appendChild(confirmBox);

    document.getElementById('confirmYes').onclick = () => {
        confirmBox.remove();
        callback(true);
    };
    document.getElementById('confirmNo').onclick = () => {
        confirmBox.remove();
        callback(false);
    };
}


function redirectTo(page) {
  window.location.href = page;
}

// Function to handle admin login
async function adminLogin() {
  try {
    const adminAddress = document.getElementById("adminAddress").value;
    const isValidAdmin = await isValidAdminAddress(adminAddress);

    if (isValidAdmin) {
      displayMessage("Admin Login Successful");
      redirectTo("admin_dashboard.html");
    } else {
      displayMessage("Invalid Admin Address");
    }
  } catch (error) {
    console.error("Error logging in as admin:", error.message);
  }
}

// Function to validate admin address
async function isValidAdminAddress(adminAddress) {
  return adminAddress.trim() !== "";
}

async function registerDonor() {
  await registerUser("Donor");
}

async function registerPatient() {
  await registerUser("Patient");
}

// Function to register a user (donor or patient)
async function registerUser() {
  try {
    const userName = document.getElementById("userName").value;
    const userType = document.getElementById("userType").value;

    const bloodTypeSelect = document.getElementById("bloodType");
    const selectedBloodType = bloodTypeSelect.options[bloodTypeSelect.selectedIndex].value;

    // UPDATED: bloodTypeMapping to include Rh factors
    const bloodTypeMapping = {
      "A_POS": 0, "A+": 0,
      "A_NEG": 1, "A-": 1,
      "B_POS": 2, "B+": 2,
      "B_NEG": 3, "B-": 3,
      "AB_POS": 4, "AB+": 4,
      "AB_NEG": 5, "AB-": 5,
      "O_POS": 6, "O+": 6,
      "O_NEG": 7, "O-": 7
    };

    const bloodTypeNumericValue = bloodTypeMapping[selectedBloodType.toUpperCase()];
    if (bloodTypeNumericValue === undefined) {
      displayMessage("Invalid blood type selected. Please choose from A+, A-, B+, B-, AB+, AB-, O+, O-.");
      return;
    }

    let registrationMethod;
    if (userType === "Donor") {
      registrationMethod = bloodBankContract.methods.registerAsDonor;
    } else if (userType === "Patient") {
      registrationMethod = bloodBankContract.methods.registerAsPatient;
    } else {
      displayMessage("Invalid user type selected.");
      return;
    }

    const defaultAccount = await web3.eth.getAccounts().then((accounts) => accounts[0]);

    const transaction = await registrationMethod(userName, bloodTypeNumericValue).send({ from: defaultAccount });

    console.log("Transaction Hash:", transaction.transactionHash);
    console.log("Gas Used:", transaction.gasUsed);
    if (transaction.status) {
      displayMessage(`${userType} registered successfully!`);
      if (userType === "Donor") {
        redirectTo("donor_login.html");
      } else if (userType === "Patient") {
        redirectTo("patient_login.html");
      }
    } else {
      displayMessage("Transaction failed. Please check the transaction status.");
    }
  } catch (error) {
    console.error("Error registering user:", error.message);
    if (error.message.includes("insufficient funds")) {
      displayMessage("Insufficient funds. Please make sure your account has enough ETH.");
    } else if (error.message.includes("gas too low")) {
      displayMessage("Gas limit too low. Please increase the gas limit.");
    } else {
      displayMessage("An unexpected error occurred. Please check the console for more details.");
    }
  }
}

// Function to handle granting user permission by admin
async function grantUserPermission() {
  try {
    const { registeredDonors, registeredPatients } =
      await bloodBankContract.methods.getRegisteredUsers().call();

    // UPDATED: bloodTypeMapReverse to include Rh factors
    const bloodTypeMapReverse = {
      0: 'A+', 1: 'A-',
      2: 'B+', 3: 'B-',
      4: 'AB+', 5: 'AB-',
      6: 'O+', 7: 'O-'
    };

    const donorsDetailsList = document.getElementById("donorsDetailsList");
    if (donorsDetailsList) {
      donorsDetailsList.innerHTML = "";
      if (registeredDonors.length === 0) {
          const listItem = document.createElement("li");
          listItem.textContent = "No registered donors.";
          donorsDetailsList.appendChild(listItem);
      } else {
          for (const donorAddress of registeredDonors) {
            const donorDetails = await bloodBankContract.methods
              .donors(donorAddress)
              .call();
            const listItem = document.createElement("li");
            listItem.textContent = `Donor at ${donorAddress}: Name - ${donorDetails.name}, Blood Type - ${bloodTypeMapReverse[donorDetails.bloodType]}`;
            donorsDetailsList.appendChild(listItem);
          }
      }
    }


    const patientsDetailsList = document.getElementById("patientsDetailsList");
    if (patientsDetailsList) {
      patientsDetailsList.innerHTML = "";
      if (registeredPatients.length === 0) {
          const listItem = document.createElement("li");
          listItem.textContent = "No registered patients.";
          patientsDetailsList.appendChild(listItem);
      } else {
          for (const patientAddress of registeredPatients) {
            const patientDetails = await bloodBankContract.methods
              .patients(patientAddress)
              .call();
            const listItem = document.createElement("li");
            listItem.textContent = `Patient at ${patientAddress}: Name - ${patientDetails.name}, Blood Type - ${bloodTypeMapReverse[patientDetails.bloodType]}`;
            patientsDetailsList.appendChild(listItem);
          }
      }
    }
  } catch (error) {
    console.error("Error during granting user permission:", error.message);
    displayMessage("Error granting user permission: " + error.message);
  }
}

// Function to handle donor login
async function donorLogin() {
  try {
    const donorAddress = document.getElementById("donorAddress").value;
    const isDonorAllowed = await bloodBankContract.methods
      .isDonorAllowed(donorAddress)
      .call();

    if (isDonorAllowed) {
      displayMessage("Donor Login Successful");
      redirectTo("donor_dashboard.html");
    } else {
      displayMessage("Donor Login Permission Denied. Please contact the admin.");
    }
  }  catch (error) {
    console.error("Error during donor login:", error.message);
    displayMessage("Error during donor login: " + error.message);
  }
}

// Function to handle patient login
async function patientLogin() {
  try {
    const patientAddress = document.getElementById("patientAddress").value;
    const isPatientAllowed = await bloodBankContract.methods
      .isPatientAllowed(patientAddress)
      .call();

    if (isPatientAllowed) {
      displayMessage("Patient Login Successful");
      redirectTo("patient_dashboard.html");
    } else {
      displayMessage("Patient Login Permission Denied. Please contact the admin.");
    }
  } catch (error) {
    console.error("Error during patient login:", error.message);
    displayMessage("Error during patient login: " + error.message);
  }
}

// Function to handle adding a hospital
async function addHospital() {
  try {
    displayPrompt("Enter hospital name:", async (hospitalName) => {
      if (!hospitalName) {
        displayMessage("Hospital name cannot be empty.");
        return;
      }
      displayPrompt("Enter hospital location (address):", async (hospitalLocation) => {
        if (!hospitalLocation) {
          displayMessage("Hospital location cannot be empty.");
          return;
        }
        const accounts = await web3.eth.getAccounts();
        const currentUserAddress = accounts[0];

        await bloodBankContract.methods
          .addHospital(hospitalLocation, hospitalName)
          .send({ from: currentUserAddress });

        displayMessage("Hospital Added Successfully");
      });
    });

  } catch (error) {
    console.error("Error during adding hospital:", error.message);
    displayMessage("Error adding hospital: " + error.message);
  }
}

// Function to get the current user's Ethereum address using web3.js
async function getCurrentUserAddress() {
  if (window.ethereum) {
    try {
      const accounts = await window.ethereum.request({ method: 'eth_accounts' });
      return accounts[0] || null;
    } catch (error) {
      console.error("Error getting accounts:", error.message);
      return null;
    }
  } else {
    console.error("Web3 provider not found");
    return null;
  }
}

async function donateBlood() {
  try {
    const donorAddress = await getCurrentUserAddress();
    if (!donorAddress) {
      displayMessage("Please connect your MetaMask wallet and ensure you are logged in as a donor.");
      return;
    }

    displayPrompt("Enter the blood type (e.g., A+, A-, B+, B-, etc.):", async (bloodTypeInput) => {
      // UPDATED: bloodTypeMapping to include Rh factors
      const bloodTypeMap = {
        "A_POS": 0, "A+": 0,
        "A_NEG": 1, "A-": 1,
        "B_POS": 2, "B+": 2,
        "B_NEG": 3, "B-": 3,
        "AB_POS": 4, "AB+": 4,
        "AB_NEG": 5, "AB-": 5,
        "O_POS": 6, "O+": 6,
        "O_NEG": 7, "O-": 7
      };
      const bloodType = bloodTypeMap[bloodTypeInput.toUpperCase()];
      if (bloodType === undefined) {
        displayMessage("Invalid blood type entered. Please use formats like A+, A-, B+, B-, etc.");
        return;
      }

      displayPrompt("Enter the amount of blood to donate:", async (donationAmount) => {
        const amount = parseInt(donationAmount);
        if (isNaN(amount) || amount <= 0) {
          displayMessage("Invalid donation amount.");
          return;
        }

        try {
          // Check if the donor is registered and allowed before attempting donation
          const donorDetails = await bloodBankContract.methods.donors(donorAddress).call();
          const isDonorAllowed = await bloodBankContract.methods.isDonorAllowed(donorAddress).call();

          if (!donorDetails.isRegistered) {
            displayMessage("You are not registered as a donor. Please register first.");
            return;
          }
        

          await bloodBankContract.methods
            .donateBlood(bloodType, amount)
            .send({ from: donorAddress });

          displayMessage("Blood Donation Successful");
          await displayDonorInfo(); // Re-display donor info to update the donation details list
        } catch (error) {
          console.error("Error during blood donation:", error.message);
          let errorMessage = "Error during blood donation: Internal JSON-RPC error.";
          if (error.message.includes("User denied transaction signature")) {
            errorMessage = "Blood donation cancelled by user in MetaMask.";
          } else if (error.message.includes("Donor not registered")) {
            errorMessage = "Error: Donor not registered. Please register as a donor.";
          } else if (error.message.includes("Donor already has permission")) {
            errorMessage = "Error: Donor already has permission. Please check admin dashboard.";
          } else if (error.message.includes("revert")) {
            // Attempt to parse the revert reason if available
            const revertReasonMatch = error.message.match(/revert: (.*)/);
            if (revertReasonMatch && revertReasonMatch[1]) {
                errorMessage = `Error during blood donation: ${revertReasonMatch[1]}.`;
            } else {
                errorMessage = "Error during blood donation: Transaction reverted by smart contract.";
            }
          }
          displayMessage(errorMessage);
        }
      });
    });

  } catch (error) {
    console.error("Error during blood donation:", error.message);
    displayMessage("Error during blood donation: " + error.message);
  }
}

// Function to display donor-specific information on the donor dashboard
async function displayDonorInfo() {
  try {
    const donorAddress = await getCurrentUserAddress();
    const donorInfoElement = document.getElementById("donorInfo");
    const donationDetailsList = document.getElementById("donationDetailsList");

    if (!donorAddress) {
      if (donorInfoElement) {
        donorInfoElement.textContent = "Please connect your MetaMask wallet.";
      }
      if (donationDetailsList) {
        donationDetailsList.innerHTML = "<li>No donation history to display. Please connect your MetaMask wallet.</li>";
      }
      return;
    }

    // Fetch donor details
    const donorDetails = await bloodBankContract.methods.donors(donorAddress).call();
    const bloodTypeMapReverse = {
        0: 'A+', 1: 'A-',
        2: 'B+', 3: 'B-',
        4: 'AB+', 5: 'AB-',
        6: 'O+', 7: 'O-'
    };

    if (donorInfoElement) {
      if (donorDetails.isRegistered) {
        donorInfoElement.textContent = `Name: ${donorDetails.name}, Blood Type: ${bloodTypeMapReverse[donorDetails.bloodType]}`;
      } else {
        donorInfoElement.textContent = "You are not registered as a donor.";
      }
    }

    // Fetch and display donor's total donated blood by type
    if (donationDetailsList) {
      donationDetailsList.innerHTML = "";
      let hasDonations = false;
      for (let i = 0; i < 8; i++) { // Loop through all 8 blood types
        const donatedAmount = await bloodBankContract.methods.donorBalances(donorAddress, i).call();
        if (donatedAmount > 0) {
          hasDonations = true;
          const listItem = document.createElement("li");
          listItem.textContent = `Donated Blood Type ${bloodTypeMapReverse[i]}: ${donatedAmount} units`;
          donationDetailsList.appendChild(listItem);
        }
      }
      if (!hasDonations) {
        const listItem = document.createElement("li");
        listItem.textContent = "No blood donations recorded yet.";
        donationDetailsList.appendChild(listItem);
      }
    }

  } catch (error) {
    console.error("Error displaying donor info:", error.message);
    displayMessage("Error displaying donor information: " + error.message);
  }
}


// Function to request blood
async function requestBlood() {
  try {
    const patientAddress = await getCurrentUserAddress();

    if (!patientAddress) {
      displayMessage("Patient address not available. Please connect MetaMask.");
      return;
    }

    displayPrompt("Enter blood type (e.g., A+, A-, B+, B-, etc.):", (bloodTypeString) => {
      // UPDATED: bloodTypeMapping to include Rh factors
      const bloodType = mapBloodType(bloodTypeString.toUpperCase());
      if (bloodType === undefined) {
        displayMessage("Invalid blood type entered. Please use formats like A+, A-, B+, B-, etc.");
        return;
      }

      displayPrompt("Enter the amount of blood requested:", async (amountString) => {
        const amount = parseInt(amountString);
        if (isNaN(amount) || amount <= 0) {
          displayMessage("Invalid amount entered.");
          return;
        }

        try {
          // Check if the patient is registered and allowed before requesting
          const patientDetails = await bloodBankContract.methods.patients(patientAddress).call();
          const isPatientAllowed = await bloodBankContract.methods.isPatientAllowed(patientAddress).call();

          if (!patientDetails.isRegistered) {
            displayMessage("You are not registered as a patient. Please register first.");
            return;
          }
          

          await bloodBankContract.methods
            .requestBlood(bloodType, amount)
            .send({ from: patientAddress });

          displayMessage("Blood Request Sent");
          await displayPatientPendingRequests(); // Update patient's pending requests
        } catch (error) {
          console.error("Error during blood request:", error.message);
          let errorMessage = "Error during blood request: Internal JSON-RPC error.";
          if (error.message.includes("User denied transaction signature")) {
            errorMessage = "Blood request cancelled by user in MetaMask.";
          } else if (error.message.includes("You need to register as a patient first")) {
            errorMessage = "Error: You need to register as a patient first.";
          } else if (error.message.includes("revert")) {
            const revertReasonMatch = error.message.match(/revert: (.*)/);
            if (revertReasonMatch && revertReasonMatch[1]) {
                errorMessage = `Error during blood request: ${revertReasonMatch[1]}.`;
            } else {
                errorMessage = "Error during blood request: Transaction reverted by smart contract.";
            }
          }
          displayMessage(errorMessage);
        }
      });
    });
  } catch (error) {
    console.error("Error during blood request:", error.message);
    displayMessage("An unexpected error occurred during blood request: " + error.message);
  }
}


// Function to display blood donation requests on the admin dashboard
async function displayBloodRequests(targetElementId) {
  try {
    const bloodRequestsList = document.getElementById(targetElementId);

    if (!bloodRequestsList) {
      console.error(`Element with id '${targetElementId}' not found.`);
      return;
    }

    bloodRequestsList.innerHTML = "";

    const { registeredPatients } = await bloodBankContract.methods
      .getRegisteredUsers()
      .call();

    // UPDATED: bloodTypeMapReverse to include Rh factors
    const bloodTypeMapReverse = {
      0: 'A+', 1: 'A-',
      2: 'B+', 3: 'B-',
      4: 'AB+', 5: 'AB-',
      6: 'O+', 7: 'O-'
    };

    if (registeredPatients.length === 0) {
      const listItem = document.createElement("li");
      listItem.textContent = "No blood requests found from registered patients.";
      bloodRequestsList.appendChild(listItem);
      return;
    }

    let foundRequests = false;
    // UPDATED: Loop through all 8 blood types
    for (let i = 0; i < 8; i++) {
        for (const patientAddress of registeredPatients) {
            const requests = await bloodBankContract.methods
            .getPatientRequests(patientAddress, i) // Use 'i' for bloodType
            .call();

            for (const request of requests) {
            if (!request.isResponded) {
                foundRequests = true;
                const listItem = document.createElement("li");
                listItem.textContent = `Blood request from Patient: ${patientAddress.substring(0, 6)}... Blood Type: ${bloodTypeMapReverse[request.bloodType]}, Amount: ${request.amount} units`;
                bloodRequestsList.appendChild(listItem);
            }
            }
        }
    }

    if (!foundRequests) {
        const listItem = document.createElement("li");
        listItem.textContent = "No pending blood requests.";
        bloodRequestsList.appendChild(listItem);
    }

  } catch (error) {
    console.error(
      "Error during displaying blood donation requests:",
      error.message
    );
    displayMessage("Error displaying blood requests: " + error.message);
  }
}

function mapBloodType(bloodTypeString) {
  // UPDATED: bloodTypeMap to include Rh factors and handle various input formats
  const bloodTypeMap = {
    "A_POS": 0, "A+": 0,
    "A_NEG": 1, "A-": 1,
    "B_POS": 2, "B+": 2,
    "B_NEG": 3, "B-": 3,
    "AB_POS": 4, "AB+": 4,
    "AB_NEG": 5, "AB-": 5,
    "O_POS": 6, "O+": 6,
    "O_NEG": 7, "O-": 7
  };
  // Normalize input to uppercase and remove spaces/underscores for flexible matching
  const normalizedInput = bloodTypeString.toUpperCase().replace(/[\s_]/g, '');
  return bloodTypeMap[normalizedInput];
}

// Function to display the response on the patient dashboard
async function displayResponse(patientAddress, response) { // Made async as getCurrentUserAddress is async
  const patientDashboard = document.getElementById("patientDashboard");
  if (patientDashboard) {
    const responseMessage = response ? "approved" : "rejected";
    const listItem = document.createElement("li");
    listItem.textContent = `Your blood donation request has been ${responseMessage}.`;
    patientDashboard.appendChild(listItem);
  } else {
    console.warn("Element with ID 'patientDashboard' not found. Response not displayed.");
  }
}

async function respondToRequest() {
  try {
    const userAddress = await getCurrentUserAddress();

    if (!userAddress) {
      displayMessage("Invalid user address. Please make sure MetaMask is connected.");
      return;
    }

    displayPrompt("Enter patient address:", (patientAddress) => {
      if (!web3.utils.isAddress(patientAddress)) {
        displayMessage("Invalid patient address. Please try again.");
        return;
      }

      displayPrompt("Enter blood type (e.g., A+, A-, B+, B-, etc.):", (bloodTypeString) => {
        // UPDATED: bloodTypeMap to include Rh factors
        const bloodType = mapBloodType(bloodTypeString.toUpperCase());
        if (bloodType === undefined) {
          displayMessage("Invalid blood type entered. Please use formats like A+, A-, B+, B-, etc.");
          return;
        }

        displayConfirm("Do you want to approve the blood donation request?", async (responseConfirm) => {
          try {
            await bloodBankContract.methods
              .respondToRequest(patientAddress, bloodType, responseConfirm)
              .send({ from: userAddress });

            displayMessage("Your response has been sent.");
            // Re-display blood requests on admin dashboard after responding
            if (window.location.pathname.includes("admin_dashboard.html")) {
                await displayBloodRequests("bloodRequestsListAdmin");
            }
          } catch (error) {
            console.error("Error during responding to blood donation requests:", error.message);
            let errorMessage = "Error responding to request. Please check console for more details.";
            if (error.message.includes("revert")) {
                errorMessage = "Transaction reverted by smart contract. Ensure patient is registered and has a pending request for the selected blood type.";
            } else if (error.message.includes("User denied transaction signature")) {
                errorMessage = "Transaction denied by user in MetaMask.";
            }
            displayMessage(errorMessage);
          }
        });
      });
    });

  } catch (error) {
    console.error(
      "Error during responding to blood donation requests:",
      error.message
    );
    displayMessage("An unexpected error occurred during responding to request: " + error.message);
  }
}

async function displayPatientResponses() {
  try {
    const currentPatientAddress = await getCurrentUserAddress();
    if (!currentPatientAddress) {
      const patientResponsesList = document.getElementById("patientResponsesList");
      if (patientResponsesList) {
        patientResponsesList.innerHTML = "<li>Please log in as a patient to view responses.</li>";
      }
      return;
    }

    const responses = await bloodBankContract.methods
      .getPatientResponses(currentPatientAddress)
      .call();

    const patientResponsesList = document.getElementById("patientResponsesList");

    if (patientResponsesList) {
      patientResponsesList.innerHTML = "";

      if (responses.length === 0) {
        const listItem = document.createElement("li");
        listItem.textContent = "No responses to your blood requests yet.";
        patientResponsesList.appendChild(listItem);
        return;
      }

      // UPDATED: bloodTypeMapReverse to include Rh factors
      const bloodTypeMapReverse = {
        0: 'A+', 1: 'A-',
        2: 'B+', 3: 'B-',
        4: 'AB+', 5: 'AB-',
        6: 'O+', 7: 'O-'
      };
      responses.forEach((response) => {
        const responseMessage = response.response ? "approved" : "rejected";
        const listItem = document.createElement("li");
        listItem.textContent = `Your request for Blood Type ${bloodTypeMapReverse[response.bloodType]} (${response.amount} units) has been ${responseMessage}.`;
        patientResponsesList.appendChild(listItem);
      });
    } else {
      console.warn("Element with ID 'patientResponsesList' not found. Patient responses not displayed.");
    }

  } catch (error) {
    console.error("Error during displaying patient responses:", error.message);
    displayMessage("Error displaying your responses: " + error.message);
  }
}


// Functions for custom prompt and confirm dialogs (instead of browser's default prompt/confirm)
function displayPrompt(message, callback) {
    const promptBox = document.createElement('div');
    promptBox.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background-color: #f0f0f0;
        border: 1px solid #ccc;
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        z-index: 1000;
        font-family: Arial, sans-serif;
        color: #333;
        text-align: center;
    `;
    promptBox.innerHTML = `
        <p style="color: #333;">${message}</p>
        <input type="text" id="promptInput" style="
            width: 80%;
            padding: 8px;
            margin-bottom: 10px;
            border: 1px solid #ccc;
            border-radius: 4px;
            color: #333;
        "/>
        <button id="promptOk" style="
            background-color: #3498db;
            color: white;
            border: none;
            padding: 8px 16px;
            margin-top: 10px;
            border-radius: 4px;
            cursor: pointer;
        ">OK</button>
    `;
    document.body.appendChild(promptBox);

    const promptInput = document.getElementById('promptInput');
    const promptOk = document.getElementById('promptOk');

    promptOk.onclick = () => {
        promptBox.remove();
        callback(promptInput.value);
    };

    promptInput.onkeypress = (e) => {
        if (e.key === 'Enter') {
            promptBox.remove();
            callback(promptInput.value);
        }
    };
    promptInput.focus();
}

// Function to display total blood inventory and donations
async function displayBloodInventory() {
    try {
        const totalDonatedElement = document.getElementById("totalBloodDonated");
        const bloodInventoryList = document.getElementById("bloodInventoryList");
        
        // UPDATED: bloodTypeMapReverse to include Rh factors
        const bloodTypeMapReverse = {
            0: 'A+', 1: 'A-',
            2: 'B+', 3: 'B-',
            4: 'AB+', 5: 'AB-',
            6: 'O+', 7: 'O-'
        };

        const isDonatedBloodPage = window.location.pathname.includes("donated_Blood.html");
        const isAdminDashboardPage = window.location.pathname.includes("admin_dashboard.html");

        if (!totalDonatedElement || !bloodInventoryList) {
            if (isDonatedBloodPage || isAdminDashboardPage) {
                console.error("Elements for blood inventory not found on the current page.");
            }
            return;
        }

        const totalBlood = await bloodBankContract.methods.getTotalBloodDonated().call();
        totalDonatedElement.textContent = `Total Blood Donated: ${totalBlood} units`;

        bloodInventoryList.innerHTML = "";
        let hasInventory = false;
        // UPDATED: Loop through all 8 blood types
        for (let i = 0; i < 8; i++) {
            const bloodTypeAmount = await bloodBankContract.methods.getBloodInventory(i).call();
            if (bloodTypeAmount > 0) {
                hasInventory = true;
                const listItem = document.createElement("li");
                listItem.textContent = `Blood Type ${bloodTypeMapReverse[i]}: ${bloodTypeAmount} units`;
                bloodInventoryList.appendChild(listItem);
            }
        }
        if (!hasInventory) {
            const listItem = document.createElement("li");
            listItem.textContent = "No blood currently in inventory.";
            bloodInventoryList.appendChild(listItem);
        }

    } catch (error) {
        console.error("Error fetching blood inventory:", error.message);
        displayMessage("Error fetching blood inventory: " + error.message);
    }
}

// Function to display pending blood requests for the CURRENT patient on their dashboard
async function displayPatientPendingRequests() {
    try {
        const currentPatientAddress = await getCurrentUserAddress();
        const bloodRequestsListPatient = document.getElementById("bloodRequestsListPatient");

        if (!bloodRequestsListPatient) {
            console.error("Element with ID 'bloodRequestsListPatient' not found.");
            return;
        }

        bloodRequestsListPatient.innerHTML = "";

        if (!currentPatientAddress) {
            bloodRequestsListPatient.innerHTML = "<li>Please log in as a patient to view your requests.</li>";
            return;
        }

        // UPDATED: bloodTypeMapReverse to include Rh factors
        const bloodTypeMapReverse = {
            0: 'A+', 1: 'A-',
            2: 'B+', 3: 'B-',
            4: 'AB+', 5: 'AB-',
            6: 'O+', 7: 'O-'
        };
        let foundRequests = false;

        // UPDATED: Loop through all 8 blood types
        for (let i = 0; i < 8; i++) {
            const requests = await bloodBankContract.methods
                .getPatientRequests(currentPatientAddress, i)
                .call();

            for (const request of requests) {
                if (!request.isResponded) { // Only show pending requests
                    foundRequests = true;
                    const listItem = document.createElement("li");
                    listItem.textContent = `Requested: Blood Type ${bloodTypeMapReverse[request.bloodType]}, Amount: ${request.amount} units (Pending)`;
                    bloodRequestsListPatient.appendChild(listItem);
                }
            }
        }

        if (!foundRequests) {
            const listItem = document.createElement("li");
            listItem.textContent = "No pending blood requests.";
            bloodRequestsListPatient.appendChild(listItem);
        }

    } catch (error) {
        console.error("Error fetching patient's pending blood requests:", error.message);
        displayMessage("Error displaying your pending requests: " + error.message);
    }
}


// Global initialization function called once the window is fully loaded
window.onload = async () => {
    // Initialize common dashboard elements
    if (window.location.pathname.includes("admin_dashboard.html")) {
        await grantUserPermission();
        await displayBloodInventory();
        await displayBloodRequests("bloodRequestsListAdmin");
    }
    else if (window.location.pathname.includes("patient_dashboard.html")) {
        await displayPatientPendingRequests();
        await displayPatientResponses();
    }
    else if (window.location.pathname.includes("donor_dashboard.html")) {
        await displayDonorInfo(); // Call displayDonorInfo for the donor dashboard
    }
    else if (window.location.pathname.toLowerCase().includes("donated_blood.html")) {
        await displayBloodInventory();
    }
};
