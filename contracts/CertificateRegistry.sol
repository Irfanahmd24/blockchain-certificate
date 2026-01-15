// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title CertificateRegistry
 * @dev Manages the secure registration and verification of student certificate hashes on the blockchain.
 */
contract CertificateRegistry {
    // Structure to hold certificate data on the blockchain
    struct Certificate {
        address issuer;          // The address that issued the certificate (Admin)
        uint256 timestamp;       // The time of issuance
        bool isValid;            // Always true if registered
        string studentId;        // Off-chain reference to the student's unique ID
    }

    // Mapping: Certificate Hash (bytes32) => Certificate Details (struct)
    mapping(bytes32 => Certificate) public certificates;

    // Event to log when a certificate is successfully issued
    event CertificateIssued(bytes32 indexed certificateHash, address indexed issuer, string studentId);

    // Only the contract owner (the Admin account that deployed the contract) can issue certificates
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // Modifier to restrict access to the contract owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only the contract owner can call this function.");
        _;
    }

    /**
     * @dev Issues a new certificate by storing its hash and student ID on the blockchain.
     * The hash must be generated off-chain from the content of the PDF certificate.
     * @param _certificateHash The SHA-256 hash of the certificate PDF (prefixed with 0x).
     * @param _studentId The unique identifier of the student.
     */
    function issueCertificate(bytes32 _certificateHash, string memory _studentId) public onlyOwner {
        // Ensure this hash has not been issued before
        require(certificates[_certificateHash].issuer == address(0), "Certificate already exists.");

        certificates[_certificateHash] = Certificate({
            issuer: msg.sender,
            timestamp: block.timestamp,
            isValid: true,
            studentId: _studentId
        });

        emit CertificateIssued(_certificateHash, msg.sender, _studentId);
    }

    /**
     * @dev Checks if a certificate hash is registered (i.e., valid) by checking the issuer address.
     * @param _certificateHash The SHA-256 hash to check.
     * @return A boolean indicating validity.
     */
    function verifyCertificate(bytes32 _certificateHash) public view returns (bool) {
        // If the issuer address is not the zero address, the certificate is registered and valid.
        return certificates[_certificateHash].issuer != address(0);
    }

    /**
     * @dev Retrieves all stored details for a specific certificate hash.
     * @param _certificateHash The SHA-256 hash of the certificate.
     * @return issuer The address that issued the certificate.
     * @return timestamp The issuance timestamp.
     * @return isValid The current validity status (always true if registered).
     * @return studentId The off-chain ID of the student.
     */
    function getCertificateDetails(bytes32 _certificateHash) public view returns (
        address issuer,
        uint256 timestamp,
        bool isValid,
        string memory studentId
    ) {
        Certificate storage cert = certificates[_certificateHash];
        return (cert.issuer, cert.timestamp, cert.isValid, cert.studentId);
    }
}