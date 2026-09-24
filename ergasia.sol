
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Ergasia {
    address public immutable admin;
    uint256 private nextCertificateId = 1;

    enum Role {
        None,
        Admin,
        Issuer,
        Holder,
        RevocationOfficer,
        Auditor,
        Verifier
    }

    struct Certificate {
        uint256 certificateId;
        string certificateType;
        address issuer;
        address holder;
        string fileHash;
        uint256 issueDate;
        uint256 expiryDate;
        string status; // Valid, Expired, Revoked
        bool revoked;
        string revocationReason;
    }

    struct User {
        address userAddress;
        string name;
        Role role;
        bool active;
    }

    // Storage
    mapping(uint256 => Certificate) public certificates;
    mapping(address => User) public users;

    mapping(address => uint256[]) public issuerCertificates;
    mapping(address => uint256[]) public holderCertificates;
    mapping(string => uint256) public certificateByHash;

    address[] public allUsers;
    uint256[] public allCertificates;

    // Modifiers
    modifier onlyAdmin() {
        require(
            msg.sender == admin ||
            users[msg.sender].role == Role.Admin,
             "Only admin"
        );
        _;
    }

    modifier onlyIssuer() {
        _checkRole(Role.Issuer);
        _;
    }

    modifier onlyHolder() {
        _checkRole(Role.Holder);
        _;
    }

    modifier onlyRevocationOfficer() {
        _checkRole(Role.RevocationOfficer);
        _;
    }

    modifier onlyAdminOrAuditor {
        require(
            msg.sender == admin ||
            users[msg.sender].role == Role.Admin ||
            users[msg.sender].role == Role.Auditor,
            "Only Admin or Auditor"
        );
        _;
    }

    modifier onlyVerifier() {
        require(
            users[msg.sender].role == Role.Verifier ,
            "Only Verifier"
        );
        require(users[msg.sender].active, "User is not active");
        _;
    }

    function _checkRole(Role role) internal view {
        require(users[msg.sender].role == role, "Invalid role");
        require(users[msg.sender].active, "User is not active");
    }

    // Events
    event UserRegistered(address indexed userAddress, string name, Role role);
    event CertificateIssued(uint256 indexed certificateId, address indexed issuer, address indexed holder);
    event CertificateVerified(uint256 indexed certificateId, string fileHash, address indexed verifier);
    event CertificateRevoked(uint256 indexed certificateId, string reason, address indexed revocationOfficer);
    event CertificateExpired(uint256 certificateId);

    constructor() {
        admin = msg.sender;
        users[msg.sender] = User(msg.sender, "Admin", Role.Admin, true);
        allUsers.push(msg.sender);
        emit UserRegistered(msg.sender, "Admin", Role.Admin);
    }

    function registerUser(
        address userAddress,
        string memory name,
        Role role
    ) public onlyAdmin {
        require(userAddress != address(0), "Invalid address");
        require(users[userAddress].userAddress == address(0), "User already registered");

        users[userAddress] = User(userAddress, name, role, true);
        allUsers.push(userAddress);
        emit UserRegistered(userAddress, name, role);
    }

    function getAllUsers() public view onlyAdminOrAuditor returns (User[] memory) {
        uint256 totalUsers = allUsers.length;
        User[] memory resultList = new User[](totalUsers);

        for (uint256 i = 0; i < totalUsers; i++) {
            resultList[i] = users[allUsers[i]];
        }

        return resultList;
    }

    function issueCertificate(
        string memory certificateType,
        address holder,
        string memory fileHash,
        uint256 issueDate,
        uint256 expiryDate
    ) public onlyIssuer {
        require(holder != address(0), "Invalid holder address");
        require(certificateByHash[fileHash] == 0, "Hash already exists");

        uint256 certificateId = nextCertificateId;

        certificates[certificateId] = Certificate(
            certificateId,
            certificateType,
            msg.sender,
            holder,
            fileHash,
            issueDate,
            expiryDate,
            "Valid",
            false,
            ""
        );

        holderCertificates[holder].push(certificateId);
        issuerCertificates[msg.sender].push(certificateId);
        certificateByHash[fileHash] = certificateId;
        allCertificates.push(certificateId);

        nextCertificateId++;

        emit CertificateIssued(certificateId, msg.sender, holder);
    }

    function getAllCertificates() public view onlyAdminOrAuditor returns (Certificate[] memory) {
        uint256 totalCertificates = allCertificates.length;
        Certificate[] memory resultList = new Certificate[](totalCertificates);

        for (uint256 i = 0; i < totalCertificates; i++) {
            resultList[i] = certificates[allCertificates[i]];
        }

        return resultList;
    }

    function getIssuerCertificates(address issuer) public view onlyIssuer returns (uint256[] memory) {
        return issuerCertificates[issuer];
    }

    function getHolderCertificates(address holder) public view onlyHolder returns (uint256[] memory) {
        return holderCertificates[holder];
    }

    function verifyCertificateById(uint256 certificateId) public onlyVerifier returns (Certificate memory) {
        require(certificates[certificateId].certificateId != 0, "Certificate does not exist");
        require(!certificates[certificateId].revoked, "Certificate has been revoked");
        require(keccak256(bytes(certificates[certificateId].status)) == keccak256(bytes("Expired")), "Certificate has been expired");
        emit CertificateVerified(certificateId, certificates[certificateId].fileHash, msg.sender);
        return certificates[certificateId];
    }

    function verifyCertificateByHash(string memory fileHash) public onlyVerifier returns (Certificate memory) {
        uint256 certificateId = certificateByHash[fileHash];
        require(certificateId != 0, "Certificate not found");
        require(!certificates[certificateId].revoked, "Certificate has been revoked");
        require(keccak256(bytes(certificates[certificateId].status)) == keccak256(bytes("Expired")), "Certificate has been expired");
        emit CertificateVerified(certificateId, fileHash, msg.sender);
        return certificates[certificateId];
    }

    function revokeCertificate(uint256 certificateId, string memory reason) public onlyRevocationOfficer {
        require(certificates[certificateId].certificateId != 0, "Certificate does not exist");
        require(!certificates[certificateId].revoked, "Certificate is already revoked");

        certificates[certificateId].revoked = true;
        certificates[certificateId].status = "Revoked";
        certificates[certificateId].revocationReason = reason;
        
        emit CertificateRevoked(certificateId, reason, msg.sender);
    }

    function checkCertificateStatus(uint256 certificateId) public returns (string memory) {
        Certificate memory cert = certificates[certificateId];
        require(certificates[certificateId].certificateId != 0, "Certificate does not exist");
        require(
            msg.sender == admin ||
            users[msg.sender].role == Role.Admin ||
            cert.issuer == msg.sender ||
            cert.holder == msg.sender ||
            users[msg.sender].role == Role.Auditor,
            "Not authorized"
        );
        
        if (certificates[certificateId].revoked) {
            return "Revoked";
        }

        if (keccak256(bytes(certificates[certificateId].status)) == keccak256(bytes("Expired"))) {
            return "Expired";
        }

        if (certificates[certificateId].expiryDate != 0 && block.timestamp > certificates[certificateId].expiryDate) {
            certificates[certificateId].status = "Expired";

            emit CertificateExpired(certificateId);

            return "Expired";
        }

        return certificates[certificateId].status;
    }

    function getCertificate(uint256 certificateId) public view returns (Certificate memory) {
        Certificate memory cert = certificates[certificateId];
        require(cert.certificateId != 0, "Certificate does not exist");
        require(
            msg.sender == admin ||
            cert.issuer == msg.sender ||
            cert.holder == msg.sender ||
            users[msg.sender].role == Role.Admin ||
            users[msg.sender].role == Role.Auditor ||
            users[msg.sender].role == Role.Verifier ||
            users[msg.sender].role == Role.RevocationOfficer,
            "Not authorized"
        );
        return cert;
    }
}
