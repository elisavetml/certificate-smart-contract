// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ergasia {
    address public admin;
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
        require(msg.sender == admin, "Only admin");
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

    modifier onlyAuditorOrVerifier() {
        require(
            users[msg.sender].role == Role.Auditor || 
            users[msg.sender].role == Role.Verifier || 
            msg.sender == admin,
            "Not authorized as Auditor or Verifier"
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
    event CertificateVerified(uint256 indexed certificateId);
    event CertificateRevoked(uint256 indexed certificateId, string reason);
    event CertificateExpired(uint256 certificateId);

    constructor() {
        admin = msg.sender;
        users[msg.sender] = User(msg.sender, "Admin", Role.Admin, true);
        allUsers.push(msg.sender);
        emit UserRegistered(msg.sender, "Admin", Role.Admin);
    }

    function registerUser(
        address _userAddress,
        string memory _name,
        Role _role
    ) public onlyAdmin {
        require(_userAddress != address(0), "Invalid address");
        require(users[_userAddress].userAddress == address(0), "User already registered");

        users[_userAddress] = User(_userAddress, _name, _role, true);
        allUsers.push(_userAddress);
        emit UserRegistered(_userAddress, _name, _role);
    }

    function getAllUsers() public view onlyAdmin returns (User[] memory) {
        uint256 totalUsers = allUsers.length;
        User[] memory resultList = new User[](totalUsers);

        for (uint256 i = 0; i < totalUsers; i++) {
            resultList[i] = users[allUsers[i]];
        }

        return resultList;
    }

    function issueCertificate(
        string memory _certificateType,
        address _holder,
        string memory _fileHash,
        uint256 _issueDate,
        uint256 _expiryDate
    ) public onlyIssuer {
        require(_holder != address(0), "Invalid holder address");
        require(certificateByHash[_fileHash] == 0, "Hash already exists");

        uint256 _certificateId = nextCertificateId;

        certificates[_certificateId] = Certificate(
            _certificateId,
            _certificateType,
            msg.sender,
            _holder,
            _fileHash,
            _issueDate,
            _expiryDate,
            "Valid",
            false,
            ""
        );

        holderCertificates[_holder].push(_certificateId);
        issuerCertificates[msg.sender].push(_certificateId);
        certificateByHash[_fileHash] = _certificateId;
        allCertificates.push(_certificateId);

        nextCertificateId++;

        emit CertificateIssued(_certificateId, msg.sender, _holder);
    }

    function getAllCertificates() public view onlyAdmin returns (Certificate[] memory) {
        uint256 totalCertificates = allCertificates.length;
        Certificate[] memory resultList = new Certificate[](totalCertificates);

        for (uint256 i = 0; i < totalCertificates; i++) {
            resultList[i] = certificates[allCertificates[i]];
        }

        return resultList;
    }

    function getIssuerCertificates(address _issuer) public view onlyIssuer returns (uint256[] memory) {
        return issuerCertificates[_issuer];
    }

    function getHolderCertificates(address _holder) public view onlyHolder returns (uint256[] memory) {
        return holderCertificates[_holder];
    }

    function verifyCertificateById(uint256 _certificateId) public view onlyAuditorOrVerifier returns (Certificate memory) {
        require(certificates[_certificateId].certificateId != 0, "Certificate does not exist");
        return certificates[_certificateId];
    }

    function verifyCertificateByHash(string memory _fileHash) public view onlyAuditorOrVerifier returns (Certificate memory) {
        uint256 certificateId = certificateByHash[_fileHash];
        require(certificateId != 0, "Certificate not found");
        return certificates[certificateId];
    }

    function revokeCertificate(uint256 _certificateId, string memory _reason) public onlyRevocationOfficer {
        require(certificates[_certificateId].certificateId != 0, "Certificate does not exist");
        require(!certificates[_certificateId].revoked, "Certificate is already revoked");

        certificates[_certificateId].revoked = true;
        certificates[_certificateId].status = "Revoked";
        certificates[_certificateId].revocationReason = _reason;
        
        emit CertificateRevoked(_certificateId, _reason);
    }

    function checkCertificateStatus(uint256 _certificateId) public view returns (string memory) {
        require(certificates[_certificateId].certificateId != 0, "Certificate does not exist");
        
        if (certificates[_certificateId].revoked) {
            return "Revoked";
        }
        if (
            certificates[_certificateId].expiryDate != 0 &&
            block.timestamp > certificates[_certificateId].expiryDate
        ) {
            return "Expired";
        }
        return certificates[_certificateId].status;
    }

    function getCertificate(uint256 _certificateId) public view returns (Certificate memory) {
        Certificate memory cert = certificates[_certificateId];
        require(cert.certificateId != 0, "Certificate does not exist");
        require(
            msg.sender == admin ||
            cert.issuer == msg.sender ||
            cert.holder == msg.sender ||
            users[msg.sender].role == Role.Auditor ||
            users[msg.sender].role == Role.Verifier ||
            users[msg.sender].role == Role.RevocationOfficer,
            "Not authorized"
        );
        return cert;
    }
}
