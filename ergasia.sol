
// SPDX-License-Identifier: MIT 
// Δηλώνει την άδεια χρήσης του κώδικα. 
pragma solidity ^0.8.34; //Δηλώνει ποια έκδοση Solidity

contract ergasia {

    //
    // admin


    
    //
    address public admin;

    constructor() {
        admin = msg.sender;
    }


    //
    // Structures
    //
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
        uint256 role; // 1: admin, 2: issuer 3: holder 4: revokation officer 5: Auditor
        bool active;
    }


    // storage
    mapping(uint256 => Certificate) public certificates; //λέει οτι το κλειδι πρέπει να ειναι τυπου uint256 και το item τύπου certificate
    mapping(address => User) public users; 

    mapping(address => uint256[]) public issuerCertificates;
    mapping(address => uint256[]) public holderCertificates;
    mapping(string => uint256) public certificateByHash;

    
    address[] public allUsers;
    uint256[] public allCertificates;


    uint256 private nextCertificateId = 1;


    //
    // Functions
    //
   // memory: προσωρινά δεδομένα για όσο εκτελείται η συνάρτηση | storage: μόνιμα δεδομένα στο blockchain
   // _ εναι για να μας βοηθά να ξεχωρίζουμε οτι ειναι απο παράμετρο
   //Το memory μπορεί να χρησιμοποιηθεί με τύπους όπως: string array struct mapping. Το uint256 είναι απλός value type

    //εγγραφή χρηστών με καθορισμό ρόλου, μόνο από διαχειριστή
   function registerUser(address _userAddress, string memory _name, uint256 _role) public onlyAdmin {
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


    //έκδοση νέου πιστοποιητικού, μόνο από εξουσιοδοτημένο φορέα έκδοσης
    function issueCertificate(string memory _certificateType, address _holder, string memory _fileHash, uint256 _issueDate, uint256 _expiryDate) public onlyIssuer{
        
        uint256 _certificateId = nextCertificateId;

        certificates[_certificateId] = Certificate( _certificateId, _certificateType, msg.sender, _holder, _fileHash, _issueDate, _expiryDate, "Valid", false, "" );
        holderCertificates[_holder].push(_certificateId);
        issuerCertificates[msg.sender].push(_certificateId);
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


    // προβολή πιστοποιητικών εκδότη
    function getIssuerCertificates(address _issuer) public onlyIssuer view returns (uint256[] memory) { 
        return issuerCertificates[_issuer]; 
    }

    // προβολή πιστοποιητικών κατόχου
    function getHolderCertificates(address _holder) public onlyHolder view returns (uint256[] memory) { 
        return holderCertificates[_holder]; 
    }


    // o επαλήθευση πιστοποιητικού βάσει certificateId ή fileHash
    function verifyCertificateById(uint256 _certificateId) public onlyAuditor returns (Certificate memory) { 
        emit CertificateVerified(_certificateId);
        return certificates[_certificateId];
    }
    function verifyCertificateByHash(string memory _fileHash) public onlyAuditor returns (Certificate memory) { 
        uint256 certificateId = certificateByHash[_fileHash]; 
        emit CertificateVerified(certificateId);
        return certificates[certificateId]; 
    }

    // ανάκληση πιστοποιητικού, μόνο από εξουσιοδοτημένο ρόλο
    function revokeCertificate(uint256 _certificateId, string memory _reason) public onlyRevocationOfficer{
        require(certificates[_certificateId].issuer == msg.sender, "You did not issue this certificate");
        certificates[_certificateId].revoked = true;
        certificates[_certificateId].status = "Revoked";
        certificates[_certificateId].revocationReason = _reason;
        emit CertificateRevoked(_certificateId, _reason);
    }

    // έλεγχο κατάστασης πιστοποιητικού
    function checkCertificateStatus(uint256 _certificateId) public onlyAuditor returns (string memory) {
        if (block.timestamp > certificates[_certificateId].expiryDate) {
            emit CertificateExpired(_certificateId);
        }
        return certificates[_certificateId].status;
    }

    // προβολή όλων των δεδομένων πιστοποιητικού με view συνάρτηση, ανάλογα με τα δικαιώματα πρόσβασης
    function getCertificate(uint256 _certificateId) public view returns(Certificate memory){
        Certificate memory certificate = certificates[_certificateId];
        require( msg.sender == admin || certificate.issuer == msg.sender ||certificate.holder == msg.sender,"Not authorized");
        return certificate;
    }


    //
    // Modifiers
    //

    //Στο σημείο που βρίσκεται το _, βάλε τον κώδικα της function.
    modifier onlyAdmin() {
    require(msg.sender == admin, "Only admin");
    _;
    }

    modifier onlyIssuer() {
        require(users[msg.sender].role == 2, "Only issuer");
        require(users[msg.sender].active, "Only active users");
        _;
    }


     modifier onlyHolder() {
        require(users[msg.sender].role == 3, "Only holder");
        require(users[msg.sender].active, "Only active users");
        _;
    }

    modifier onlyRevocationOfficer() {
        require( users[msg.sender].role == 4, "Only revocation officer" );
        require(users[msg.sender].active, "Only active users");
        _;
    }

    modifier onlyAuditor() {
        require( users[msg.sender].role == 5, "Only auditor" );
        require(users[msg.sender].active, "Only active users");
        _;
    }

    modifier onlyActiveUser() {
        require( users[msg.sender].active, "User is not active" );
        _;
    }


    /*********/
    // Events
    /*********/
    event UserRegistered(address userAddress, string name, uint256 role);
    event CertificateIssued(uint256 certificateId, address issuer, address holder);
    event CertificateVerified(uint256 certificateId);
    event CertificateRevoked(uint256 certificateId, string reason);
    event CertificateExpired(uint256 certificateId);
}