// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @title SELVA Traceability - Copaiba oil-resin traceability MVP
/// @author SELVA
/// @notice MVP smart contract implementing registration, producer promotion,
///         product (lot) registration and ownership transfer, plus basic history.
/// @dev Simple, well commented implementation following the supplementary material.
contract SELVATraceability {

    // ---------- Ownership / Roles ----------
    address public owner; // contract owner (deployer) - has administrative privileges

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only contract owner");
        _;
    }

    modifier onlyRegistered(bytes32 userHash) {
        require(users[userHash].createdAt != 0, "User not registered");
        _;
    }

    // ---------- Events (for off-chain forensic / UI) ----------
    event UserRegistered(bytes32 indexed userHash, address userAddress);
    event ProducerCreated(address indexed producerAddress);
    event ProductAdded(string indexed lotId, address indexed producer, bytes32 documentHash);
    event OwnershipTransferred(string indexed lotId, address indexed from, address indexed to);

    // ---------- User model ----------
    struct User {
        string name;
        string cpf;
        address account; // Ethereum address that registered
        uint256 createdAt;
    }

    // maps a user-hash -> User
    mapping(bytes32 => User) private users;
    bytes32[] private userIndex;

    // maps address -> userHash (if registered)
    mapping(address => bytes32) private addressToUserHash;

    // ---------- Producer role ----------
    mapping(address => bool) public isProducer;

    // ---------- Product / Lot model ----------
    struct Product {
        string lotId;          // unique identifier (ex: "ABC123")
        uint256 volume;        // liters (or base units)
        string origin;         // origin text (species + location)
        address producer;      // original extractor (immutable)
        address currentOwner;  // current owner
        bytes32 documentHash;  // SHA-256 hash of license/document
        uint256 createdAt;     // block.timestamp of registration
        bool active;           // whether this lot is active (registered)
    }

    // mapping lotId -> Product
    mapping(string => Product) private products;

    // keep index of lotIds for listing
    string[] private lotIndex;

    // ---------- Product history entries ----------
    struct Trace {
        address actor;      // who executed action
        string action;      // "CREATED" | "TRANSFERRED" | "OTHER"
        bytes32 docHash;    // optional doc hash associated with the action
        address from;       // previous owner (if transfer)
        address to;         // new owner (if transfer)
        uint256 timestamp;  // block timestamp
    }

    // mapping lotId => array of trace events
    mapping(string => Trace[]) private history;

    // ---------- Read helpers (public) ----------
    /// @notice Get product details by lotId
    function getProduct(string memory _lotId) public view returns (
        string memory lotId,
        uint256 volume,
        string memory origin,
        address producer,
        address currentOwner,
        bytes32 documentHash,
        uint256 createdAt,
        bool active
    ) {
        Product memory p = products[_lotId];
        require(p.createdAt != 0, "Product not found");
        return (p.lotId, p.volume, p.origin, p.producer, p.currentOwner, p.documentHash, p.createdAt, p.active);
    }

    /// @notice Get product history arrays for a lot
    /// @dev Returns parallel arrays for easier ABI decoding off-chain
    function getProductHistory(string memory _lotId) public view returns (
        address[] memory actors,
        string[] memory actions,
        bytes32[] memory docHashes,
        address[] memory froms,
        address[] memory tos,
        uint256[] memory timestamps
    ) {
        Trace[] memory traces = history[_lotId];
        uint256 len = traces.length;

        actors = new address[](len);
        actions = new string[](len);
        docHashes = new bytes32[](len);
        froms = new address[](len);
        tos = new address[](len);
        timestamps = new uint256[](len);

        for (uint256 i = 0; i < len; i++) {
            actors[i] = traces[i].actor;
            actions[i] = traces[i].action;
            docHashes[i] = traces[i].docHash;
            froms[i] = traces[i].from;
            tos[i] = traces[i].to;
            timestamps[i] = traces[i].timestamp;
        }
    }

    /// @notice List all registered lotIds
    function listAllLotIds() public view returns (string[] memory) {
        return lotIndex;
    }

    /// @notice Check whether address is a registered user
    function isUserRegistered(address _addr) public view returns (bool) {
        return addressToUserHash[_addr] != bytes32(0);
    }

    // ---------- Core functions (as specified in the material) ----------

    /// @notice Register a user and return a userHash (bytes32)
    /// @dev userHash is computed as keccak256(name + cpf + block.timestamp + msg.sender)
    function registerUser(string memory _name, string memory _cpf) public returns (bytes32) {
        require(bytes(_name).length > 0 && bytes(_cpf).length > 0, "Invalid input");
        require(addressToUserHash[msg.sender] == bytes32(0), "Address already registered");

        bytes32 userHash = keccak256(abi.encodePacked(_name, _cpf, block.timestamp, msg.sender));

        users[userHash] = User({
            name: _name,
            cpf: _cpf,
            account: msg.sender,
            createdAt: block.timestamp
        });

        addressToUserHash[msg.sender] = userHash;

        // Store for enumeration
        userIndex.push(userHash);

        emit UserRegistered(userHash, msg.sender);
        return userHash;
    }

    /// @notice Returns all registered user hashes
    function listAllUsers() public view returns (bytes32[] memory) {
        return userIndex;
    }

    /// @notice Promote an existing registered user (address) to producer role
    /// @dev only contract owner can call this (administrative action)
    function makeProducer(address _userAddress) external onlyOwner {
        require(_userAddress != address(0), "Zero address");
        require(addressToUserHash[_userAddress] != bytes32(0), "User not registered");
        require(!isProducer[_userAddress], "Already producer");

        isProducer[_userAddress] = true;

        emit ProducerCreated(_userAddress);
    }

    /// @notice Register a new product (lot) on-chain
    /// @dev Only producers may call this. Prevent duplicate lot registrations.
    function addProduct(
        string memory _lotId,
        uint256 _volume,
        string memory _origin,
        bytes32 _docHash
    ) external {
        require(isProducer[msg.sender], "Only producers can add products");
        require(bytes(_lotId).length > 0, "Missing lotId");
        require(_volume > 0, "Volume must be > 0");
        Product storage p = products[_lotId];
        require(p.createdAt == 0 || p.active == false, "Product with this lot ID already exists");

        products[_lotId] = Product({
            lotId: _lotId,
            volume: _volume,
            origin: _origin,
            producer: msg.sender,
            currentOwner: msg.sender,
            documentHash: _docHash,
            createdAt: block.timestamp,
            active: true
        });

        lotIndex.push(_lotId);

        // add initial trace entry
        history[_lotId].push(Trace({
            actor: msg.sender,
            action: "CREATED",
            docHash: _docHash,
            from: address(0),
            to: msg.sender,
            timestamp: block.timestamp
        }));

        emit ProductAdded(_lotId, msg.sender, _docHash);
    }

    /// @notice Transfer ownership of a lot to another address
    /// @dev Only the current owner of the lot can transfer it.
    function transferProduct(string memory _lotId, address _newOwner) external {
        require(_newOwner != address(0), "Zero address");
        Product storage p = products[_lotId];
        require(p.createdAt != 0 && p.active == true, "Product not found or inactive");
        require(p.currentOwner == msg.sender, "Only current owner can transfer this product");

        address previousOwner = p.currentOwner;
        p.currentOwner = _newOwner;

        // push trace
        history[_lotId].push(Trace({
            actor: msg.sender,
            action: "TRANSFERRED",
            docHash: p.documentHash,
            from: previousOwner,
            to: _newOwner,
            timestamp: block.timestamp
        }));

        emit OwnershipTransferred(_lotId, previousOwner, _newOwner);
    }

    // ---------- Administrative helpers (optional) ----------

    /// @notice Deactivate a product (logical deletion) - only owner (admin)
    /// @dev Useful for administrative corrections or test cleanup
    function deactivateProduct(string memory _lotId) external onlyOwner {
        Product storage p = products[_lotId];
        require(p.createdAt != 0, "Product not found");
        p.active = false;

        // admin trace
        history[_lotId].push(Trace({
            actor: msg.sender,
            action: "DEACTIVATED",
            docHash: p.documentHash,
            from: p.currentOwner,
            to: p.currentOwner,
            timestamp: block.timestamp
        }));
    }

    /// @notice Convenience: get user by hash
    function getUser(bytes32 _userHash) public view returns (string memory name, string memory cpf, address account, uint256 createdAt) {
        User memory u = users[_userHash];
        require(u.createdAt != 0, "User not found");
        return (u.name, u.cpf, u.account, u.createdAt);
    }

    /// @notice Get userHash for an address (0 if not registered)
    function userHashOf(address _addr) public view returns (bytes32) {
        return addressToUserHash[_addr];
    }
}
