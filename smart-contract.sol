// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @title SELVA Traceability - Copaiba oil-resin traceability MVP
/// @author SELVA Research Team - Federal University of Amazonas (UFAM)
/// @notice MVP smart contract for blockchain-based traceability of Amazonian copaiba supply chains
/// @dev Optimized implementation with reduced gas consumption
/// @custom:version 2.0.0 - Gas optimized, bug fixes applied
contract SELVATraceability {

    // ══════════════════════════════════════════════════════════════
    // OWNERSHIP & ACCESS CONTROL
    // ══════════════════════════════════════════════════════════════
    
    address public immutable owner; // Contract deployer (immutable saves gas)

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only contract owner");
        _;
    }

    modifier onlyProducer() {
        require(isProducer[msg.sender], "Only producers can perform this action");
        _;
    }

    // ══════════════════════════════════════════════════════════════
    // EVENTS (for off-chain indexing and forensic analysis)
    // ══════════════════════════════════════════════════════════════
    
    event UserRegistered(bytes32 indexed userHash, address indexed userAddress, string name);
    event ProducerCreated(address indexed producerAddress, bytes32 indexed userHash);
    event ProductAdded(string indexed lotId, address indexed producer, uint256 volume, bytes32 documentHash);
    event OwnershipTransferred(string indexed lotId, address indexed from, address indexed to, uint256 timestamp);
    event ProductDeactivated(string indexed lotId, address indexed deactivatedBy);

    // ══════════════════════════════════════════════════════════════
    // USER MODEL
    // ══════════════════════════════════════════════════════════════
    
    struct User {
        string name;
        string cpf;
        address account;
        uint64 createdAt;  // uint64 is sufficient for timestamps (saves gas)
        bool exists;       // Explicit flag for existence check
    }

    mapping(bytes32 => User) private users;
    bytes32[] private userIndex;
    mapping(address => bytes32) private addressToUserHash;

    // ══════════════════════════════════════════════════════════════
    // PRODUCER ROLE
    // ══════════════════════════════════════════════════════════════
    
    mapping(address => bool) public isProducer;
    address[] private producerList; // Track all producers for enumeration

    // ══════════════════════════════════════════════════════════════
    // PRODUCT / LOT MODEL
    // ══════════════════════════════════════════════════════════════
    
    struct Product {
        string lotId;
        uint128 volume;        // uint128 saves gas, more than enough for liters
        string origin;
        address producer;      // Original producer (immutable after creation)
        address currentOwner;
        bytes32 documentHash;
        uint64 createdAt;
        bool active;
    }

    mapping(string => Product) private products;
    string[] private lotIndex;

    // ══════════════════════════════════════════════════════════════
    // PRODUCT HISTORY / AUDIT TRAIL
    // ══════════════════════════════════════════════════════════════
    
    struct Trace {
        address actor;
        string action;      // "CREATED" | "TRANSFERRED" | "DEACTIVATED"
        bytes32 docHash;
        address from;
        address to;
        uint64 timestamp;
    }

    mapping(string => Trace[]) private history;

    // ══════════════════════════════════════════════════════════════
    // USER FUNCTIONS
    // ══════════════════════════════════════════════════════════════

    /// @notice Register a new user in the system
    /// @param _name User's full name
    /// @param _cpf User's CPF (Brazilian tax ID)
    /// @return userHash Unique identifier for the user
    function registerUser(string calldata _name, string calldata _cpf) external returns (bytes32) {
        require(bytes(_name).length > 0, "Name required");
        require(bytes(_cpf).length > 0, "CPF required");
        require(addressToUserHash[msg.sender] == bytes32(0), "Address already registered");

        bytes32 userHash = keccak256(abi.encodePacked(_name, _cpf, block.timestamp, msg.sender));

        users[userHash] = User({
            name: _name,
            cpf: _cpf,
            account: msg.sender,
            createdAt: uint64(block.timestamp),
            exists: true
        });

        addressToUserHash[msg.sender] = userHash;
        userIndex.push(userHash);

        emit UserRegistered(userHash, msg.sender, _name);
        return userHash;
    }

    /// @notice Promote a registered user to producer role
    /// @dev Only contract owner can call this. The user must be registered first.
    /// @param _userAddress Address of the user to promote
    function makeProducer(address _userAddress) external onlyOwner {
        require(_userAddress != address(0), "Invalid address");
        
        bytes32 userHash = addressToUserHash[_userAddress];
        require(userHash != bytes32(0), "User not registered");
        require(!isProducer[_userAddress], "Already a producer");

        isProducer[_userAddress] = true;
        producerList.push(_userAddress);

        emit ProducerCreated(_userAddress, userHash);
    }

    // ══════════════════════════════════════════════════════════════
    // PRODUCT FUNCTIONS
    // ══════════════════════════════════════════════════════════════

    /// @notice Register a new product (lot) on the blockchain
    /// @dev Only producers can add products. Duplicate lotIds are rejected.
    /// @param _lotId Unique identifier for the lot
    /// @param _volume Volume in liters (or base units)
    /// @param _origin Origin information (species, location, GPS)
    /// @param _docHash SHA-256 hash of environmental license/document
    function addProduct(
        string calldata _lotId,
        uint128 _volume,
        string calldata _origin,
        bytes32 _docHash
    ) external onlyProducer {
        require(bytes(_lotId).length > 0, "LotId required");
        require(_volume > 0, "Volume must be positive");
        require(!products[_lotId].active, "Lot already exists");

        products[_lotId] = Product({
            lotId: _lotId,
            volume: _volume,
            origin: _origin,
            producer: msg.sender,
            currentOwner: msg.sender,
            documentHash: _docHash,
            createdAt: uint64(block.timestamp),
            active: true
        });

        lotIndex.push(_lotId);

        // Record creation in history
        history[_lotId].push(Trace({
            actor: msg.sender,
            action: "CREATED",
            docHash: _docHash,
            from: address(0),
            to: msg.sender,
            timestamp: uint64(block.timestamp)
        }));

        emit ProductAdded(_lotId, msg.sender, _volume, _docHash);
    }

    /// @notice Transfer ownership of a product to another address
    /// @dev Only the current owner can transfer. Validates product exists and is active.
    /// @param _lotId Lot identifier to transfer
    /// @param _newOwner Address of the new owner
    function transferProduct(string calldata _lotId, address _newOwner) external {
        require(_newOwner != address(0), "Invalid recipient");
        
        Product storage p = products[_lotId];
        require(p.active, "Product not found or inactive");
        require(p.currentOwner == msg.sender, "Only owner can transfer");

        address previousOwner = p.currentOwner;
        p.currentOwner = _newOwner;

        // Record transfer in history
        history[_lotId].push(Trace({
            actor: msg.sender,
            action: "TRANSFERRED",
            docHash: p.documentHash,
            from: previousOwner,
            to: _newOwner,
            timestamp: uint64(block.timestamp)
        }));

        emit OwnershipTransferred(_lotId, previousOwner, _newOwner, block.timestamp);
    }

    /// @notice Deactivate a product (administrative action)
    /// @dev Only owner can deactivate. Used for corrections or cleanup.
    /// @param _lotId Lot identifier to deactivate
    function deactivateProduct(string calldata _lotId) external onlyOwner {
        Product storage p = products[_lotId];
        require(p.createdAt != 0, "Product not found");
        require(p.active, "Already inactive");
        
        p.active = false;

        history[_lotId].push(Trace({
            actor: msg.sender,
            action: "DEACTIVATED",
            docHash: p.documentHash,
            from: p.currentOwner,
            to: p.currentOwner,
            timestamp: uint64(block.timestamp)
        }));

        emit ProductDeactivated(_lotId, msg.sender);
    }

    // ══════════════════════════════════════════════════════════════
    // VIEW FUNCTIONS (Read-only, no gas cost for external calls)
    // ══════════════════════════════════════════════════════════════

    /// @notice Get product details by lotId
    function getProduct(string calldata _lotId) external view returns (
        string memory lotId,
        uint128 volume,
        string memory origin,
        address producer,
        address currentOwner,
        bytes32 documentHash,
        uint64 createdAt,
        bool active
    ) {
        Product memory p = products[_lotId];
        require(p.createdAt != 0, "Product not found");
        return (p.lotId, p.volume, p.origin, p.producer, p.currentOwner, p.documentHash, p.createdAt, p.active);
    }

    /// @notice Get complete history of a product
    function getProductHistory(string calldata _lotId) external view returns (
        address[] memory actors,
        string[] memory actions,
        bytes32[] memory docHashes,
        address[] memory froms,
        address[] memory tos,
        uint64[] memory timestamps
    ) {
        Trace[] memory traces = history[_lotId];
        uint256 len = traces.length;

        actors = new address[](len);
        actions = new string[](len);
        docHashes = new bytes32[](len);
        froms = new address[](len);
        tos = new address[](len);
        timestamps = new uint64[](len);

        for (uint256 i = 0; i < len; i++) {
            actors[i] = traces[i].actor;
            actions[i] = traces[i].action;
            docHashes[i] = traces[i].docHash;
            froms[i] = traces[i].from;
            tos[i] = traces[i].to;
            timestamps[i] = traces[i].timestamp;
        }
    }

    /// @notice List all registered lot IDs
    function listAllLotIds() external view returns (string[] memory) {
        return lotIndex;
    }

    /// @notice Get total number of products registered
    function getProductCount() external view returns (uint256) {
        return lotIndex.length;
    }

    /// @notice List all registered users
    function listAllUsers() external view returns (bytes32[] memory) {
        return userIndex;
    }

    /// @notice Get total number of registered users
    function getUserCount() external view returns (uint256) {
        return userIndex.length;
    }

    /// @notice Get user details by hash
    function getUser(bytes32 _userHash) external view returns (
        string memory name,
        string memory cpf,
        address account,
        uint64 createdAt
    ) {
        User memory u = users[_userHash];
        require(u.exists, "User not found");
        return (u.name, u.cpf, u.account, u.createdAt);
    }

    /// @notice Check if address is a registered user
    function isUserRegistered(address _addr) external view returns (bool) {
        return addressToUserHash[_addr] != bytes32(0);
    }

    /// @notice Get userHash for an address
    function userHashOf(address _addr) external view returns (bytes32) {
        return addressToUserHash[_addr];
    }

    /// @notice List all producers
    function listAllProducers() external view returns (address[] memory) {
        return producerList;
    }

    /// @notice Get total number of producers
    function getProducerCount() external view returns (uint256) {
        return producerList.length;
    }
}
