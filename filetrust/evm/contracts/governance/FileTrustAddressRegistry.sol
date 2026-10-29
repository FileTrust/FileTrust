// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: FileTrustAddressRegistry
// Purpose:  The on-chain record of every FileTrust contract version: which address,
//           which runtime code, which ABI, and whether it still takes new business.
//
// Project:  FileTrust -- decentralized file storage with proven custody
// Author:   Ali Farahpoor
// Company:  Electra Sphere Innovations (ElectraSI.es)
// Location: Barcelona, Spain
// Contact:  support@filetrust.io
//
// Version:      1.0.0
// Release Date: 29 October 2026
//
// Documentation: https://docs.filetrust.io
// Website:       https://www.filetrust.io
//
pragma solidity ^0.8.37;

import "./FileTrustOwnable.sol";

/// @title FileTrustAddressRegistry
/// @notice Per logical contract name, an append-only list of versions. Each entry holds the
///         address, its runtime code hash (checked against EXTCODEHASH when written), the
///         ABI hash and a status that only moves forward: Active, Deprecated, Retired. A
///         version is never overwritten and an address belongs to one entry. The registry
///         also records the hash of each release manifest the deployment publishes.
///
///         It is data, written by governance (the timelock): it moves no money and grants
///         no authority. Slashers, rewarders, escrows and verifiers keep their own bindings.
///         Clients compare it with their signed or pinned manifests and never switch to an
///         address only because the registry names it.
/// @dev    The ABI hash is a commitment (keccak256 of the ABI JSON, as the deployment
///         manifest computes it), not a proof that the ABI is correct.
contract FileTrustAddressRegistry is FileTrustOwnable {
    uint8 public constant ACTIVE = 1;
    uint8 public constant DEPRECATED = 2;
    uint8 public constant RETIRED = 3;

    struct Entry {
        address addr;
        uint64 registeredAt;
        uint8 status;
        bytes32 codeHash;
        bytes32 abiHash;
    }

    struct Release {
        bytes32 manifestHash;
        uint64 publishedAt;
    }

    /// @notice The chain this registry describes.
    uint256 public immutable chainId;

    mapping(bytes32 => Entry[]) private _versions;
    /// @notice The name and version an address is registered under (zero if none).
    mapping(address => bytes32) public nameOf;
    mapping(address => uint32) public versionOf;
    Release[] private _releases;

    event ContractRegistered(
        bytes32 indexed name, uint32 indexed version, address indexed addr, bytes32 codeHash, bytes32 abiHash
    );
    event StatusChanged(bytes32 indexed name, uint32 indexed version, uint8 status);
    event ReleasePublished(uint32 indexed release, bytes32 manifestHash);

    error InvalidEntry();
    error InvalidVersion();
    error AddressAlreadyRegistered();
    error CodeHashMismatch();
    error UnknownEntry();
    error InvalidStatus();

    constructor() Ownable(msg.sender) {
        chainId = block.chainid;
    }

    /// @notice Record `version` of `name`: the next one, never an existing one.
    function register(bytes32 name, uint32 version, address addr, bytes32 codeHash, bytes32 abiHash)
        external
        onlyOwner
    {
        if (name == bytes32(0) || addr == address(0) || abiHash == bytes32(0)) revert InvalidEntry();
        Entry[] storage versions = _versions[name];
        if (version == 0 || version != versions.length + 1) revert InvalidVersion();
        if (nameOf[addr] != bytes32(0)) revert AddressAlreadyRegistered();
        if (addr.code.length == 0 || addr.codehash != codeHash) revert CodeHashMismatch();
        versions.push(Entry({
            addr: addr, registeredAt: uint64(block.timestamp), status: ACTIVE, codeHash: codeHash, abiHash: abiHash
        }));
        nameOf[addr] = name;
        versionOf[addr] = version;
        emit ContractRegistered(name, version, addr, codeHash, abiHash);
    }

    /// @notice Move a version forward: Active to Deprecated or Retired, Deprecated to Retired.
    function setStatus(bytes32 name, uint32 version, uint8 status) external onlyOwner {
        Entry storage record = _entry(name, version);
        if (status <= record.status || status > RETIRED) revert InvalidStatus();
        record.status = status;
        emit StatusChanged(name, version, status);
    }

    /// @notice Record the hash of the next release manifest.
    function publishRelease(bytes32 manifestHash) external onlyOwner {
        if (manifestHash == bytes32(0)) revert InvalidEntry();
        _releases.push(Release({manifestHash: manifestHash, publishedAt: uint64(block.timestamp)}));
        emit ReleasePublished(uint32(_releases.length), manifestHash);
    }

    function latestVersion(bytes32 name) external view returns (uint32) {
        return uint32(_versions[name].length);
    }

    function entry(bytes32 name, uint32 version) external view returns (Entry memory) {
        return _entry(name, version);
    }

    function latest(bytes32 name) external view returns (uint32 version, Entry memory record) {
        version = uint32(_versions[name].length);
        record = _entry(name, version);
    }

    /// @notice Whether the registered address still runs the registered code.
    function isCodeIntact(bytes32 name, uint32 version) external view returns (bool) {
        Entry storage record = _entry(name, version);
        return record.addr.codehash == record.codeHash;
    }

    function releaseCount() external view returns (uint32) {
        return uint32(_releases.length);
    }

    function release(uint32 number) public view returns (Release memory) {
        if (number == 0 || number > _releases.length) revert UnknownEntry();
        return _releases[number - 1];
    }

    function latestRelease() external view returns (uint32 number, Release memory record) {
        number = uint32(_releases.length);
        record = release(number);
    }

    function _entry(bytes32 name, uint32 version) private view returns (Entry storage) {
        Entry[] storage versions = _versions[name];
        if (version == 0 || version > versions.length) revert UnknownEntry();
        return versions[version - 1];
    }
}
