// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20BurnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract RealToken is
    Initializable,
    ERC20Upgradeable,
    ERC20BurnableUpgradeable,
    PausableUpgradeable,
    AccessControlUpgradeable,
    UUPSUpgradeable
{
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    mapping(address => bool) private kycUsers;
    address public kycStoreAddress;
    RealToken private kycStore;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        string memory name,
        string memory symbol,
        address owner,
        address waddress
    ) public initializer {
        __ERC20_init(name, symbol);
        __ERC20Burnable_init();
        __Pausable_init();
        __AccessControl_init();
        __UUPSUpgradeable_init();
        _grantRole(PAUSER_ROLE, owner);
        _grantRole(MINTER_ROLE, owner);
        _grantRole(DEFAULT_ADMIN_ROLE, owner);
        _grantRole(UPGRADER_ROLE, owner);
        kycUsers[address(0)] = true;
        kycStoreAddress = waddress;
        kycStore = RealToken(kycStoreAddress);
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }

    function burn(uint256 amount) public override onlyRole(MINTER_ROLE) {}

    function burnFrom(
        address account,
        uint256 amount
    ) public override onlyRole(MINTER_ROLE) {}

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 amount
    ) internal override whenNotPaused {
        require(
            kycStoreAddress != address(0),
            "whitelistAddress not initialized"
        );
        require(kycStore.isKYCVerified(to), "Recipient not allowed");
        super._beforeTokenTransfer(from, to, amount);
    }

    function setWhitelistAddress(
        address newAddress
    ) external onlyRole(MINTER_ROLE) {
        kycStoreAddress = newAddress;
        kycStore = RealToken(kycStoreAddress);
    }

    function addToWhitelist(address account) external onlyRole(MINTER_ROLE) {
        require(account != address(0), "Invalid address");
        require(!kycUsers[account], "Address already whitelisted");
        kycUsers[account] = true;
    }

    function isKYCVerified(address user) external view returns (bool) {
        return kycUsers[user];
    }

    function removeFromWhitelist(
        address account
    ) external onlyRole(MINTER_ROLE) {
        require(account != address(0), "Invalid address");
        require(kycUsers[account], "Address not whitelisted");
        kycUsers[account] = false;
    }

    function addMultipleToWhitelist(
        address[] memory accounts
    ) external onlyRole(MINTER_ROLE) {
        for (uint256 i = 0; i < accounts.length; i++) {
            address account = accounts[i];
            require(account != address(0), "Invalid address");
            if (!kycUsers[account]) {
                kycUsers[account] = true;
            }
        }
    }

    function removeMultipleFromWhitelist(
        address[] memory accounts
    ) external onlyRole(MINTER_ROLE) {
        for (uint256 i = 0; i < accounts.length; i++) {
            address account = accounts[i];
            require(account != address(0), "Invalid address");
            if (kycUsers[account]) {
                kycUsers[account] = false;
            }
        }
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}
}
