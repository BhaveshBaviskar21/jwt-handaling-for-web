var jwt_storage = artifacts.require("./jwt_storage.sol");

module.exports = function(deployer) {
  // deployment steps
  deployer.deploy(jwt_storage);
};
