// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;

contract jwt_storage {
  
    // Storage variable to hold the token
    string private token;

    // Event for when the token is updated
    event TokenUpdated(string newToken);


    // Function to set the token (initial setup)
    function setToken(string memory _token) public {
        token = _token;
        emit TokenUpdated(_token);
    }

    // Function to get the token and add the caller to the fetchers list if not already added
    function getToken() public view returns (string memory) {
        // Add caller to fetchers list if not already added
        return token;
    }
}

