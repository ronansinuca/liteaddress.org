//https://raw.github.com/bitcoinjs/bitcoinjs-lib/09e8c6e184d6501a0c2c59d73ca64db5c0d3eb95/src/address.js
Bitcoin.Address = function (bytes) {
	if ("string" == typeof bytes) {
		bytes = Bitcoin.Address.decodeString(bytes);
	}
	this.hash = bytes;
	this.version = Bitcoin.Address.networkVersion;
};

Bitcoin.Address.networkVersion = 38; // mainnet

/**
* Serialize this object as a standard Bitcoin address.
*
* Returns the address as a base58-encoded string in the standardized format.
*/
Bitcoin.Address.prototype.toString = function () {
	// Get a copy of the hash
	var hash = this.hash.slice(0);

	// Version
	hash.unshift(this.version);
	var checksum = Crypto.SHA256(Crypto.SHA256(hash, { asBytes: true }), { asBytes: true });
	var bytes = hash.concat(checksum.slice(0, 4));

	// -------------------------------------------------------------------
	/*hash = this.hash.slice(0);

	var address = hash.slice(hash.length - 20, 20);

	address.unshift(this.version);

	checksum = Crypto.Keccak256(Crypto.Keccak256(address, { asBytes: true }), { asBytes: true });

	var bytes = address.concat(checksum.slice(0, 8));

	return "0x" + Crypto.util.bytesToHex(bytes).toString();*/
	//0x2615c6efec7761ab248b9d85bc2701167fa31bfbf7e4e6a21e45be9071


	//0x71C7656EC7ab88b098defB751B7401B5f6d8976F
	//0x1D1479C185d32EB90533a08b36B3CFa5F84A0E6B

	//GbRJZ2ay8mod686jHcRVtWWtKBxScXuqME

	/* 
	Ethereum address
	  0x742d35Cc6634C0532925a3b844Bc454e4438f44e
	  0x95222290dd7278aa3ddd389cc1e1d165cc4bafe5
	  0x456d9347342B72BCf800bBf117391ac2f807c6bF
	  0x1D1479C185d32EB90533a08b36B3CFa5F84A0E6B
	*/
	return Bitcoin.Base58.encode(bytes);
};

Bitcoin.Address.prototype.getHashBase64 = function () {
	return Crypto.util.bytesToBase64(this.hash);
};

/**
* Parse a Bitcoin address contained in a string.
*/
Bitcoin.Address.decodeString = function (string) {
	var bytes = Bitcoin.Base58.decode(string);
	var hash = bytes.slice(0, 21);
	var checksum = Crypto.SHA256(Crypto.SHA256(hash, { asBytes: true }), { asBytes: true });

	if (checksum[0] != bytes[21] ||
			checksum[1] != bytes[22] ||
			checksum[2] != bytes[23] ||
			checksum[3] != bytes[24]) {
		throw "Checksum validation failed!";
	}

	var version = hash.shift();

	if (version != 0) {
		throw "Version " + version + " not supported!";
	}

	return hash;
};