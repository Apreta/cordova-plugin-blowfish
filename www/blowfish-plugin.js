/*global cordova, module*/

module.exports = {
    encrypt: function (data, successCallback, errorCallback) {
        cordova.exec(successCallback, errorCallback, "Blowfish", "encrypt", [data]);
    },
    decrypt: function (data, successCallback, errorCallback) {
        cordova.exec(successCallback, errorCallback, "Blowfish", "decrypt", [data]);
    },
    setKey: function (key, successCallback, errorCallback) {
        cordova.exec(successCallback, errorCallback, "Blowfish", "setKey", [key]);
    }
};
