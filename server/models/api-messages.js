var ApiMessages = function () { };
ApiMessages.prototype.EMAIL_NOT_FOUND = 0;
ApiMessages.prototype.INVALID_PWD = 1;
ApiMessages.prototype.DB_ERROR = 2;
ApiMessages.prototype.NOT_FOUND = 3;
ApiMessages.prototype.EMAIL_ALREADY_EXISTS = 4;
ApiMessages.prototype.COULD_NOT_CREATE_USER = 5;
ApiMessages.prototype.PASSWORD_RESET_EXPIRED = 6;
ApiMessages.prototype.PASSWORD_RESET_HASH_MISMATCH = 7;
ApiMessages.prototype.PASSWORD_RESET_EMAIL_MISMATCH = 8;
ApiMessages.prototype.COULD_NOT_RESET_PASSWORD = 9;

module.exports = ApiMessages;