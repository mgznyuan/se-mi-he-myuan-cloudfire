const bcrypt = require('bcrypt');
const saltRounds = 12; // Adjust cost factor if needed (10-12 is common)
const myPlainTextPasscode = 'heiswrongabouteverything!'; // <<<=== PUT YOUR ACTUAL PASSCODE HERE



bcrypt.hash(myPlainTextPasscode, saltRounds, function(err, hash) {
    if (err) {
        console.error("Error hashing passcode:", err);
        return;
    }
    console.log("\n--- Your Secure bcrypt Passcode Hash ---");
    console.log(hash);
    console.log("----------------------------------------");
    console.log("Copy this hash and store it securely (e.g., as a Cloudflare Secret).");
    console.log("DO NOT store the plain text passcode ('" + myPlainTextPasscode + "') anywhere in your application code or secrets.\n");
});