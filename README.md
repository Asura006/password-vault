#include <iostream>
#include <string>
#include <ctime>

// Base class for password generation
class BasePasswordGenerator {
protected:
    int length;

public:
    BasePasswordGenerator(int len) : length(len) {}

    virtual std::string generatePassword() = 0;

    int getLength() const {
        return length;
    }
};

// Derived class implementing specific password generation logic
class PasswordGenerator : public BasePasswordGenerator {
private:
    std::string lowerChars;
    std::string upperChars;
    std::string digits;
    std::string specialChars;

    // Simple random number generator using LCG
    unsigned long seed;

    int random(int max) {
        seed = (seed * 1103515245 + 12345) % (1 << 31);
        return seed % max;
    }

public:
    PasswordGenerator(int len)
        : BasePasswordGenerator(len),
          lowerChars("abcdefghijklmnopqrstuvwxyz"),
          upperChars("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
          digits("0123456789"),
          specialChars("!@#$%^&*()-_=+[]{};:,.<>?/|"),
          seed(static_cast<unsigned long>(time(0))) { // Initialize seed with current time
    }

    std::string generatePassword() override {
        std::string allChars = lowerChars + upperChars + digits + specialChars;
        std::string password;

        for (int i = 0; i < length; ++i) {
            int index = random(allChars.size()); // Generate random index
            password += allChars[index]; // Append random character to password
        }

        return password;
    }
};

// Base class for password management
class BasePasswordManager {
protected:
    std::string password;
    int shift;

public:
    // Constructor to initialize the password and shift value
    BasePasswordManager(const std::string &pwd, int s) : password(pwd), shift(s) {}

    // Virtual function for encryption (to be overridden)
    virtual std::string encrypt() = 0;

    // Virtual function for decryption (to be overridden)
    virtual std::string decrypt(const std::string &encryptedPassword, int s) = 0;

    // Getter for password
    std::string getPassword() const {
        return password;
    }

    // Getter for shift
    int getShift() const {
        return shift;
    }
};

// Derived class implementing specific encryption and decryption
class PasswordManager : public BasePasswordManager {
private:
    std::string encryptedPassword; // Store encrypted password

public:
    // Constructor to initialize base class
    PasswordManager(const std::string &pwd, int s) : BasePasswordManager(pwd, s) {}

    // Function to encrypt the password
    std::string encrypt() override {
        encryptedPassword = password; // Set encrypted password
        for (char &c : encryptedPassword) {
            c = (c + shift); // Shift character
        }
        return encryptedPassword; // Return encrypted password
    }

    // Function to decrypt the password
    std::string decrypt(const std::string &encryptedPassword, int s) override {
        std::string decryptedPassword = encryptedPassword;
        for (char &c : decryptedPassword) {
            c = (c - s); // Reverse shift character
        }
        return decryptedPassword; // Return decrypted password
    }

    // Function to get the encrypted password
    std::string getEncryptedPassword() const {
        return encryptedPassword; // Return stored encrypted password
    }
};

int main() {
    std::string choice;

    do {
        std::cout << "Would you like to provide your own password, generate a random one, or exit? (enter 'own', 'random', or 'exit'): ";
        std::cin >> choice;

        if (choice == "exit") {
            break; // Exit the loop if the user chooses to exit
        }

        std::string password;
        if (choice == "own") {
            std::cout << "Enter your password: ";
            std::cin.ignore();  // Ignore the newline character left in the input buffer
            std::getline(std::cin, password);
        } else if (choice == "random") {
            int length;
            std::cout << "Enter the desired password length: ";
            std::cin >> length;

            if (length < 1) {
                std::cerr << "Password length must be at least 1." << std::endl;
                continue; // Prompt again if the length is invalid
            }

            // Create an instance of PasswordGenerator
            PasswordGenerator passwordGen(length);
            password = passwordGen.generatePassword();
            std::cout << "Generated Password: " << password << std::endl;
        } else {
            std::cerr << "Invalid choice! Please enter 'own', 'random', or 'exit'." << std::endl;
            continue; // Restart the loop if input is invalid
        }

        int shift;
        std::cout << "Enter the shift value for encryption (1-25): ";
        std::cin >> shift;

        // Ensure shift value is within a valid range
        if (shift < 1 || shift > 25) {
            std::cerr << "Shift value must be between 1 and 25." << std::endl;
            continue; // Exit if shift value is invalid
        }

        // Create an instance of PasswordManager
        PasswordManager pm(password, shift);
        
        // Encrypt the password
        std::string encryptedPassword = pm.encrypt();
        std::cout << "Encrypted Password: " << encryptedPassword << std::endl;

        do {
            // Display menu options
            std::cout << "\nChoose an action:\n";
            std::cout << "1. Decrypt Password\n";
            std::cout << "0. Exit\n";
            std::cout << "Enter your choice (1 or 0): ";
            std::cin >> choice;

            if (choice == "1") {
                std::string encryptedInput;
                std::cout << "Enter the encrypted password for decryption: ";
                std::cin.ignore();  // Ignore the newline character left in the input buffer
                std::getline(std::cin, encryptedInput);

                int inputShift;
                std::cout << "Enter the shift value used for encryption: ";
                std::cin >> inputShift;

                // Ensure the input shift value is valid
                if (inputShift < 1 || inputShift > 25) {
                    std::cerr << "Shift value must be between 1 and 25." << std::endl;
                    continue; // Exit if shift value is invalid
                }

                std::string decryptedPassword = pm.decrypt(encryptedInput, inputShift);
                std::cout << "Decrypted Password: " << decryptedPassword << std::endl;
            } else if (choice == "0") {
                break; // Exit the inner loop
            } else {
                std::cerr << "Invalid choice! Please select 1 or 0." << std::endl;
            }

        } while (true); // Continue until the user chooses to exit

    } while (true); // Continue until the user chooses to exit

    std::cout << "Exiting the program. Goodbye!" << std::endl;

    return 0;
}
