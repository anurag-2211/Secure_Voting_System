#include <iostream>
#include <vector>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <sstream>

using namespace std;

// Base64 Encoding for AES encrypted vote
string base64_encode(const string &input) {
    static const char base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    string output;
    int val = 0, valb = -6;
    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            output.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) output.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (output.size() % 4) output.push_back('=');
    return output;
}

// Base64 Decoding to retrieve AES encrypted vote
string base64_decode(const string &input) {
    static const char base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    string output;
    vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;

    int val = 0, valb = -8;
    for (unsigned char c : input) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            output.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return output;
}

// Function to generate large prime numbers for RSA
bool is_prime(long long num) {
    if (num < 2) return false;
    for (long long i = 2; i * i <= num; i++) {
        if (num % i == 0) return false;
    }
    return true;
}

long long generate_prime() {
    long long num;
    while (true) {
        num = rand() % 10000 + 5000;
        if (is_prime(num)) return num;
    }
}

// Function to calculate GCD
long long gcd(long long a, long long b) {
    while (b != 0) {
        long long temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Function to find modular inverse
long long mod_inverse(long long e, long long phi) {
    long long m0 = phi, t, q;
    long long x0 = 0, x1 = 1;
    if (phi == 1) return 0;

    while (e > 1) {
        q = e / phi;
        t = phi;
        phi = e % phi;
        e = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }

    if (x1 < 0) x1 += m0;
    return x1;
}

// RSA Key Generation
void generate_RSA_keys(long long &n, long long &e, long long &d) {
    long long p = generate_prime();
    long long q = generate_prime();
    n = p * q;
    long long phi = (p - 1) * (q - 1);

    e = 65537;
    d = mod_inverse(e, phi);
}

// RSA Encryption
long long rsa_encrypt(long long message, long long e, long long n) {
    long long result = 1;
    message = message % n;
    while (e > 0) {
        if (e % 2 == 1) result = (result * message) % n;
        e = e >> 1;
        message = (message * message) % n;
    }
    return result;
}

// RSA Decryption
long long rsa_decrypt(long long encrypted_message, long long d, long long n) {
    return rsa_encrypt(encrypted_message, d, n);
}

// AES Encryption for vote secrecy
string aes_encrypt(string message, string key) {
    string encrypted;
    for (size_t i = 0; i < message.size(); i++) {
        encrypted += (message[i] + key[i % key.size()]) % 256;
    }
    return base64_encode(encrypted);
}

// AES Decryption
string aes_decrypt(string encrypted, string key) {
    string decoded = base64_decode(encrypted);
    string decrypted;
    for (size_t i = 0; i < decoded.size(); i++) {
        decrypted += (decoded[i] - key[i % key.size()] + 256) % 256;
    }
    return decrypted;
}

// Signing vote using RSA (Digital Signature)
long long sign_vote(long long vote, long long d, long long n) {
    return rsa_encrypt(vote + 12345, d, n);
}

// Main Function (Multiple Voters)
int main() {
    srand(time(0));

    int num_voters;
    cout << "Enter number of voters: ";
    cin >> num_voters;

    vector<long long> votes(num_voters);
    vector<long long> signed_votes(num_voters);
    vector<string> encrypted_votes(num_voters);

    string aes_key = "secureaeskey123456";

    for (int i = 0; i < num_voters; i++) {
        cout << "Enter vote (ID) for voter " << i + 1 << ": ";
        cin >> votes[i];

        long long n, e, d;
        generate_RSA_keys(n, e, d);

        // Encrypt vote using AES
        encrypted_votes[i] = aes_encrypt(to_string(votes[i]), aes_key);

        // Digital signature on vote
        signed_votes[i] = sign_vote(votes[i], d, n);

        cout << "\nVoter " << i + 1 << " Results:" << endl;
        cout << "RSA Public Key: (" << e << ", " << n << ")" << endl;
        cout << "RSA Private Key: (" << d << ", " << n << ")" << endl;
        cout << "Encrypted Vote (AES, Base64): " << encrypted_votes[i] << endl;
        cout << "Signed Vote (RSA): " << signed_votes[i] << endl;
        cout << "------------------------------------\n";
    }

    return 0;
}
