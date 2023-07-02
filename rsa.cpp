// Sample.cpp

#include "cryptopp/rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

#include "cryptopp/sha.h"
using CryptoPP::SHA1;

#include "cryptopp/filters.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/cryptlib.h"
using CryptoPP::DecodingResult;
using CryptoPP::Exception;

#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;
#include <iostream>
using std::cerr;
using std::cout;

using std::endl;
using std::wcerr;
using std::wcin;
using std::wcout;

#include <string>
using std::string;
using std::wstring;
#include <io.h>
#include <fcntl.h>
// function connvert str to wstr
std::wstring string2wstring(const std::string &str)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.from_bytes(str);
}
// function convert wstr to str
std::string wstring2string(const std::wstring &wstr)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(wstr);
}

// Conver integer to string and wstring;

// integer to string, wstring
#include <sstream>
using std::ostringstream;

wstring integer_to_wstring(const CryptoPP::Integer &t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t;
    std::string encoded(oss.str());
    std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(encoded);
}

string integer_to_string(const CryptoPP::Integer &t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t;
    std::string encoded(oss.str());
    return encoded;
}

#include "cryptopp/base64.h"
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;

#include <exception>
using std::exception;

#include <iostream>
using std::cerr;
using std::cin;
using std::cout;
using std::endl;
using std::wcerr;
using std::wcin;
using std::wcout;

#include <assert.h>
#include <cryptopp/integer.h>
using CryptoPP::Integer;

// Genererate keys
#include "cryptopp/cryptlib.h"
using CryptoPP::DecodingResult;
using CryptoPP::Exception;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
/*Reading key input from file*/
#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;

// Load key from files
void Load(const string &filename, BufferedTransformation &bt);

void LoadPrivateKey(const string &filename, PrivateKey &key);

void LoadPublicKey(const string &pubkey_rsa, PublicKey &key);

void DecodePrivateKey(const string &filename, RSA::PrivateKey &key);

void DecodePublicKey(const string &filename, RSA::PublicKey &key);

void Decode(const string &filename, BufferedTransformation &bt);

// Encodekey in der form
void Encode(const string &filename, const BufferedTransformation &bt)
{
    FileSink file(filename.c_str());
    bt.CopyTo(file);
    file.MessageEnd();
}
void EncodePrivateKey(const string &filename, const RSA::PrivateKey &key)
{
    ByteQueue queue;
    key.DEREncodePrivateKey(queue);
    Encode(filename, queue);
}

void EncodePublicKey(const string &filename, const RSA::PublicKey &key)
{
    ByteQueue queue;
    key.DEREncodePublicKey(queue);
    Encode(filename, queue);
}

int main(int argc, char *argv[])
{

#ifdef __linux__
    setlocale(LC_ALL, "");
#elif __APPLE__
#if TARGET_OS_MAC
    setlocale(LC_ALL, "");
#else
#endif
#elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif

    wcout << "1.Encryption \n2.Decryption \nEnter a number (1 or 2): ";
    int modeende, modekey, modeplaintext, modeciphertext;
    string plain, cipher, recovered, encoded, cipher1;
    wstring plain1, cipher2;

    std::wcin.sync();
    std::wcin >> modeende;
    wcout << endl
          << "1.Random key \n2. Load key from file \nEnter mode for key: "; // Choose mode for key
    std::wcin >> modekey;

    ////////////////////////////////////////////////
    // Generate keys

    AutoSeededRandomPool rng;
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 3072);
    RSA::PublicKey publicKey(privateKey);
    switch (modekey)
    {
    case 1:

        break;

    case 2:
    {
        LoadPrivateKey("private-key.der", privateKey);
        LoadPublicKey("public-key.der", publicKey);
    }
    break;
    }

    Integer n1 = privateKey.GetModulus();
    Integer p1 = privateKey.GetPrime1();
    Integer q1 = privateKey.GetPrime2();
    Integer d1 = privateKey.GetPrivateExponent();
    Integer e1 = publicKey.GetPublicExponent();
    wcout << "modul n: " << integer_to_wstring(n1) << endl;
    wcout << endl
          << "prime number p: " << integer_to_wstring(p1) << endl;
    wcout << endl
          << "prime number q: " << integer_to_wstring(q1) << endl;
    wcout << endl
          << "public exponent e: " << integer_to_wstring(e1) << endl;

    switch (modeende)
    {
    case 1: // Encryption
    {
        wcout << endl
              << "1.Input from screen \n2. Load plaintext from file \nEnter mode plaintext: "; // Choose mode for plaintext
        std::wcin.sync();
        std::wcin >> modeplaintext;
        switch (modeplaintext)
        {
        case 1:
        {
            wcout << endl
                  << "Input text: ";
            std::wcin.sync();
            std::getline(std::wcin, plain1);
            plain = wstring2string(plain1);
        }
        break;
        case 2:
        {
            FileSource("plain.txt", true, new StringSink(plain));
            wcout << "Check plaintext: " << string2wstring(plain) << endl;
        }
        break;
        }

        RSAES_OAEP_SHA_Encryptor e(publicKey);

        StringSource(plain, true,
                     new PK_EncryptorFilter(rng, e,
                                            new StringSink(cipher)) // PK_EncryptorFilter
        );                                                          // StringSource

        ////////////////////////////////////////////////
        encoded.clear();
        StringSource(cipher, true,
                     new Base64Encoder(
                         new StringSink(encoded)) // HexEncoder
        );                                        // StringSources
        wcout << "cipher text (Base64): " << string2wstring(encoded) << endl;
    }
    break;

    case 2: // Decryption
    {
        wcout << endl
              << "1.Input from screen \n2. Load ciphertext from file \nEnter mode ciphertext (Base64): "; // Choose mode for plaintext
        std::wcin.sync();
        std::wcin >> modeciphertext;
        switch (modeciphertext)
        {
        case 1:
        {

            wcout << endl
                  << "Input text: ";
            std::wcin.sync();
            std::getline(std::wcin, cipher2);
            cipher1 = wstring2string(cipher2);
        }
        break;

        case 2:
        {
            FileSource("cipher.txt", true, new StringSink(cipher1));
            wcout << "Check cipher: " << string2wstring(cipher1) << endl;
        }
        break;
        }

        StringSource(cipher1, true,
                     new Base64Decoder(
                         new StringSink(cipher)) // HexDecoder
        );                                       // StringSource

        try
        {
            RSAES_OAEP_SHA_Decryptor d(privateKey);

            StringSource(cipher, true,
                         new PK_DecryptorFilter(rng, d,
                                                new StringSink(recovered)) // PK_EncryptorFilter
            );                                                             // StringSource

            assert(plain == recovered);
            wcout << "recovered text: " << string2wstring(recovered) << endl;
        }
        catch (CryptoPP::Exception &e)
        {
            cerr << "Caught Exception..." << endl;
            cerr << e.what() << endl;
        }

        return 0;
    }
    }
}

// Load key from files
void Load(const string &filename, BufferedTransformation &bt)
{
    FileSource file(filename.c_str(), true /*pumpAll*/);

    file.TransferTo(bt);
    bt.MessageEnd();
}
void LoadPrivateKey(const string &filename, PrivateKey &key)
{
    ByteQueue queue;
    Load(filename, queue);
    key.Load(queue);
}

void LoadPublicKey(const string &filename, PublicKey &key)
{
    ByteQueue queue;
    Load(filename, queue);
    key.Load(queue);
}

// Decode ber keys
void DecodePrivateKey(const string &filename, RSA::PrivateKey &key)
{
    ByteQueue queue;
    Decode(filename, queue);
    key.BERDecodePrivateKey(queue, false /*optParams*/, queue.MaxRetrievable());
}

void DecodePublicKey(const string &filename, RSA::PublicKey &key)
{
    ByteQueue queue;
    Decode(filename, queue);
    key.BERDecodePublicKey(queue, false /*optParams*/, queue.MaxRetrievable());
}

void Decode(const string &filename, BufferedTransformation &bt)
{
    FileSource file(filename.c_str(), true /*pumpAll*/);
    file.TransferTo(bt);
    bt.MessageEnd();
}