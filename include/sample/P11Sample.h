#pragma once

#include <string>
#include <vector>
#include <utility>
namespace p11sample
{
    class P11Sample
    {
    public:
        static P11Sample& i();
        void initialize();

        unsigned long openSession();
        void closeSession(unsigned long session);

        void login(unsigned long session, std::string_view pin);
        void logout(unsigned long session);

        unsigned long generateAESKey(unsigned long session);
        std::vector<unsigned char> encrypt(unsigned long session, unsigned long keyHandle, std::vector<unsigned char> data);
        std::vector<unsigned char> decrypt(unsigned long session, unsigned long keyHandle, std::vector<unsigned char> ciphertext);

        std::pair<unsigned long, unsigned long> generateECKeyPair(unsigned long session);
        std::vector<unsigned char> signECData(unsigned long session, unsigned long privKey, std::vector<unsigned char>& data);
        void verifyECSignature(unsigned long session, unsigned long pubKey, std::vector<unsigned char>& data, std::vector<unsigned char>& signature);

        unsigned long generateTokenAESKey(unsigned long session);
        unsigned long findObject(unsigned long session, std::string& label);
        void showAESAtribute(unsigned long session, unsigned long handle);
        std::vector<unsigned char> aesWrapKey(unsigned long session, unsigned long keyHandle);
        void aesUnwrap(unsigned long session, unsigned long keyHandle, std::vector<unsigned char>& wrappedKey, std::string& label);
        void destroyObject(unsigned long session, unsigned long handle);

        ~P11Sample();


    private:
        bool libOpened{false}, initialized{false};
        P11Sample() {};
    };
};
