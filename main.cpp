#include <iostream>
#include <memory>
#include <vector>
#include <string>

#include <sample/P11Sample.h>

using namespace p11sample;

int main(int, char**){
    P11Sample::i().initialize();
    auto session{P11Sample::i().openSession()};
    
    //login
    P11Sample::i().login(session, "password");

    std::string label{"AES01"};
    auto retrievedHandle {P11Sample::i().findObject(session, label)};
    std::cout << "Retrieved handle: " << retrievedHandle << std::endl;

    P11Sample::i().destroyObject(session, retrievedHandle);

    // auto wrappedKey{P11Sample::i().aesWrapKey(session, retrievedHandle)};
    // std::cout << "Wrapped key: ";
    // for (auto dat: wrappedKey)
    //     std::cout << std::hex << (int)dat << " ";
    // std::cout << std::endl;

    // std::string keyLabel{"AES02"};
    // P11Sample::i().aesUnwrap(session, retrievedHandle, wrappedKey, keyLabel);

    // //generate key
    // auto keyHandle{P11Sample::i().generateAESKey(session)};
    // std::cout << "Key Handle: " << keyHandle << std::endl;

    //encrypt
    // std::vector<unsigned char> data{0x01,0x01,0x01,0x01};
    // for (auto &dat: data)
    //     std::cout << (int) dat << " ";
    // std::cout << std::endl;
    // auto enc{P11Sample::i().encrypt(session, retrievedHandle, data)};
    // for (auto &dat: enc)
    //     std::cout << (int) dat << " ";
    // std::cout << std::endl;
    // auto plain{P11Sample::i().decrypt(session, retrievedHandle, enc)};
    // for (auto &dat: plain)
    //     std::cout << (int) dat << " ";
    // std::cout << std::endl;

    // if (plain == data) std::cout << "Plaintext similar\n"; else std::cout << "Plaintext differs\n";
    

    // auto keypair{P11Sample::i().generateECKeyPair(session)};
    // std::cout << "EC pub key: " << keypair.first << ", EC private key: " << keypair.second << std::endl;


    // auto signature{P11Sample::i().signECData(session, keypair.second, data)};
    // std::cout << "Signature: ";
    // for (auto &dat: signature)
    //     std::cout << (int) dat << " ";
    // std::cout << std::endl;
    // P11Sample::i().verifyECSignature(session, keypair.first, data, signature);

    // auto handle{P11Sample::i().generateTokenAESKey(session)};
    // std::cout << "Generated key handle: " << handle << std::endl;

    P11Sample::i().logout(session);
    P11Sample::i().closeSession(session);
    return EXIT_SUCCESS;
}
