#include <P11Sample.h>

#include <cryptoki.h>
#include <iostream>

#ifdef __unix__
#include <dlfcn.h>
#elif _WIN32
#include <windows.h>
#endif

namespace
{
    void checkOperations(CK_RV ret, std::string_view name)
    {
        if (ret != CKR_OK)
        {
            std::cerr << "Function " << name << " Failed.\n";
            std::cerr << "Ret value: " << std::hex << ret << std::endl;
            exit(EXIT_FAILURE);
        }
    }
};

namespace p11sample
{
    static constexpr char const* LIBNAME = "libsofthsm2.so";
    static void* p11_handle;
    static CK_SLOT_ID firstSlotId{0};
    static CK_FUNCTION_LIST* funcList;

    P11Sample& P11Sample::i()
    {
        static P11Sample instance;
        return instance;
    }

    void P11Sample::initialize()
    {

#ifdef __unix__
            p11_handle = dlopen(LIBNAME, RTLD_NOW);
#elif __WIN32
            p11_handle = LoadLibrary(LIBNAME);
#endif

        if (!p11_handle)
        {
            std::cerr << "Unable to open library " << LIBNAME << std::endl;
            exit(EXIT_FAILURE);
        }

        this->libOpened = true;

        CK_C_GetFunctionList ck_get_func_list;

#ifdef __unix__
            ck_get_func_list = (CK_C_GetFunctionList) dlsym(p11_handle, "C_GetFunctionList");
#elif __WIN32
            ck_get_func_list = (CK_C_GetFunctionList) GetProcAddress(p11_handle, "C_GetFunctionList");
#endif

        if (!ck_get_func_list)
        {
            std::cerr << "Unable to populate GetFunctionList " << std::endl;
            exit(EXIT_FAILURE);
        }

        checkOperations(ck_get_func_list(&funcList), "CK_GetFunctionList");
        checkOperations(funcList->C_Initialize(NULL_PTR), "C_Initialize");
        this->initialized = true;
    }

    unsigned long P11Sample::openSession()
    {
        if (firstSlotId == 0)
        {
            CK_ULONG slotCount;
            checkOperations(funcList->C_GetSlotList(NULL_PTR, NULL_PTR, &slotCount), "C_GetSlotList");

            std::vector<CK_SLOT_ID> slotList(slotCount);
            checkOperations(funcList->C_GetSlotList(NULL_PTR, slotList.data(), &slotCount), "C_GetSlotList");

            firstSlotId = slotList[0];
        }

        CK_SESSION_HANDLE sesHandle;
        checkOperations(funcList->C_OpenSession(firstSlotId, CKF_SERIAL_SESSION | CKF_RW_SESSION ,NULL_PTR, NULL_PTR, &sesHandle), "C_OpenSession");

        CK_ULONG mechLen;
        checkOperations(funcList->C_GetMechanismList(firstSlotId, NULL_PTR, &mechLen), "C_GetMechanismList");

        std::vector<CK_MECHANISM_TYPE> mechList(mechLen);
        checkOperations(funcList->C_GetMechanismList(firstSlotId, mechList.data(), &mechLen), "C_GetMechanismList");

        for (int i=0; i != mechLen; i++)
        {
            if (mechList[i] == CKM_ECDSA_SHA256)
                std::cout << "Available mechanism type: " << mechList[i] << std::endl;
        }

        return sesHandle;
    }

    void P11Sample::closeSession(unsigned long session)
    {
        checkOperations(funcList->C_CloseSession(session), "C_CloseSession");
    }

    void P11Sample::login(unsigned long session, std::string_view pin)
    {
        auto pinVal{reinterpret_cast<unsigned char*>(const_cast<char *>(pin.data()))};
        checkOperations(funcList->C_Login(session, CKU_USER, pinVal, pin.size()), "C_Login");
    }

    void P11Sample::logout(unsigned long session)
    {
        checkOperations(funcList->C_Logout(session), "C_Logout");
    }

    unsigned long P11Sample::generateAESKey(unsigned long session)
    {
        CK_UTF8CHAR label[] = "AES01";
        CK_ULONG keySize = 32;
        CK_MECHANISM mech{CKM_AES_KEY_GEN};
        CK_BBOOL yes{CK_TRUE};
        CK_BBOOL no{CK_FALSE};

        CK_ATTRIBUTE attrKey[] = {
            {CKA_TOKEN,      &no,       sizeof(CK_BBOOL)},
            {CKA_PRIVATE,    &yes,      sizeof(CK_BBOOL)},
            {CKA_MODIFIABLE, &no,       sizeof(CK_BBOOL)},
            {CKA_EXTRACTABLE,&no,       sizeof(CK_BBOOL)},
            {CKA_SENSITIVE,  &yes,      sizeof(CK_BBOOL)},
            {CKA_ENCRYPT,    &yes,      sizeof(CK_BBOOL)},
            {CKA_DECRYPT,    &yes,      sizeof(CK_BBOOL)},
            {CKA_VALUE_LEN,  &keySize,  sizeof(CK_ULONG)},
            {CKA_LABEL,      &label,    sizeof(label)},
        };

        CK_ULONG attrKeyLen = sizeof(attrKey)/ sizeof(*attrKey);

        CK_OBJECT_HANDLE keyHandle;
        checkOperations(funcList->C_GenerateKey(session, &mech, attrKey, attrKeyLen, &keyHandle), "C_GenerateKey");
        return keyHandle;
    }

    std::vector<unsigned char> P11Sample::encrypt(unsigned long session, unsigned long keyHandle, std::vector<unsigned char> data)
    {
        CK_BYTE IV[] = "123456781234";
        CK_BYTE AAD[] = "12345678";
        CK_MECHANISM mech{CKM_AES_GCM, NULL_PTR, 0};
        CK_GCM_PARAMS params = {
            IV,
            12,
            sizeof(IV),
            AAD,
            sizeof(AAD),
            128
        };
        mech.pParameter = &params;
        mech.ulParameterLen = sizeof(params);
        checkOperations(funcList->C_EncryptInit(session, &mech, keyHandle), "C_EncryptInit");

        unsigned long encryptedLength;
        checkOperations(funcList->C_Encrypt(session, data.data(), data.size(), NULL_PTR, &encryptedLength), "C_Encrypt");

        std::vector<unsigned char> encrypted(encryptedLength);
        checkOperations(funcList->C_Encrypt(session, data.data(), data.size(), encrypted.data(), &encryptedLength), "C_Encrypt");
        
        return std::move(encrypted);
    }

    std::vector<unsigned char> P11Sample::decrypt(unsigned long session, unsigned long keyHandle, std::vector<unsigned char> ciphertext)
    {
        CK_BYTE IV[] = "123456781234";
        CK_BYTE AAD[] = "12345678";
        CK_MECHANISM mech{CKM_AES_GCM, NULL_PTR, 0};
        CK_GCM_PARAMS params = {
            IV,
            12,
            sizeof(IV),
            AAD,
            sizeof(AAD),
            128
        };
        mech.pParameter = &params;
        mech.ulParameterLen = sizeof(params);
        checkOperations(funcList->C_DecryptInit(session, &mech, keyHandle), "C_DecryptInit");

        unsigned long plaintextLength;
        checkOperations(funcList->C_Decrypt(session, ciphertext.data(), ciphertext.size(), NULL_PTR, &plaintextLength), "C_Decrypt");

        std::vector<unsigned char> plaintext(plaintextLength);
        checkOperations(funcList->C_Decrypt(session, ciphertext.data(), ciphertext.size(), plaintext.data(), &plaintextLength), "C_Decrypt");

        plaintext.resize(plaintextLength);
        return std::move(plaintext);
    }

    std::pair<unsigned long, unsigned long> P11Sample::generateECKeyPair(unsigned long session)
    {
        CK_MECHANISM mech = {CKM_EC_KEY_PAIR_GEN};
        CK_BBOOL yes{CK_TRUE};
        CK_BBOOL no{CK_FALSE};
        CK_BYTE curve[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23};

        CK_ATTRIBUTE keyAttrPub[] = {
            {CKA_TOKEN,         &no,        sizeof(CK_BBOOL)},
            {CKA_PRIVATE,       &no,        sizeof(CK_BBOOL)},
            {CKA_MODIFIABLE,    &no,        sizeof(CK_BBOOL)},
            {CKA_VERIFY,        &yes,       sizeof(CK_BBOOL)},
            {CKA_EC_PARAMS,     &curve,     sizeof(curve)},
        };

        auto keyAttrPubLen = sizeof(keyAttrPub) / sizeof(*keyAttrPub);

        CK_ATTRIBUTE keyAttrPriv[] = {
            {CKA_TOKEN,         &no,        sizeof(CK_BBOOL)},
            {CKA_PRIVATE,       &yes,       sizeof(CK_BBOOL)},
            {CKA_MODIFIABLE,    &no,        sizeof(CK_BBOOL)},
            {CKA_SIGN,          &yes,       sizeof(CK_BBOOL)},
            {CKA_SENSITIVE,     &yes,       sizeof(CK_BBOOL)},
        };

        auto keyAttrPrivLen = sizeof(keyAttrPriv) / sizeof(*keyAttrPriv);

        CK_OBJECT_HANDLE pubKey, privKey;
        checkOperations(funcList->C_GenerateKeyPair(session, &mech, keyAttrPub, keyAttrPubLen, keyAttrPriv, keyAttrPrivLen, &pubKey, &privKey), "C_GenerateKeyPair");

        return std::make_pair(pubKey, privKey);
    }

    std::vector<unsigned char> P11Sample::signECData(unsigned long session, unsigned long privKey, std::vector<unsigned char>& data)
    {
        CK_MECHANISM mech{CKM_ECDSA};
        checkOperations(funcList->C_SignInit(session, &mech, privKey), "C_SignInit");

        CK_ULONG signatureLength;
        checkOperations(funcList->C_Sign(session, data.data(), data.size(), NULL_PTR, &signatureLength), "C_Sign");

        std::vector<unsigned char> signature(signatureLength);
        checkOperations(funcList->C_Sign(session, data.data(), data.size(), signature.data(), &signatureLength), "C_Sign");

        signature.resize(signatureLength);
        return std::move(signature);
    }

    void P11Sample::verifyECSignature(unsigned long session, unsigned long pubKey, std::vector<unsigned char>& data, std::vector<unsigned char>& signature)
    {
        CK_MECHANISM mech{CKM_ECDSA};
        checkOperations(funcList->C_VerifyInit(session, &mech, pubKey), "C_VerifyInit");
        checkOperations(funcList->C_Verify(session, data.data(), data.size(), signature.data(), signature.size()), "C_Verify");
    }

    unsigned long P11Sample::generateTokenAESKey(unsigned long session)
    {
        CK_MECHANISM mech{CKM_AES_KEY_GEN};
        CK_UTF8CHAR label[] = "AES01";
        CK_ULONG keySize = 32;
        CK_BBOOL yes{CK_TRUE};
        CK_BBOOL no{CK_FALSE};

        CK_ATTRIBUTE keyAttr[] = {
            {CKA_LABEL,         &label,     sizeof(label)},
            {CKA_TOKEN,         &yes,       sizeof(CK_BBOOL)},
            {CKA_PRIVATE,       &yes,       sizeof(CK_BBOOL)},
            {CKA_MODIFIABLE,    &yes,       sizeof(CK_BBOOL)},
            {CKA_SENSITIVE,     &yes,       sizeof(CK_BBOOL)},
            {CKA_EXTRACTABLE,   &yes,       sizeof(CK_BBOOL)},
            {CKA_VALUE_LEN,     &keySize,   sizeof(CK_ULONG)},
            {CKA_ENCRYPT,       &yes,       sizeof(CK_BBOOL)},
            {CKA_DECRYPT,       &yes,       sizeof(CK_BBOOL)},
            {CKA_WRAP,          &no,        sizeof(CK_BBOOL)}
        };

        CK_ULONG keyAttrLen = sizeof(keyAttr)/sizeof(*keyAttr);

        CK_OBJECT_HANDLE keyHandle;
        checkOperations(funcList->C_GenerateKey(session, &mech, keyAttr, keyAttrLen, &keyHandle), "CK_GenerateKey in token");

        return keyHandle;
    }

    unsigned long P11Sample::findObject(unsigned long session, std::string& label)
    {
        CK_BBOOL yes{CK_TRUE};
        CK_BBOOL no{CK_FALSE};
        std::cout << label << std::endl;

        CK_ATTRIBUTE searchAttr[] = {
            {CKA_TOKEN,     &yes,           sizeof(CK_BBOOL)},
            {CKA_LABEL,     label.data(),   label.size()+1}
        };

        CK_ULONG attrSize = sizeof(searchAttr)/sizeof(*searchAttr);
        checkOperations(funcList->C_FindObjectsInit(session, searchAttr, attrSize), "C_FindObjectsInit");

        CK_ULONG retSize;
        CK_ULONG totalSize = 0;
        std::vector<CK_OBJECT_HANDLE> objList(10);
        do{

            checkOperations(funcList->C_FindObjects(session, objList.data(), 10, &retSize), "C_FindObjects");
            totalSize+=retSize;
        } while(retSize != 0);

        checkOperations(funcList->C_FindObjectsFinal(session), "C_FindObjectsFinal");
        return objList[0];
    }

    void P11Sample::showAESAtribute(unsigned long session, unsigned long handle)
    {
        CK_BBOOL yes{CK_TRUE};
        CK_BBOOL no{CK_FALSE};

        std::vector<CK_BYTE> value(100);
        CK_ATTRIBUTE attrList[] = {
            {CKA_TOKEN,     &yes,           sizeof(CK_BBOOL)},
            {CKA_VALUE,     value.data(),   value.size()},
        };

        CK_ULONG attrSize = sizeof(attrList)/sizeof(*attrList);
        checkOperations(funcList->C_GetAttributeValue(session, handle, attrList, attrSize), "C_GetAttributeValue");


        std::cout << "Key Value: ";
        for (auto& dat: value)
            std::cout << (int)dat << " ";
        std::cout << std::endl;
    }

    std::vector<unsigned char> P11Sample::aesWrapKey(unsigned long session, unsigned long keyHandle)
    {
        CK_MECHANISM mech{CKM_AES_KEY_WRAP};

        CK_ULONG wrappedLength;
        checkOperations(funcList->C_WrapKey(session, &mech, keyHandle, keyHandle, NULL_PTR, &wrappedLength), "C_WrapKey get length");

        std::vector<unsigned char> wrappedKey(wrappedLength);
        checkOperations(funcList->C_WrapKey(session, &mech, keyHandle, keyHandle, wrappedKey.data(), &wrappedLength), "C_WrapKey");

        wrappedKey.resize(wrappedLength);
        return std::move(wrappedKey);
    }

    void P11Sample::aesUnwrap(unsigned long session, unsigned long keyHandle, std::vector<unsigned char>& wrappedKey, std::string& label)
    {
        CK_MECHANISM mech{CKM_AES_KEY_WRAP};
        CK_ULONG keySize = 32;
        CK_BBOOL yes{CK_TRUE};
        CK_BBOOL no{CK_FALSE};
        CK_OBJECT_CLASS ckoClass{CKO_SECRET_KEY};
        CK_KEY_TYPE keyType{CKK_AES};

        CK_ATTRIBUTE keyAttr[] = {
            {CKA_LABEL,         label.data(),       label.size() + 1},
            {CKA_CLASS,         &ckoClass,          sizeof(ckoClass)},
            {CKA_KEY_TYPE,      &keyType,           sizeof(keyType)},
            {CKA_TOKEN,         &yes,               sizeof(CK_BBOOL)},
            {CKA_EXTRACTABLE,   &yes,               sizeof(CK_BBOOL)},
            {CKA_SENSITIVE,     &no,                sizeof(CK_BBOOL)}
        };

        CK_ULONG keyAttrLen = sizeof(keyAttr)/sizeof(*keyAttr);

        CK_ULONG wrappedLength;
        checkOperations(funcList->C_UnwrapKey(session, &mech, keyHandle, wrappedKey.data(), wrappedKey.size(), keyAttr, keyAttrLen, &keyHandle), "C_UnwrapKey");
    }

    void P11Sample::destroyObject(unsigned long session, unsigned long handle)
    {
        checkOperations(funcList->C_DestroyObject(session, handle), "DestroyObject");
    }

    P11Sample::~P11Sample()
    {
        // if (this->initialized)
        // {
        //     checkOperations(funcList->C_Finalize(NULL_PTR), "C_Finalize");
        //     this->initialized = false;
        // }

        if (this->libOpened)
        {
#ifdef __unix
            if (dlclose(p11_handle))
            {
                std::cerr << "dlclose failed.\n";
            }
            this->libOpened = false;
#elif __WIN32
            // TODO
#endif
        }
    }
};

