// Copyright (c) 2016-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <base58.h>
#include <fs.h>
#include <interfaces/chain.h>
#include <util/system.h>
#include <wallet/wallet.h>
#include <wallet/walletutil.h>
#include <key_io.h>
#include <util/bip32.h>

namespace WalletTool {

// The standard wallet deleter function blocks on the validation interface
// queue, which doesn't exist for the bitcoin-wallet. Define our own
// deleter here.
static void WalletToolReleaseWallet(CWallet* wallet)
{
    wallet->WalletLogPrintf("Releasing wallet\n");
    wallet->Flush(true);
    delete wallet;
}

static std::shared_ptr<CWallet> CreateWallet(const std::string& name, const fs::path& path)
{
    if (fs::exists(path)) {
        tfm::format(std::cerr, "Error: File exists already\n");
        return nullptr;
    }
    // dummy chain interface
    auto chain = interfaces::MakeChain();
    std::shared_ptr<CWallet> wallet_instance(new CWallet(*chain, WalletLocation(name), WalletDatabase::Create(path)), WalletToolReleaseWallet);
    bool first_run = true;
    DBErrors load_wallet_ret = wallet_instance->LoadWallet(first_run);
    if (load_wallet_ret != DBErrors::LOAD_OK) {
        tfm::format(std::cerr, "Error creating %s", name.c_str());
        return nullptr;
    }

    wallet_instance->SetMinVersion(FEATURE_HD_SPLIT);

    // generate a new HD seed
    CPubKey seed = wallet_instance->GenerateNewSeed();
    wallet_instance->SetHDSeed(seed);

    tfm::format(std::cout, "Topping up keypool...\n");
    wallet_instance->TopUpKeyPool();
    return wallet_instance;
}

static std::shared_ptr<CWallet> LoadWallet(const std::string& name, const fs::path& path)
{
    if (!fs::exists(path)) {
        tfm::format(std::cerr, "Error: Wallet files does not exist\n");
        return nullptr;
    }

    // dummy chain interface
    auto chain = interfaces::MakeChain();
    std::shared_ptr<CWallet> wallet_instance(new CWallet(*chain, WalletLocation(name), WalletDatabase::Create(path)), WalletToolReleaseWallet);
    DBErrors load_wallet_ret;
    try {
        bool first_run;
        load_wallet_ret = wallet_instance->LoadWallet(first_run);
    } catch (const std::runtime_error&) {
        tfm::format(std::cerr, "Error loading %s. Is wallet being used by another process?\n", name.c_str());
        return nullptr;
    }

    if (load_wallet_ret != DBErrors::LOAD_OK) {
        wallet_instance = nullptr;
        if (load_wallet_ret == DBErrors::CORRUPT) {
            tfm::format(std::cerr, "Error loading %s: Wallet corrupted", name.c_str());
            return nullptr;
        } else if (load_wallet_ret == DBErrors::NONCRITICAL_ERROR) {
            tfm::format(std::cerr, "Error reading %s! All keys read correctly, but transaction data"
                            " or address book entries might be missing or incorrect.",
                name.c_str());
        } else if (load_wallet_ret == DBErrors::TOO_NEW) {
            tfm::format(std::cerr, "Error loading %s: Wallet requires newer version of %s",
                name.c_str(), PACKAGE_NAME);
            return nullptr;
        } else if (load_wallet_ret == DBErrors::NEED_REWRITE) {
            tfm::format(std::cerr, "Wallet needed to be rewritten: restart %s to complete", PACKAGE_NAME);
            return nullptr;
        } else {
            tfm::format(std::cerr, "Error loading %s", name.c_str());
            return nullptr;
        }
    }

    return wallet_instance;
}

static void WalletShowInfo(CWallet* wallet_instance)
{
    LOCK(wallet_instance->cs_wallet);

    tfm::format(std::cout, "Wallet info\n===========\n");
    tfm::format(std::cout, "Encrypted: %s\n", wallet_instance->IsCrypted() ? "yes" : "no");
    tfm::format(std::cout, "HD (hd seed available): %s\n", wallet_instance->GetHDChain().seed_id.IsNull() ? "no" : "yes");
    tfm::format(std::cout, "Keypool Size: %u\n", wallet_instance->GetKeyPoolSize());
    tfm::format(std::cout, "Transactions: %zu\n", wallet_instance->mapWallet.size());
    tfm::format(std::cout, "Address Book: %zu\n", wallet_instance->mapAddressBook.size());
}

std::string static EncodeDumpString(const std::string &str) {
    std::stringstream ret;
    for (const unsigned char c : str) {
        if (c <= 32 || c >= 128 || c == '%') {
            ret << '%' << HexStr(&c, &c + 1);
        } else {
            ret << c;
        }
    }
    return ret.str();
}

static bool GetWalletAddressesForKey(CWallet* const pwallet, const CKeyID& keyid, std::string& strAddr, std::string& strLabel) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    bool fLabelFound = false;
    CKey key;
    pwallet->GetKey(keyid, key);
    for (const auto& dest : GetAllDestinationsForKey(key.GetPubKey())) {
        if (pwallet->mapAddressBook.count(dest)) {
            if (!strAddr.empty()) {
                strAddr += ",";
            }
            strAddr += EncodeDestination(dest);
            strLabel = EncodeDumpString(pwallet->mapAddressBook[dest].name);
            fLabelFound = true;
        }
    }
    if (!fLabelFound) {
        strAddr = EncodeDestination(GetDestinationForKey(key.GetPubKey(), pwallet->m_default_address_type));
    }
    return fLabelFound;
}

static void WalletDumpKey(CWallet* pwallet)
{
    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    std::map<CTxDestination, int64_t> mapKeyBirth;
    const std::map<CKeyID, int64_t>& mapKeyPool = pwallet->GetAllReserveKeys();
    pwallet->GetKeyBirthTimes(*locked_chain, mapKeyBirth);

    std::set<CScriptID> scripts = pwallet->GetCScripts();
    // TODO: include scripts in GetKeyBirthTimes() output instead of separate

    // sort time/key pairs
    std::vector<std::pair<int64_t, CKeyID> > vKeyBirth;
    for (const auto& entry : mapKeyBirth) {
        if (const PKHash* keyID = boost::get<PKHash>(&entry.first)) { // set and test
            vKeyBirth.push_back(std::make_pair(entry.second, CKeyID(*keyID)));
        }
    }
    mapKeyBirth.clear();
    std::sort(vKeyBirth.begin(), vKeyBirth.end());

    // produce output
    std::cout << strprintf("# Wallet dump created by Bitcoin %s\n", CLIENT_BUILD);
    std::cout << strprintf("# * Created on %s\n", FormatISO8601DateTime(GetTime()));
    const Optional<int> tip_height = locked_chain->getHeight();
    std::cout << strprintf("# * Best block at time of backup was %i (%s),\n", tip_height.get_value_or(-1), tip_height ? locked_chain->getBlockHash(*tip_height).ToString() : "(missing block hash)");
    std::cout << strprintf("#   mined on %s\n", tip_height ? FormatISO8601DateTime(locked_chain->getBlockTime(*tip_height)) : "(missing block time)");
    std::cout << "\n";

    // add the base58check encoded extended master if the wallet uses HD
    CKeyID seed_id = pwallet->GetHDChain().seed_id;
    if (!seed_id.IsNull())
    {
        CKey seed;
        std::cout << strprintf("# seed id: %s \n\n", seed_id.GetHex());
        if (pwallet->GetKey(seed_id, seed)) {
            std::cout << strprintf("# seed: %s \n\n", EncodeSecret(seed));
            CExtKey masterKey;
            masterKey.SetSeed(seed.begin(), seed.size());

            std::cout << "# extended private masterkey: " << EncodeExtKey(masterKey) << "\n\n";
        }
    }
    // ELEMENTS: Dump the master blinding key in hex as well
    if (!pwallet->blinding_derivation_key.IsNull()) {
        std::cout << ("# Master private blinding key: " + HexStr(pwallet->blinding_derivation_key) + "\n\n");
    }
    for (std::vector<std::pair<int64_t, CKeyID> >::const_iterator it = vKeyBirth.begin(); it != vKeyBirth.end(); it++) {
        const CKeyID &keyid = it->second;
        std::string strTime = FormatISO8601DateTime(it->first);
        std::string strAddr;
        std::string strLabel;
        CKey key;
        if (pwallet->GetKey(keyid, key)) {
            std::cout << strprintf("%s %s ", EncodeSecret(key), strTime);
            if (GetWalletAddressesForKey(pwallet, keyid, strAddr, strLabel)) {
               std::cout << strprintf("label=%s", strLabel);
            } else if (keyid == seed_id) {
                std::cout << "hdseed=1";
            } else if (mapKeyPool.count(keyid)) {
                std::cout << "reserve=1";
            } else if (pwallet->mapKeyMetadata[keyid].hdKeypath == "s") {
                std::cout << "inactivehdseed=1";
            } else {
                std::cout << "change=1";
            }
            std::cout << strprintf(" # addr=%s%s\n", strAddr, (pwallet->mapKeyMetadata[keyid].has_key_origin ? " hdkeypath="+WriteHDKeypath(pwallet->mapKeyMetadata[keyid].key_origin.path) : ""));
        }
    }
    std::cout << "\n";
    for (const CScriptID &scriptid : scripts) {
        CScript script;
        std::string create_time = "0";
        std::string address = EncodeDestination(ScriptHash(scriptid));
        // get birth times for scripts with metadata
        auto it = pwallet->m_script_metadata.find(scriptid);
        if (it != pwallet->m_script_metadata.end()) {
            create_time = FormatISO8601DateTime(it->second.nCreateTime);
        }
        if(pwallet->GetCScript(scriptid, script)) {
            std::cout << strprintf("%s %s script=1", HexStr(script.begin(), script.end()), create_time);
            std::cout << strprintf(" # addr=%s\n", address);
        }
    }
    std::cout << "\n";

    // std::map<CTxDestination, std::vector<COutput>>
    auto coins = pwallet->CWallet::ListCoins(*locked_chain);
    std::cout << "# Coins:\n";
    for (const auto& pair : coins) {
        std::string address = EncodeDestination(pair.first);
        for (const auto& output : pair.second) {
            std::cout << strprintf(" # addr=%s, output=%s \n", address, output.ToString());
        }
    }

    std::cout << "\n";
    std::cout << "# End of dump\n";
}

bool ExecuteWalletToolFunc(const std::string& command, const std::string& name)
{
    fs::path path = fs::absolute(name, GetWalletDir());

    if (command == "create") {
        std::shared_ptr<CWallet> wallet_instance = CreateWallet(name, path);
        if (wallet_instance) {
            WalletShowInfo(wallet_instance.get());
            wallet_instance->Flush(true);
        }
    } else if (command == "info") {
        if (!fs::exists(path)) {
            tfm::format(std::cerr, "Error: no wallet file at %s\n", name.c_str());
            return false;
        }
        std::string error;
        if (!WalletBatch::VerifyEnvironment(path, error)) {
            tfm::format(std::cerr, "Error loading %s. Is wallet being used by other process?\n", name.c_str());
            return false;
        }
        std::shared_ptr<CWallet> wallet_instance = LoadWallet(name, path);
        if (!wallet_instance) return false;
        WalletShowInfo(wallet_instance.get());
        wallet_instance->Flush(true);
    } else if (command == "dump") {
        if (!fs::exists(path)) {
            tfm::format(std::cerr, "Error: no wallet file at %s\n", name.c_str());
            return false;
        }
        std::string error;
        if (!WalletBatch::VerifyEnvironment(path, error)) {
            tfm::format(std::cerr, "Error loading %s. Is wallet being used by other process?\n", name.c_str());
            return false;
        }
        std::shared_ptr<CWallet> wallet_instance = LoadWallet(name, path);
        if (!wallet_instance) return false;
        WalletDumpKey(wallet_instance.get());
        wallet_instance->Flush(true);
    } else {
        tfm::format(std::cerr, "Invalid command: %s\n", command.c_str());
        return false;
    }

    return true;
}
} // namespace WalletTool
