#include <cassert>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include "aes.hpp"

using namespace boomerang;
AES aes;

void unit_test(std::string key_hex, std::string pt_hex, std::string ct_hex) {
    auto key = hex_to_key(key_hex);
    auto pt = hex_to_block(pt_hex);
    auto ct_res = aes.encrypt(key, pt);
    auto ct_expected = block_to_hex(ct_res);
    assert(ct_expected == ct_hex);
    auto ct = hex_to_block(ct_hex);
    auto pt_res = aes.decrypt(key, ct);
    auto pt_expected = block_to_hex(pt_res);
    assert(pt_expected == pt_hex);
}

void gfsbox_test() {
    std::vector<std::string> test_vectors = {
        "f34481ec3cc627bacd5dc3fb08f273e6 0336763e966d92595a567cc9ce537f5e",
        "9798c4640bad75c7c3227db910174e72 a9a1631bf4996954ebc093957b234589",
        "96ab5c2ff612d9dfaae8c31f30c42168 ff4f8391a6a40ca5b25d23bedd44a597",
        "6a118a874519e64e9963798a503f1d35 dc43be40be0e53712f7e2bf5ca707209",
        "cb9fceec81286ca3e989bd979b0cb284 92beedab1895a94faa69b632e5cc47ce",
        "b26aeb1874e47ca8358ff22378f09144 459264f4798f6a78bacb89c15ed3d601",
        "58c8e00b2631686d54eab84b91f0aca1 08a4e2efec8a8e3312ca7460b9040bbf",   
    };
    std::string key_hex(32, '0');
    for (auto tv : test_vectors) {
        std::string pt_hex, ct_hex;
        std::stringstream ss(tv);
        ss >> pt_hex >> ct_hex;
        unit_test(key_hex, pt_hex, ct_hex);
    }
};

void keysbox_test() {
    std::vector<std::string> test_vectors = {
        "10a58869d74be5a374cf867cfb473859 6d251e6944b051e04eaa6fb4dbf78465",
        "caea65cdbb75e9169ecd22ebe6e54675 6e29201190152df4ee058139def610bb",
        "a2e2fa9baf7d20822ca9f0542f764a41 c3b44b95d9d2f25670eee9a0de099fa3",
        "b6364ac4e1de1e285eaf144a2415f7a0 5d9b05578fc944b3cf1ccf0e746cd581",
        "64cf9c7abc50b888af65f49d521944b2 f7efc89d5dba578104016ce5ad659c05",
        "47d6742eefcc0465dc96355e851b64d9 0306194f666d183624aa230a8b264ae7",
        "3eb39790678c56bee34bbcdeccf6cdb5 858075d536d79ccee571f7d7204b1f67",
        "64110a924f0743d500ccadae72c13427 35870c6a57e9e92314bcb8087cde72ce",
        "18d8126516f8a12ab1a36d9f04d68e51 6c68e9be5ec41e22c825b7c7affb4363",
        "f530357968578480b398a3c251cd1093 f5df39990fc688f1b07224cc03e86cea",
        "da84367f325d42d601b4326964802e8e bba071bcb470f8f6586e5d3add18bc66",
        "e37b1c6aa2846f6fdb413f238b089f23 43c9f7e62f5d288bb27aa40ef8fe1ea8",
        "6c002b682483e0cabcc731c253be5674 3580d19cff44f1014a7c966a69059de5",
        "143ae8ed6555aba96110ab58893a8ae1 806da864dd29d48deafbe764f8202aef",
        "b69418a85332240dc82492353956ae0c a303d940ded8f0baff6f75414cac5243",
        "71b5c08a1993e1362e4d0ce9b22b78d5 c2dabd117f8a3ecabfbb11d12194d9d0",
        "e234cdca2606b81f29408d5f6da21206 fff60a4740086b3b9c56195b98d91a7b",
        "13237c49074a3da078dc1d828bb78c6f 8146a08e2357f0caa30ca8c94d1a0544",
        "3071a2a48fe6cbd04f1a129098e308f8 4b98e06d356deb07ebb824e5713f7be3",
        "90f42ec0f68385f2ffc5dfc03a654dce 7a20a53d460fc9ce0423a7a0764c6cf2",
        "febd9a24d8b65c1c787d50a4ed3619a9 f4a70d8af877f9b02b4c40df57d45b17",
    };
    std::string pt_hex(32, '0');
    for (auto tv : test_vectors) {
        std::string key_hex, ct_hex;
        std::stringstream ss(tv);
        ss >> key_hex >> ct_hex;
        unit_test(key_hex, pt_hex, ct_hex);
    }
}

void vartxt_test() {
    std::vector<std::string> test_vectors = {
        "80000000000000000000000000000000 3ad78e726c1ec02b7ebfe92b23d9ec34",
        "c0000000000000000000000000000000 aae5939c8efdf2f04e60b9fe7117b2c2",
        "e0000000000000000000000000000000 f031d4d74f5dcbf39daaf8ca3af6e527",
        "f0000000000000000000000000000000 96d9fd5cc4f07441727df0f33e401a36",
        "f8000000000000000000000000000000 30ccdb044646d7e1f3ccea3dca08b8c0",
        "fc000000000000000000000000000000 16ae4ce5042a67ee8e177b7c587ecc82",
        "fe000000000000000000000000000000 b6da0bb11a23855d9c5cb1b4c6412e0a",
        "ff000000000000000000000000000000 db4f1aa530967d6732ce4715eb0ee24b",
        "ff800000000000000000000000000000 a81738252621dd180a34f3455b4baa2f",
        "ffc00000000000000000000000000000 77e2b508db7fd89234caf7939ee5621a",
        "ffe00000000000000000000000000000 b8499c251f8442ee13f0933b688fcd19",
        "fff00000000000000000000000000000 965135f8a81f25c9d630b17502f68e53",
        "fff80000000000000000000000000000 8b87145a01ad1c6cede995ea3670454f",
        "fffc0000000000000000000000000000 8eae3b10a0c8ca6d1d3b0fa61e56b0b2",
        "fffe0000000000000000000000000000 64b4d629810fda6bafdf08f3b0d8d2c5",
        "ffff0000000000000000000000000000 d7e5dbd3324595f8fdc7d7c571da6c2a",
        "ffff8000000000000000000000000000 f3f72375264e167fca9de2c1527d9606",
        "ffffc000000000000000000000000000 8ee79dd4f401ff9b7ea945d86666c13b",
        "ffffe000000000000000000000000000 dd35cea2799940b40db3f819cb94c08b",
        "fffff000000000000000000000000000 6941cb6b3e08c2b7afa581ebdd607b87",
        "fffff800000000000000000000000000 2c20f439f6bb097b29b8bd6d99aad799",
        "fffffc00000000000000000000000000 625d01f058e565f77ae86378bd2c49b3",
        "fffffe00000000000000000000000000 c0b5fd98190ef45fbb4301438d095950",
        "ffffff00000000000000000000000000 13001ff5d99806efd25da34f56be854b",
        "ffffff80000000000000000000000000 3b594c60f5c8277a5113677f94208d82",
        "ffffffc0000000000000000000000000 e9c0fc1818e4aa46bd2e39d638f89e05",
        "ffffffe0000000000000000000000000 f8023ee9c3fdc45a019b4e985c7e1a54",
        "fffffff0000000000000000000000000 35f40182ab4662f3023baec1ee796b57",
        "fffffff8000000000000000000000000 3aebbad7303649b4194a6945c6cc3694",
        "fffffffc000000000000000000000000 a2124bea53ec2834279bed7f7eb0f938",
        "fffffffe000000000000000000000000 b9fb4399fa4facc7309e14ec98360b0a",
        "ffffffff000000000000000000000000 c26277437420c5d634f715aea81a9132",
        "ffffffff800000000000000000000000 171a0e1b2dd424f0e089af2c4c10f32f",
        "ffffffffc00000000000000000000000 7cadbe402d1b208fe735edce00aee7ce",
        "ffffffffe00000000000000000000000 43b02ff929a1485af6f5c6d6558baa0f",
        "fffffffff00000000000000000000000 092faacc9bf43508bf8fa8613ca75dea",
        "fffffffff80000000000000000000000 cb2bf8280f3f9742c7ed513fe802629c",
        "fffffffffc0000000000000000000000 215a41ee442fa992a6e323986ded3f68",
        "fffffffffe0000000000000000000000 f21e99cf4f0f77cea836e11a2fe75fb1",
        "ffffffffff0000000000000000000000 95e3a0ca9079e646331df8b4e70d2cd6",
        "ffffffffff8000000000000000000000 4afe7f120ce7613f74fc12a01a828073",
        "ffffffffffc000000000000000000000 827f000e75e2c8b9d479beed913fe678",
        "ffffffffffe000000000000000000000 35830c8e7aaefe2d30310ef381cbf691",
        "fffffffffff000000000000000000000 191aa0f2c8570144f38657ea4085ebe5",
        "fffffffffff800000000000000000000 85062c2c909f15d9269b6c18ce99c4f0",
        "fffffffffffc00000000000000000000 678034dc9e41b5a560ed239eeab1bc78",
        "fffffffffffe00000000000000000000 c2f93a4ce5ab6d5d56f1b93cf19911c1",
        "ffffffffffff00000000000000000000 1c3112bcb0c1dcc749d799743691bf82",
        "ffffffffffff80000000000000000000 00c55bd75c7f9c881989d3ec1911c0d4",
        "ffffffffffffc0000000000000000000 ea2e6b5ef182b7dff3629abd6a12045f",
        "ffffffffffffe0000000000000000000 22322327e01780b17397f24087f8cc6f",
        "fffffffffffff0000000000000000000 c9cacb5cd11692c373b2411768149ee7",
        "fffffffffffff8000000000000000000 a18e3dbbca577860dab6b80da3139256",
        "fffffffffffffc000000000000000000 79b61c37bf328ecca8d743265a3d425c",
        "fffffffffffffe000000000000000000 d2d99c6bcc1f06fda8e27e8ae3f1ccc7",
        "ffffffffffffff000000000000000000 1bfd4b91c701fd6b61b7f997829d663b",
        "ffffffffffffff800000000000000000 11005d52f25f16bdc9545a876a63490a",
        "ffffffffffffffc00000000000000000 3a4d354f02bb5a5e47d39666867f246a",
        "ffffffffffffffe00000000000000000 d451b8d6e1e1a0ebb155fbbf6e7b7dc3",
        "fffffffffffffff00000000000000000 6898d4f42fa7ba6a10ac05e87b9f2080",
        "fffffffffffffff80000000000000000 b611295e739ca7d9b50f8e4c0e754a3f",
        "fffffffffffffffc0000000000000000 7d33fc7d8abe3ca1936759f8f5deaf20",
        "fffffffffffffffe0000000000000000 3b5e0f566dc96c298f0c12637539b25c",
        "ffffffffffffffff0000000000000000 f807c3e7985fe0f5a50e2cdb25c5109e",
        "ffffffffffffffff8000000000000000 41f992a856fb278b389a62f5d274d7e9",
        "ffffffffffffffffc000000000000000 10d3ed7a6fe15ab4d91acbc7d0767ab1",
        "ffffffffffffffffe000000000000000 21feecd45b2e675973ac33bf0c5424fc",
        "fffffffffffffffff000000000000000 1480cb3955ba62d09eea668f7c708817",
        "fffffffffffffffff800000000000000 66404033d6b72b609354d5496e7eb511",
        "fffffffffffffffffc00000000000000 1c317a220a7d700da2b1e075b00266e1",
        "fffffffffffffffffe00000000000000 ab3b89542233f1271bf8fd0c0f403545",
        "ffffffffffffffffff00000000000000 d93eae966fac46dca927d6b114fa3f9e",
        "ffffffffffffffffff80000000000000 1bdec521316503d9d5ee65df3ea94ddf",
        "ffffffffffffffffffc0000000000000 eef456431dea8b4acf83bdae3717f75f",
        "ffffffffffffffffffe0000000000000 06f2519a2fafaa596bfef5cfa15c21b9",
        "fffffffffffffffffff0000000000000 251a7eac7e2fe809e4aa8d0d7012531a",
        "fffffffffffffffffff8000000000000 3bffc16e4c49b268a20f8d96a60b4058",
        "fffffffffffffffffffc000000000000 e886f9281999c5bb3b3e8862e2f7c988",
        "fffffffffffffffffffe000000000000 563bf90d61beef39f48dd625fcef1361",
        "ffffffffffffffffffff000000000000 4d37c850644563c69fd0acd9a049325b",
        "ffffffffffffffffffff800000000000 b87c921b91829ef3b13ca541ee1130a6",
        "ffffffffffffffffffffc00000000000 2e65eb6b6ea383e109accce8326b0393",
        "ffffffffffffffffffffe00000000000 9ca547f7439edc3e255c0f4d49aa8990",
        "fffffffffffffffffffff00000000000 a5e652614c9300f37816b1f9fd0c87f9",
        "fffffffffffffffffffff80000000000 14954f0b4697776f44494fe458d814ed",
        "fffffffffffffffffffffc0000000000 7c8d9ab6c2761723fe42f8bb506cbcf7",
        "fffffffffffffffffffffe0000000000 db7e1932679fdd99742aab04aa0d5a80",
        "ffffffffffffffffffffff0000000000 4c6a1c83e568cd10f27c2d73ded19c28",
        "ffffffffffffffffffffff8000000000 90ecbe6177e674c98de412413f7ac915",
        "ffffffffffffffffffffffc000000000 90684a2ac55fe1ec2b8ebd5622520b73",
        "ffffffffffffffffffffffe000000000 7472f9a7988607ca79707795991035e6",
        "fffffffffffffffffffffff000000000 56aff089878bf3352f8df172a3ae47d8",
        "fffffffffffffffffffffff800000000 65c0526cbe40161b8019a2a3171abd23",
        "fffffffffffffffffffffffc00000000 377be0be33b4e3e310b4aabda173f84f",
        "fffffffffffffffffffffffe00000000 9402e9aa6f69de6504da8d20c4fcaa2f",
        "ffffffffffffffffffffffff00000000 123c1f4af313ad8c2ce648b2e71fb6e1",
        "ffffffffffffffffffffffff80000000 1ffc626d30203dcdb0019fb80f726cf4",
        "ffffffffffffffffffffffffc0000000 76da1fbe3a50728c50fd2e621b5ad885",
        "ffffffffffffffffffffffffe0000000 082eb8be35f442fb52668e16a591d1d6",
        "fffffffffffffffffffffffff0000000 e656f9ecf5fe27ec3e4a73d00c282fb3",
        "fffffffffffffffffffffffff8000000 2ca8209d63274cd9a29bb74bcd77683a",
        "fffffffffffffffffffffffffc000000 79bf5dce14bb7dd73a8e3611de7ce026",
        "fffffffffffffffffffffffffe000000 3c849939a5d29399f344c4a0eca8a576",
        "ffffffffffffffffffffffffff000000 ed3c0a94d59bece98835da7aa4f07ca2",
        "ffffffffffffffffffffffffff800000 63919ed4ce10196438b6ad09d99cd795",
        "ffffffffffffffffffffffffffc00000 7678f3a833f19fea95f3c6029e2bc610",
        "ffffffffffffffffffffffffffe00000 3aa426831067d36b92be7c5f81c13c56",
        "fffffffffffffffffffffffffff00000 9272e2d2cdd11050998c845077a30ea0",
        "fffffffffffffffffffffffffff80000 088c4b53f5ec0ff814c19adae7f6246c",
        "fffffffffffffffffffffffffffc0000 4010a5e401fdf0a0354ddbcc0d012b17",
        "fffffffffffffffffffffffffffe0000 a87a385736c0a6189bd6589bd8445a93",
        "ffffffffffffffffffffffffffff0000 545f2b83d9616dccf60fa9830e9cd287",
        "ffffffffffffffffffffffffffff8000 4b706f7f92406352394037a6d4f4688d",
        "ffffffffffffffffffffffffffffc000 b7972b3941c44b90afa7b264bfba7387",
        "ffffffffffffffffffffffffffffe000 6f45732cf10881546f0fd23896d2bb60",
        "fffffffffffffffffffffffffffff000 2e3579ca15af27f64b3c955a5bfc30ba",
        "fffffffffffffffffffffffffffff800 34a2c5a91ae2aec99b7d1b5fa6780447",
        "fffffffffffffffffffffffffffffc00 a4d6616bd04f87335b0e53351227a9ee",
        "fffffffffffffffffffffffffffffe00 7f692b03945867d16179a8cefc83ea3f",
        "ffffffffffffffffffffffffffffff00 3bd141ee84a0e6414a26e7a4f281f8a2",
        "ffffffffffffffffffffffffffffff80 d1788f572d98b2b16ec5d5f3922b99bc",
        "ffffffffffffffffffffffffffffffc0 0833ff6f61d98a57b288e8c3586b85a6",
        "ffffffffffffffffffffffffffffffe0 8568261797de176bf0b43becc6285afb",
        "fffffffffffffffffffffffffffffff0 f9b0fda0c4a898f5b9e6f661c4ce4d07",
        "fffffffffffffffffffffffffffffff8 8ade895913685c67c5269f8aae42983e",
        "fffffffffffffffffffffffffffffffc 39bde67d5c8ed8a8b1c37eb8fa9f5ac0",
        "fffffffffffffffffffffffffffffffe 5c005e72c1418c44f569f2ea33ba54f3",
        "ffffffffffffffffffffffffffffffff 3f5b8cc9ea855a0afa7347d23e8d664e",
    };
    std::string key_hex(32, '0');
    for (auto tv : test_vectors) {
        std::string pt_hex, ct_hex;
        std::stringstream ss(tv);
        ss >> pt_hex >> ct_hex;
        unit_test(key_hex, pt_hex, ct_hex);
    }
}

void varkey_test() {
    std::vector<std::string> test_vectors = {
        "80000000000000000000000000000000 0edd33d3c621e546455bd8ba1418bec8",
        "c0000000000000000000000000000000 4bc3f883450c113c64ca42e1112a9e87",
        "e0000000000000000000000000000000 72a1da770f5d7ac4c9ef94d822affd97",
        "f0000000000000000000000000000000 970014d634e2b7650777e8e84d03ccd8",
        "f8000000000000000000000000000000 f17e79aed0db7e279e955b5f493875a7",
        "fc000000000000000000000000000000 9ed5a75136a940d0963da379db4af26a",
        "fe000000000000000000000000000000 c4295f83465c7755e8fa364bac6a7ea5",
        "ff000000000000000000000000000000 b1d758256b28fd850ad4944208cf1155",
        "ff800000000000000000000000000000 42ffb34c743de4d88ca38011c990890b",
        "ffc00000000000000000000000000000 9958f0ecea8b2172c0c1995f9182c0f3",
        "ffe00000000000000000000000000000 956d7798fac20f82a8823f984d06f7f5",
        "fff00000000000000000000000000000 a01bf44f2d16be928ca44aaf7b9b106b",
        "fff80000000000000000000000000000 b5f1a33e50d40d103764c76bd4c6b6f8",
        "fffc0000000000000000000000000000 2637050c9fc0d4817e2d69de878aee8d",
        "fffe0000000000000000000000000000 113ecbe4a453269a0dd26069467fb5b5",
        "ffff0000000000000000000000000000 97d0754fe68f11b9e375d070a608c884",
        "ffff8000000000000000000000000000 c6a0b3e998d05068a5399778405200b4",
        "ffffc000000000000000000000000000 df556a33438db87bc41b1752c55e5e49",
        "ffffe000000000000000000000000000 90fb128d3a1af6e548521bb962bf1f05",
        "fffff000000000000000000000000000 26298e9c1db517c215fadfb7d2a8d691",
        "fffff800000000000000000000000000 a6cb761d61f8292d0df393a279ad0380",
        "fffffc00000000000000000000000000 12acd89b13cd5f8726e34d44fd486108",
        "fffffe00000000000000000000000000 95b1703fc57ba09fe0c3580febdd7ed4",
        "ffffff00000000000000000000000000 de11722d893e9f9121c381becc1da59a",
        "ffffff80000000000000000000000000 6d114ccb27bf391012e8974c546d9bf2",
        "ffffffc0000000000000000000000000 5ce37e17eb4646ecfac29b9cc38d9340",
        "ffffffe0000000000000000000000000 18c1b6e2157122056d0243d8a165cddb",
        "fffffff0000000000000000000000000 99693e6a59d1366c74d823562d7e1431",
        "fffffff8000000000000000000000000 6c7c64dc84a8bba758ed17eb025a57e3",
        "fffffffc000000000000000000000000 e17bc79f30eaab2fac2cbbe3458d687a",
        "fffffffe000000000000000000000000 1114bc2028009b923f0b01915ce5e7c4",
        "ffffffff000000000000000000000000 9c28524a16a1e1c1452971caa8d13476",
        "ffffffff800000000000000000000000 ed62e16363638360fdd6ad62112794f0",
        "ffffffffc00000000000000000000000 5a8688f0b2a2c16224c161658ffd4044",
        "ffffffffe00000000000000000000000 23f710842b9bb9c32f26648c786807ca",
        "fffffffff00000000000000000000000 44a98bf11e163f632c47ec6a49683a89",
        "fffffffff80000000000000000000000 0f18aff94274696d9b61848bd50ac5e5",
        "fffffffffc0000000000000000000000 82408571c3e2424540207f833b6dda69",
        "fffffffffe0000000000000000000000 303ff996947f0c7d1f43c8f3027b9b75",
        "ffffffffff0000000000000000000000 7df4daf4ad29a3615a9b6ece5c99518a",
        "ffffffffff8000000000000000000000 c72954a48d0774db0b4971c526260415",
        "ffffffffffc000000000000000000000 1df9b76112dc6531e07d2cfda04411f0",
        "ffffffffffe000000000000000000000 8e4d8e699119e1fc87545a647fb1d34f",
        "fffffffffff000000000000000000000 e6c4807ae11f36f091c57d9fb68548d1",
        "fffffffffff800000000000000000000 8ebf73aad49c82007f77a5c1ccec6ab4",
        "fffffffffffc00000000000000000000 4fb288cc2040049001d2c7585ad123fc",
        "fffffffffffe00000000000000000000 04497110efb9dceb13e2b13fb4465564",
        "ffffffffffff00000000000000000000 75550e6cb5a88e49634c9ab69eda0430",
        "ffffffffffff80000000000000000000 b6768473ce9843ea66a81405dd50b345",
        "ffffffffffffc0000000000000000000 cb2f430383f9084e03a653571e065de6",
        "ffffffffffffe0000000000000000000 ff4e66c07bae3e79fb7d210847a3b0ba",
        "fffffffffffff0000000000000000000 7b90785125505fad59b13c186dd66ce3",
        "fffffffffffff8000000000000000000 8b527a6aebdaec9eaef8eda2cb7783e5",
        "fffffffffffffc000000000000000000 43fdaf53ebbc9880c228617d6a9b548b",
        "fffffffffffffe000000000000000000 53786104b9744b98f052c46f1c850d0b",
        "ffffffffffffff000000000000000000 b5ab3013dd1e61df06cbaf34ca2aee78",
        "ffffffffffffff800000000000000000 7470469be9723030fdcc73a8cd4fbb10",
        "ffffffffffffffc00000000000000000 a35a63f5343ebe9ef8167bcb48ad122e",
        "ffffffffffffffe00000000000000000 fd8687f0757a210e9fdf181204c30863",
        "fffffffffffffff00000000000000000 7a181e84bd5457d26a88fbae96018fb0",
        "fffffffffffffff80000000000000000 653317b9362b6f9b9e1a580e68d494b5",
        "fffffffffffffffc0000000000000000 995c9dc0b689f03c45867b5faa5c18d1",
        "fffffffffffffffe0000000000000000 77a4d96d56dda398b9aabecfc75729fd",
        "ffffffffffffffff0000000000000000 84be19e053635f09f2665e7bae85b42d",
        "ffffffffffffffff8000000000000000 32cd652842926aea4aa6137bb2be2b5e",
        "ffffffffffffffffc000000000000000 493d4a4f38ebb337d10aa84e9171a554",
        "ffffffffffffffffe000000000000000 d9bff7ff454b0ec5a4a2a69566e2cb84",
        "fffffffffffffffff000000000000000 3535d565ace3f31eb249ba2cc6765d7a",
        "fffffffffffffffff800000000000000 f60e91fc3269eecf3231c6e9945697c6",
        "fffffffffffffffffc00000000000000 ab69cfadf51f8e604d9cc37182f6635a",
        "fffffffffffffffffe00000000000000 7866373f24a0b6ed56e0d96fcdafb877",
        "ffffffffffffffffff00000000000000 1ea448c2aac954f5d812e9d78494446a",
        "ffffffffffffffffff80000000000000 acc5599dd8ac02239a0fef4a36dd1668",
        "ffffffffffffffffffc0000000000000 d8764468bb103828cf7e1473ce895073",
        "ffffffffffffffffffe0000000000000 1b0d02893683b9f180458e4aa6b73982",
        "fffffffffffffffffff0000000000000 96d9b017d302df410a937dcdb8bb6e43",
        "fffffffffffffffffff8000000000000 ef1623cc44313cff440b1594a7e21cc6",
        "fffffffffffffffffffc000000000000 284ca2fa35807b8b0ae4d19e11d7dbd7",
        "fffffffffffffffffffe000000000000 f2e976875755f9401d54f36e2a23a594",
        "ffffffffffffffffffff000000000000 ec198a18e10e532403b7e20887c8dd80",
        "ffffffffffffffffffff800000000000 545d50ebd919e4a6949d96ad47e46a80",
        "ffffffffffffffffffffc00000000000 dbdfb527060e0a71009c7bb0c68f1d44",
        "ffffffffffffffffffffe00000000000 9cfa1322ea33da2173a024f2ff0d896d",
        "fffffffffffffffffffff00000000000 8785b1a75b0f3bd958dcd0e29318c521",
        "fffffffffffffffffffff80000000000 38f67b9e98e4a97b6df030a9fcdd0104",
        "fffffffffffffffffffffc0000000000 192afffb2c880e82b05926d0fc6c448b",
        "fffffffffffffffffffffe0000000000 6a7980ce7b105cf530952d74daaf798c",
        "ffffffffffffffffffffff0000000000 ea3695e1351b9d6858bd958cf513ef6c",
        "ffffffffffffffffffffff8000000000 6da0490ba0ba0343b935681d2cce5ba1",
        "ffffffffffffffffffffffc000000000 f0ea23af08534011c60009ab29ada2f1",
        "ffffffffffffffffffffffe000000000 ff13806cf19cc38721554d7c0fcdcd4b",
        "fffffffffffffffffffffff000000000 6838af1f4f69bae9d85dd188dcdf0688",
        "fffffffffffffffffffffff800000000 36cf44c92d550bfb1ed28ef583ddf5d7",
        "fffffffffffffffffffffffc00000000 d06e3195b5376f109d5c4ec6c5d62ced",
        "fffffffffffffffffffffffe00000000 c440de014d3d610707279b13242a5c36",
        "ffffffffffffffffffffffff00000000 f0c5c6ffa5e0bd3a94c88f6b6f7c16b9",
        "ffffffffffffffffffffffff80000000 3e40c3901cd7effc22bffc35dee0b4d9",
        "ffffffffffffffffffffffffc0000000 b63305c72bedfab97382c406d0c49bc6",
        "ffffffffffffffffffffffffe0000000 36bbaab22a6bd4925a99a2b408d2dbae",
        "fffffffffffffffffffffffff0000000 307c5b8fcd0533ab98bc51e27a6ce461",
        "fffffffffffffffffffffffff8000000 829c04ff4c07513c0b3ef05c03e337b5",
        "fffffffffffffffffffffffffc000000 f17af0e895dda5eb98efc68066e84c54",
        "fffffffffffffffffffffffffe000000 277167f3812afff1ffacb4a934379fc3",
        "ffffffffffffffffffffffffff000000 2cb1dc3a9c72972e425ae2ef3eb597cd",
        "ffffffffffffffffffffffffff800000 36aeaa3a213e968d4b5b679d3a2c97fe",
        "ffffffffffffffffffffffffffc00000 9241daca4fdd034a82372db50e1a0f3f",
        "ffffffffffffffffffffffffffe00000 c14574d9cd00cf2b5a7f77e53cd57885",
        "fffffffffffffffffffffffffff00000 793de39236570aba83ab9b737cb521c9",
        "fffffffffffffffffffffffffff80000 16591c0f27d60e29b85a96c33861a7ef",
        "fffffffffffffffffffffffffffc0000 44fb5c4d4f5cb79be5c174a3b1c97348",
        "fffffffffffffffffffffffffffe0000 674d2b61633d162be59dde04222f4740",
        "ffffffffffffffffffffffffffff0000 b4750ff263a65e1f9e924ccfd98f3e37",
        "ffffffffffffffffffffffffffff8000 62d0662d6eaeddedebae7f7ea3a4f6b6",
        "ffffffffffffffffffffffffffffc000 70c46bb30692be657f7eaa93ebad9897",
        "ffffffffffffffffffffffffffffe000 323994cfb9da285a5d9642e1759b224a",
        "fffffffffffffffffffffffffffff000 1dbf57877b7b17385c85d0b54851e371",
        "fffffffffffffffffffffffffffff800 dfa5c097cdc1532ac071d57b1d28d1bd",
        "fffffffffffffffffffffffffffffc00 3a0c53fa37311fc10bd2a9981f513174",
        "fffffffffffffffffffffffffffffe00 ba4f970c0a25c41814bdae2e506be3b4",
        "ffffffffffffffffffffffffffffff00 2dce3acb727cd13ccd76d425ea56e4f6",
        "ffffffffffffffffffffffffffffff80 5160474d504b9b3eefb68d35f245f4b3",
        "ffffffffffffffffffffffffffffffc0 41a8a947766635dec37553d9a6c0cbb7",
        "ffffffffffffffffffffffffffffffe0 25d6cfe6881f2bf497dd14cd4ddf445b",
        "fffffffffffffffffffffffffffffff0 41c78c135ed9e98c096640647265da1e",
        "fffffffffffffffffffffffffffffff8 5a4d404d8917e353e92a21072c3b2305",
        "fffffffffffffffffffffffffffffffc 02bc96846b3fdc71643f384cd3cc3eaf",
        "fffffffffffffffffffffffffffffffe 9ba4a9143f4e5d4048521c4f8877d88e",
        "ffffffffffffffffffffffffffffffff a1f6258c877d5fcd8964484538bfc92c",
    };
    std::string pt_hex(32, '0');
    for (auto tv : test_vectors) {
        std::string key_hex, ct_hex;
        std::stringstream ss(tv);
        ss >> key_hex >> ct_hex;
        unit_test(key_hex, pt_hex, ct_hex);
    }
}

int main() {
    unit_test("2b7e151628aed2a6abf7158809cf4f3c", "3243f6a8885a308d313198a2e0370734", "3925841d02dc09fbdc118597196a0b32");
    gfsbox_test();
    keysbox_test();
    vartxt_test();
    varkey_test();
    return 0;   
}