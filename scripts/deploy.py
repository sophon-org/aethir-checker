
from brownie import *
from eth_account import Account
from web3 import Web3
from eth_abi import encode
from enum import IntEnum

'''from brownie.network import gas_price
from brownie.network.gas.strategies import LinearScalingStrategy
gas_strategy = LinearScalingStrategy("12 gwei", "60 gwei", 1.1)
gas_price(gas_strategy) ## gas_price(20e9)'''


def run_a_test(aethirChecker=None):

    deployer = getDeployer()
    soph_test_0, soph_test_1, soph_test_2, soph_test_3, soph_test_4 = setup_test_accounts()

    if aethirChecker is None:
        aethirChecker = deploy(deployer, soph_test_0)

    submit_values, admin_sig = setup_test_data(aethirChecker, False, soph_test_0, soph_test_1, soph_test_2, soph_test_3, soph_test_4)

    print("")
    tx = aethirChecker.submitReports(submit_values, admin_sig, {"from": deployer})

    print("")
    deployer.transfer(to=deployer.address, amount=0)

    print("")
    #print(tx.events)
    print("BatchPassed", tx.events["BatchPassed"])
    print("BatchFailed", tx.events["BatchFailed"])


    print("")
    print ('aethirChecker.getReportsInRange(0, 100000000000000000000000)')
    print ('len(aethirChecker.getReportsInRange(0, 100000000000000000000000))')
    print("")
    print ('aethirChecker.getBatchesInRange(0, 100000000000000000000000)')
    print ('len(aethirChecker.getBatchesInRange(0, 100000000000000000000000))')

    #print(aethirChecker.totalReportsInRange(5555555555555555, 100000000000000000000000))
    #print (aethirChecker.getReportsInRange(0, 10000))
    #print(aethirChecker.at(0))

    print("")

    return aethirChecker

## deployer = getDeployer()
def getDeployer():
    return accounts[0]

## soph_test_0, soph_test_1, soph_test_2, soph_test_3, soph_test_4 = setup_test_accounts()
def setup_test_accounts():

    deployer = getDeployer()

    soph_test_0 = accounts.load("soph_test_0")
    deployer.transfer(to=soph_test_0.address, amount=10e18)

    soph_test_1 = accounts.load("soph_test_1")
    deployer.transfer(to=soph_test_1.address, amount=10e18)

    soph_test_2 = accounts.load("soph_test_2")
    deployer.transfer(to=soph_test_2.address, amount=10e18)

    soph_test_3 = accounts.load("soph_test_3")
    deployer.transfer(to=soph_test_3.address, amount=10e18)

    soph_test_4 = accounts.load("soph_test_4")
    deployer.transfer(to=soph_test_4.address, amount=10e18)

    return soph_test_0, soph_test_1, soph_test_2, soph_test_3, soph_test_4

def deploy(deployer=None, report_admin=None):

    if deployer is None:
        deployer = getDeployer()

    aethirCheckerImpl = AethirChecker.deploy({"from": deployer})
    aethirCheckerProxy = AethirCheckerProxy.deploy(aethirCheckerImpl, aethirCheckerImpl.initialize.encode_input(), {"from": deployer})
    aethirChecker = Contract.from_abi("aethirChecker", aethirCheckerProxy.address, aethirCheckerImpl.abi)

    if report_admin is None:
        aethirChecker.grantRole(aethirChecker.REPORT_ADMIN_ROLE(), deployer, {"from": deployer})
    else:
        aethirChecker.grantRole(aethirChecker.REPORT_ADMIN_ROLE(), report_admin, {"from": deployer})

    return aethirChecker

## submit_values, admin_sig = setup_test_data(aethirChecker)
def setup_test_data(aethirChecker, VERBOSE=False, soph_test_0=None, soph_test_1=None, soph_test_2=None, soph_test_3=None, soph_test_4=None):
    
    if soph_test_0 is None:
        soph_test_0, soph_test_1, soph_test_2, soph_test_3, soph_test_4 = setup_test_accounts()

    parings = {}
    parings["7ba0f58f7393f9ff64592dfe1449c826cf474be0"] = soph_test_1
    aethirChecker.registerClient("7ba0f58f7393f9ff64592dfe1449c826cf474be0", {"from": soph_test_1})

    parings["a97003be58e5fa268329b07275f9ff7fa2def95f"] = soph_test_2
    aethirChecker.registerClient("a97003be58e5fa268329b07275f9ff7fa2def95f", {"from": soph_test_2})

    parings["e0ae0110a8fed8fd095a0bd9bb17c07d1134df3b"] = soph_test_3
    aethirChecker.registerClient("e0ae0110a8fed8fd095a0bd9bb17c07d1134df3b", {"from": soph_test_3})

    parings["b9078b727ffdc5e6f0d31d3a2787c66698e7db04"] = soph_test_4
    aethirChecker.registerClient("b9078b727ffdc5e6f0d31d3a2787c66698e7db04", {"from": soph_test_4})

    raw_data = [
        [
            {"jobId":"ct1rurs693qtmjkjiat0","clientId":"7ba0f58f7393f9ff64592dfe1449c826cf474be0","licenseId":"85142","jobType":1,"jobTimeType":1,"epoch":60,"period":167,"reportTime":1732503600,"container":{"id":"3111122394","continues":0,"loss":30,"duration":0,"qualified":0}},
            {"jobId":"ct1rurs693qtmjk7d8h0","clientId":"a97003be58e5fa268329b07275f9ff7fa2def95f","licenseId":"74913","jobType":1,"jobTimeType":1,"epoch":60,"period":167,"reportTime":1732503600,"container":{"id":"3111122394","continues":1,"loss":30,"duration":0,"qualified":0}},
            {"jobId":"ct1rurs693qtmjk813b0","clientId":"e0ae0110a8fed8fd095a0bd9bb17c07d1134df3ba","licenseId":"12041","jobType":1,"jobTimeType":1,"epoch":60,"period":167,"reportTime":1732503600,"container":{"id":"3111122394","continues":0,"loss":30,"duration":0,"qualified":0}}, {"jobId":"ct1rurs693qtmjkieob0","clientId":"b9078b727ffdc5e6f0d31d3a2787c66698e7db04a","licenseId":"84520","jobType":1,"jobTimeType":1,"epoch":60,"period":167,"reportTime":1732503600,"container":{"id":"113135806","continues":0,"loss":30,"duration":0,"qualified":0}},
            {"jobId":"ct1rurs693qtmjkegi4g","clientId":"7ba0f58f7393f9ff64592dfe1449c826cf474be0a","licenseId":"56870","jobType":1,"jobTimeType":1,"epoch":60,"period":167,"reportTime":1732503600,"container":{"id":"113135806","continues":0,"loss":30,"duration":0,"qualified":0}}
        ],
        [
            {"jobId":"ct1rurs693qtmjklgc7g","clientId":"a97003be58e5fa268329b07275f9ff7fa2def95f","licenseId":"14505","jobType":1,"jobTimeType":1,"epoch":60,"period":167,"reportTime":1732503600,"container":{"id":"3000170705","continues":0,"loss":30,"duration":0,"qualified":0}},
            {"jobId":"ct1rurs693qtmjkin1mg","clientId":"e0ae0110a8fed8fd095a0bd9bb17c07d1134df3b","licenseId":"74741","jobType":1,"jobTimeType":1,"epoch":60,"period":167,"reportTime":1732503600,"container":{"id":"3000170705","continues":0,"loss":30,"duration":0,"qualified":0}}
        ],
        [
            {"jobId":"ct1rurs693qtmjkcfre0","clientId":"b9078b727ffdc5e6f0d31d3a2787c66698e7db04","licenseId":"8064","jobType":1,"jobTimeType":1,"epoch":60,"period":167,"reportTime":1732503600,"container":{"id":"211331516","continues":0,"loss":30,"duration":0,"qualified":0}},
            {"jobId":"ct1rurs693qtmjkldavg","clientId":"7ba0f58f7393f9ff64592dfe1449c826cf474be0","licenseId":"10672","jobType":1,"jobTimeType":1,"epoch":60,"period":167,"reportTime":1732503600,"container":{"id":"211331516","continues":0,"loss":30,"duration":0,"qualified":0}},
            {"jobId":"ct1rurs693qtmjkfhfj0","clientId":"a97003be58e5fa268329b07275f9ff7fa2def95f","licenseId":"77060","jobType":1,"jobTimeType":1,"epoch":60,"period":167,"reportTime":1732503600,"container":{"id":"211331516","continues":0,"loss":30,"duration":0,"qualified":0}},
            {"jobId":"ct1rurs693qtmjk7ud3g","clientId":"e0ae0110a8fed8fd095a0bd9bb17c07d1134df3b","licenseId":"48471","jobType":1,"jobTimeType":1,"epoch":60,"period":167,"reportTime":1732503600,"container":{"id":"211331516","continues":0,"loss":30,"duration":0,"qualified":0}}
        ]
    ]


    submit_values = []
    for b in raw_data:
        if VERBOSE: print(b)
        row_array = []
        for r in b:
            if VERBOSE: print(r);
            container_data = encode(["uint256", "uint256", "uint256"], [r["container"]["continues"], r["container"]["loss"], r["container"]["duration"]]).hex()
            if VERBOSE: print("container_data", container_data)
            try:
                paring_to_client = parings[r["clientId"]]
            except:
                paring_to_client = soph_test_0 ## non-authorized client
            row_array.append(
                (
                    r["jobId"],
                    r["clientId"],
                    r["licenseId"],
                    r["epoch"],
                    r["period"],
                    r["reportTime"],
                    r["container"]["id"],
                    r["jobType"],
                    container_data,
                    generate_client_signature(aethirChecker, paring_to_client, r["clientId"], chain.time() + 60*60*24)
                )
            )
        submit_values.append(row_array)

    admin_sig = generate_admin_signature(aethirChecker, soph_test_0, aethirChecker.nonces(soph_test_0), chain.time() + 60*60*24)

    return submit_values, admin_sig


def get_domain_separator(verifying_contract_address):
    chain_id = chain.id  # Set your chain ID here
    text = encode(
        ["bytes32", "bytes32", "bytes32", "uint256", "address"],
        [
            Web3.solidity_keccak(["string"], ["EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"]),
            Web3.solidity_keccak(["string"], ["AethirChecker"]),
            Web3.solidity_keccak(["string"], ["1"]),
            chain_id,
            verifying_contract_address
        ]
    )
    
    return Web3.keccak(text)

def get_admin_struct_hash(signer, nonce, deadline):
    typehash = Web3.solidity_keccak(
        ["string"],
        ["AethirReportAdmin(address signer,uint256 nonce,uint256 deadline)"]
    )
    #print("admin typehash", typehash.hex())
    
    # Correctly encode the parameters before hashing
    encoded_data = encode(
        ["bytes32", "address", "uint256", "uint256"],
        [
            typehash,
            signer,
            nonce,
            deadline
        ]
    )
    struct_hash = Web3.keccak(encoded_data)
    return struct_hash

def get_client_struct_hash(signer, clientId, deadline):
    typehash = Web3.solidity_keccak(
        ["string"],
        ["AethirReportClient(address signer,string clientId,uint256 deadline)"]
    )
    #print("client typehash", typehash.hex())
    
    # Correctly encode the parameters before hashing
    encoded_data = encode(
        ["bytes32", "address", "string", "uint256"],
        [
            typehash,
            signer,
            clientId,
            deadline
        ]
    )
    struct_hash = Web3.keccak(encoded_data)
    #print("client struct_hash", struct_hash.hex())
    return struct_hash

def get_message_hash(domain_separator, struct_hash):
    prefix = b'\x19\x01'
    return Web3.solidity_keccak(
        ["bytes", "bytes32", "bytes32"],
        [prefix, domain_separator, struct_hash]
    )

def sign_message(message_hash, private_key):
    account = Account.from_key(private_key)
    signature = account.signHash(message_hash)
    #return signature.v, signature.r, signature.s
    return signature.signature

def generate_admin_signature(checker_contract, signer_account, nonce, deadline):
    #print(signer_account, nonce, deadline)
    domain_separator = get_domain_separator(checker_contract.address)
    #print(domain_separator)
    struct_hash = get_admin_struct_hash(
        signer_account.address, # signer
        nonce, # nonce,
		deadline # deadline
    )
    #print(struct_hash)
    message_hash = get_message_hash(domain_separator, struct_hash)
    #v, r, s = sign_message(message_hash, signer_account.private_key)
    signature = sign_message(message_hash, signer_account.private_key)
    #print("signature", signature.hex())

    return encode(
        ["address", "uint256", "uint256", "bytes"],
        [signer_account.address, nonce, deadline, signature]
	)

def generate_client_signature(checker_contract, signer_account, clientId, deadline):
    domain_separator = get_domain_separator(checker_contract.address)
    #print("domain_separator", domain_separator)
    struct_hash = get_client_struct_hash(
        signer_account.address, # signer
        clientId, # clientId,
		deadline # deadline
    )
    message_hash = get_message_hash(domain_separator, struct_hash)
    #v, r, s = sign_message(message_hash, signer_account.private_key)
    signature = sign_message(message_hash, signer_account.private_key)

    return encode(
        ["address", "string", "uint256", "bytes"],
        [signer_account.address, clientId, deadline, signature]
	)

