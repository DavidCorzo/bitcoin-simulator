import random
import json
import os
import subprocess
import threading
import time



entrypoint = "learncoin-cli -regtest"
wallet_quantity = 5

execute_opt = os.system

def execute_and_collect_output(commands):
    result = subprocess.run(commands, shell=True,stdout=subprocess.PIPE)
    return result.stdout.decode('utf-8')

wallets = {
    ("w{}".format(wallet_num)):[] for wallet_num in range(wallet_quantity)
}

def create_wallets_and_addresses(wallet_dict):
    for wallet_name, list in wallet_dict.items():
        execute_opt("{} createwallet {}".format(entrypoint, wallet_name))
        execute_opt("{} -rpcwallet={} getnewaddress".format(entrypoint, wallet_name))
        output = execute_and_collect_output(
            "{} -rpcwallet={} listreceivedbyaddress 1 true".format(entrypoint, wallet_name)
        )
        wallet_addresses = json.loads(output)
        wallet_dict[wallet_name] += wallet_addresses
        

create_wallets_and_addresses(wallets)

# with open('wallets.json', 'w') as fp:
#     json.dump(wallets, fp)

def getbalance(wallet_name):
    return float(execute_and_collect_output("{} -rpcwallet={} getbalance".format(entrypoint, wallet_name)))

def mine_balance(wallet_name, wallet_address):
    while True:
        current_balance = getbalance(wallet_name)
        print(current_balance)
        if current_balance:
            return current_balance
        execute_opt("{} generatetoaddress 100 {}".format(entrypoint, wallet_address))
        time.sleep(1)

def miner():
    execute_opt("while true; do {} generate 1; sleep 5; done".format(entrypoint))
    
miner_thread = threading.Thread(target=miner)
miner_thread.start()

fee_rate = 10
while True:
    sender_wname = "w{}".format(random.randint(0, wallet_quantity-1))
    sender_addr = wallets[sender_wname][0]['address']
    sender_balance = getbalance(sender_wname)
    if not sender_balance: # it is 0
        sender_balance = mine_balance(sender_wname, sender_addr)
    receiver_wname = "w{}".format(random.randint(0, wallet_quantity-1))
    receiver_addr = wallets[receiver_wname][0]['address']
    execute_opt("{} -rpcwallet={} -named sendtoaddress address={} amount={}".format(entrypoint, sender_wname, receiver_addr, sender_balance))
    print("txs from {} to {}".format(sender_wname, receiver_wname))


    

