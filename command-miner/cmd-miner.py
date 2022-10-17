import os


idle_time = 300
blocks_to_gen = 1
os.system("while true; do learncoin-cli -regtest generate {}; sleep {}; done".format(blocks_to_gen, idle_time))