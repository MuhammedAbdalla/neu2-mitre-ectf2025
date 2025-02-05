## Normally, this would be straight forward, 
## but packages are not installing correctly on my wsl environment
## bascially goes as follows
'''
MUST DO ONCE: install the tools & design packages via pip install
1. generate secrets
2a. generate subscriptions
2b. subscribe decoder to channel
3. launch uplink
4. launch satellite
5. lauch TV
'''



# # install packages
# python3 -m pip install ./tools/
# python3 -m pip install -e ./design/

# generate subscription files
CHANNELS=(1 2 3 4)
DECODER_ID=0xDEADBEEF
START_TIME=0
END_TIME=128


# generate a subcription file per channel & upload to decoder
for channel in ${CHANNELS[@]}; do
    python3 -m ectf25_design.gen_subscription secrets/secrets.json "subscriptions/sub_$channel.bin" $DECODER_ID $START $END $channel
    python3 -m ectf25.tv.subscribe "subscriptions/sub_$channel.bin" COM3
done


python3 -m ectf25.uplink ./secrets/secrets.json localhost 2100 1:1:frames/x_c0123.json

python3 -m ectf25.satellite localhost 2100 localhost 1:2001 2:2002 3:2003 &

python3 -m ectf25.tv.run localhost 2001 COM3