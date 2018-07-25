sudo ./build/ipsec-secgw -c 0xff -n 4 --vdev="crypto_aesni_gcm,socket_id=0" -- -p 0xf -P -u 0x2 --config="(3,0,1),(3,1,2),(3,2,3),(3,3,4),(1,4,5)" -f ep.cfg
