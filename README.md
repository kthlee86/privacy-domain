The following are the codes that were used for the evaluation for the paper, "Bootstrapping Privacy Services in Today's Internet." (TBD: Link to follow)

Required Environment:
	- DPDK supported Hardware
	- Intel processor that supports the AES-NI instruction set.
	- Linux Operating System

Required Libraries:
	- DPDK Release 17.02 (https://core.dpdk.org/download/)
	- Intel(R) Multi-Buffer Crypto for IPsec (https://github.com/intel/intel-ipsec-mb)

Step.1 Build DPDK Library
	- Follow the instructions at https://doc.dpdk.org/guides/linux_gsg/build_dpdk.html

Step.2 Install Intel(R) Multi-Buffer Crypto for IPsec
	- Follow the instruction in the REAME file at https://github.com/intel/intel-ipsec-mb

Step.3 Setup Linux Environment to run DPDK applications.
	- export RTE_SDK=$HOME/DPDK
	- export RTE_APP=$(HOME)/DPDK/examples
	- export RTE_TARGET=x86_64-native-linuxapp-gcc
	- export AESNI_MULTI_BUFFER_LIB_PATH=$HOME/intel-ipsec-mb-0.44

****[Running NAT evaluation (Figure 3 in [1])]****

* We extended the l3fwd application in the DPDK Library for this evaluation.

Step.4 Copy 'nat_eval' directory to $RTE_APP/.
	- cp -r nat_eval $RTE_APP/.

Step.5 Build the library for Cipher Block Chaining (CBC) mode based on AES
	- cd $RTE_APP/nat_eval/enc_lib/ff3/lib; sh mk_lnx_lib.sh; cd ../../..;

Step.6 Build the l3fwd application
	- make

Step.7 Run the NAT application.
	- run.sh has a sample command that we used to run the applications; however, the arguments must be adjusted based on your environment.
	- For Parameter configurations:
		- EAL Options: https://doc.dpdk.org/guides-17.02/testpmd_app_ug/run_app.html
		- App-specific Options: https://doc.dpdk.org/guides-17.02/sample_app_ug/l3_forward.html

Step.8 Generate Traffic
	- Generate traffic with traffic generator. For each packet:
		- Use random source addresses and destination addresses to maximize cache misses to measure worst-case performance.
		- Vary frame sizes accordingly
			- 64B, 128B, 256B, 512B, 1024B, 1518B, iMIX (7 64B frames, 4 596B frames, 1 1518B frames)

****[Running ipsec evaluation (Figure 4 in [1])]****

* We used the ipsec-secgw application in the DPDK Library for this evaluation.

Step.4 Copy 'ipsec_eval' directory to $RTE_APP/.
	- cp -r ipsec_eval $RTE_APP/.

Step.6 Build the ipsec-secgw application
	- make

Step.7 Run the ip_sec application.
	- run.sh has a sample command that we used to run the applications; however, the arguments must be adjusted based on your environment.
	- For Parameter configurations, check the following:
		- EAL Options: https://doc.dpdk.org/guides-17.02/testpmd_app_ug/run_app.html
		- App-specific Options: https://doc.dpdk.org/guides-17.02/sample_app_ug/ipsec_secgw.html

Step.8 Generate Traffic
	- Generate traffic with a traffic generator. For each packet:
		- Use random destination address to ensure that a different IPsec SA would be chosen for each packet.
		- Vary frame sizes to measure performance for different packet sizes:
			- In our expirement, we used the following Ethernet Frame sizes:
				- 64B, 128B, 256B, 512B, 1024B, 1456B, iMIX (7 64B frames, 4 596B frames, 1 1456B frames)
				- Note that we cannot use 1518B (i.e., max-size) frames, due to packet encapsulation.
		- Note that generated packets must be sent to the "Protected ports." See DPDK documentation for the ipsec application for more information about "Protected Ports" (https://doc.dpdk.org/guides-17.02/sample_app_ug/ipsec_secgw.html)

[1] Taeho Lee, Christos Pappas, Adrian Perrig, "Boostrapping Privacy Services in Today's Internet," 2018.
