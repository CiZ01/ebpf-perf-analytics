TARGET = nat64


router:
	sudo python nat64/nat64.py -c nat64/router.conf

node:
	sudo python nat64/dummy_func.py $(arg1)