router:
	sudo python nat64/router.py -c nat64/router.conf

node:
	sudo python nat64/dummy_func.py $(arg1)