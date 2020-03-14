install: 
	bash ./install.sh
dist: 
	python setup.py sdist bdist_wheel

clean : 
	rm -rf dist/ build/ *.egg-info
