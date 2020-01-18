#!/usr/bin/env bash

[ -z `which python3` ] && echo 'Could not find python3 binary.' && exit
[ -z `which pip3` ] && echo 'Could not find pip3 binary.' && exit
[ -z `which virtualenv` ] && echo 'Could not find virtualenv binary.' && exit

# clone repo and install dependencies
virtualenv -p python3 .venv && . .venv/bin/activate
pip3 install -r requirements.txt && deactivate

# link project as alias
py="`pwd`/.venv/bin/python3"
vmrun="`pwd`/vmrun.py"
os=`uname -a | awk '{print $1}'`
profile=`[ $os == 'Linux' ] && echo '.profile'`
profile=`[ $os == 'Darwin' ] && echo '.bash_profile'`

echo >> ~/$profile
echo '### vmrun' >> ~/$profile
echo "alias vmrun='$py $vmrun'" >> ~/$profile

# config
cp config_sample.json ~/.vmrun_config.json