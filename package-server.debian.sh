#!/bin/bash

workdir="/tmp/building/snowman-server/"
echo "Using $workdir as a working-directory."

binpath=$workdir"usr/bin/"
configpath=$workdir"etc/snowman/"
sharepath=$workdir"usr/share/snowman/"
varpath=$workdir"var/snowman/"

# Create workdir, and copy source there.
mkdir -p $workdir
mkdir -p $configpath
mkdir -p $binpath
mkdir -p $sharepath
mkdir -p $varpath
mkdir -p /etc/apache2/sites-available/

cp -r server/DEBIAN $workdir

cp -r server/bin/* $binpath
cp -r server/core $sharepath
cp -r server/srm $sharepath
cp -r server/tests $sharepath
cp -r server/tuning $sharepath
cp -r server/update $sharepath
cp -r server/util $sharepath
cp -r server/web $sharepath
cp server/manage.py $sharepath
cp server/etc/settings.cfg $configpath"snowman.conf"
cp server/etc/apache.conf /etc/apache2/sites-available/snowman.conf

# Delete all the subversion files from the source, as we do not want them 
#   in the final package.
find $workdir -name ".svn" -exec rm -rf {} \; &> /dev/null

# Build the package
cp $workdir"DEBIAN/control.ubuntu" $workdir"DEBIAN/control"
packagename=`grep Package $workdir/DEBIAN/control | cut -d ' ' -f 2`
packageversion=`grep Version $workdir/DEBIAN/control | cut -d ' ' -f 2`
fakeroot dpkg -b $workdir ARCHIVES/$packagename-$packageversion.deb
cp $workdir"DEBIAN/control.debian" $workdir"DEBIAN/control"
packagename=`grep Package $workdir/DEBIAN/control | cut -d ' ' -f 2`
packageversion=`grep Version $workdir/DEBIAN/control | cut -d ' ' -f 2`
fakeroot dpkg -b $workdir ARCHIVES/$packagename-$packageversion.deb

# Clean the working directory
rm -rf $workdir
