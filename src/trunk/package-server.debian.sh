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
mkdir -p $workdir"etc/apache2/sites-available/"
mkdir -p $workdir"etc/init.d/"
mkdir -p $workdir"etc/logrotate.d/"

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
cp server/etc/settings.cfg $configpath"snowman.config.template"
cp server/etc/apache.conf $workdir"etc/apache2/sites-available/snowman.conf"
cp server/etc/snowmand.initd $workdir"etc/init.d/snowmand"
cp server/etc/snowman.logrotate $workdir"etc/logrotate.d/snowman"

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
