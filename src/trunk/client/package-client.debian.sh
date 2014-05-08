#!/bin/bash

workdir="/tmp/building/snowman-client/"
echo "Using $workdir as a working-directory."

# Create workdir, and copy source there.
mkdir -p $workdir
cp -r * $workdir

# Delete all the subversion files from the source, as we do not want them 
#   in the final package.
find $workdir -name ".svn" -exec rm -rf {} \; &> /dev/null

# Grab some variables from the configfile
packagename=`grep Package $workdir/DEBIAN/control | cut -d ' ' -f 2`
packageversion=`grep Version $workdir/DEBIAN/control | cut -d ' ' -f 2`

# Build the package
fakeroot dpkg -b $workdir ARCHIVES/$packagename-$packageversion.deb

# Clean the working directory
rm -rf $workdir
