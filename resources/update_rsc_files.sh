#!/bin/sh
#-----------------------------------------------------------------------------
#
# Script used to update squidanalyzer resources files.
# The script must be run in the resources directory.
#
# Files are minified using yui-compressor.
#-----------------------------------------------------------------------------

# Create the temporary directory 
mkdir orig/ 2>/dev/null
rm flotr2.js

# Get sorttable.js file
wget https://kryogenix.org/code/browser/sorttable/sorttable.js -O orig/sorttable.js

# SquidAnalyzer use a modified version of the library, apply patch
patch -p 1 orig/sorttable.js < sa-sorttable.diff

yui-compressor orig/sorttable.js -o orig/sorttable.min.js

# Update the flotr2.js script
wget https://raw.githubusercontent.com/HumbleSoftware/Flotr2/master/flotr2.nolibs.js -O orig/flotr2.nolibs.js

yui-compressor orig/flotr2.nolibs.js -o orig/flotr2.min.js

# Update the bean.js script
wget https://github.com/fat/bean/archive/v1.0.14.tar.gz
tar xzf v1.0.14.tar.gz  bean-1.0.14/src/bean.js
cp bean-1.0.14/src/bean.js orig/
rm -rf bean-1.0.14/
rm v1.0.14.tar.gz

yui-compressor orig/bean.js -o orig/bean.min.js

# Update underscore.js
wget http://underscorejs.org/underscore.js -O orig/underscore.js

yui-compressor orig/underscore.js -o orig/underscore.min.js

cat squidanalyzer.js >> flotr2.js
echo "/* bean.min.js: see https://github.com/darold/squidanalyzer/tree/master/resources/LICENSE */" >> flotr2.js
cat orig/bean.min.js >> flotr2.js
echo "/* underscore.min.js: see https://github.com/darold/squidanalyzer/tree/master/resources/LICENSE */" >> flotr2.js
cat orig/underscore.min.js >> flotr2.js
echo "/* flotr2.min.js: see https://github.com/darold/squidanalyzer/tree/master/resources/LICENSE */" >> flotr2.js
cat orig/flotr2.min.js >> flotr2.js

cp orig/sorttable.min.js sorttable.js

# Remove temporary directory
rm -rf orig/


