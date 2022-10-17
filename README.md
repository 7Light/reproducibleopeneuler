# reproducibleopeneuler
These tools are intended to make it easier to verify that the binaries resulting from openEuler builds are reproducible.

For this, we rebuild twice locally from source with variations in

date
hostname

within opensource libfaketime.
and compare the results using the build-compare script (diffoscope) that abstracts away some unavoidable (or unimportant) differences.
