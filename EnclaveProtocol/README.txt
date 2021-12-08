### Steps to compile this project ###

A prerequisite for the successful building of this project is to have a working
intel sgxsdk installed in this folder.
Either do so using the install.sh script or you have to modify the sdk path
in both makefiles of the Enclaves.

To build this project in simulation mode, i.e. both the Enclave and App binaries,
you can just execute the build.sh shellscript in this folder.

This will do nothing more than cd into the respective Enclave folder and run 
then in order a make clean and make SGX_MODE=SIM.
Doing so builds all the neccessary binaries and makes them executable.

### Steps to run this project ###

Similarly to building this project running the run.sh is all that is neccessary.

This script will similarly cd into the correct Enclave folders and run the previously
created binaries. It does so for both Enclaves simultaniously as this is required by them.

Further it will gather their output and colorcode the one by App and Enclave A in green
for ease of use.

After running and before inspecting the source code one can run clean.sh to get rid
of all automatically created files.

### Style in which the different blocks of the exercise are surounded ###
//use this to mark code regions as specified in the assignment sheet
/*************************
 * BEGIN [region that you're annotating, e.g. E_B decrypt challenge]
 *************************/
 <your code here>
/*************************
 * END [region that you're annotating, e.g. E_B decrypt challenge]
 *************************/

