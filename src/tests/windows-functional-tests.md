# Running the Binary Toolkit Functional Tests on Windows
This document will provide information about how to run the functional tests
for the Binary Toolkit in a Windows environment, under multiple versions of Python.

These instructions assume you already have the Binary Toolkit sources present
locally.  If not, they can be checked out from GitHub using the URL
https://github.com/carbonblack/cbc-binary-toolkit; doing so will require you to
have a Windows-compatible version of Git installed.

### Install Windows Update where required
Windows 7 and 8, as well as Windows Server 2008 and 2012, require a patch to enable
secure protocols TLS 1.1 and TLS 1.2.  Information about this may be found
[here](https://support.microsoft.com/en-us/help/3140245/update-to-enable-tls-1-1-and-tls-1-2-as-default-secure-protocols-in-wi),
and the associated Windows Knowledge Base identifier is `KB3140245`.  Install
the update as given in that article (which may be downloaded through the Microsoft
Update Catalog), and apply the changes required to the Registry as documented.
Reboot after these changes are made.

### Install Python
From http://python.org, download the installers for the most recent Python
3.6, 3.7, and 3.8 versions (as of this writing, versions 3.6.8, 3.7.7, and 3.8.3).
Install the 3.6 Python first, then 3.7, and then 3.8.

### Make a CurrentVersion Link
Using an _elevated_ command prompt,  go to the `AppData\Local\Programs\Python`
subdirectory under your user profile directory (usually `C:\Users\username`).
Then use the command:

```
mklink /D CurrentVersion Python38
```

(**N.B.:** This is only guaranteed to work if your `C:` drive uses the NTFS
filesystem.  This will almost always be the case.)

### Fix the Execution PATH
Go to the Environment Variables dialog (System Control Panel or Properties page
for My Computer/This PC, then select **Advanced system settings** and then the
**Environment Variables...** button). Ensure that the first two components of
the user PATH environment variable are `%USERPROFILE%\AppData\Local\Programs\Python\CurrentVersion`
and `%USERPROFILE%\AppData\Local\Programs\Python\CurrentVersion\Scripts`.  In particular,
both of these must be before any `WindowsApps` directory.

To test this, open a command window and use the command `python --version`. It should
show that you are running Python 3.8.

### Install Visual C++ Build Tools
This is a prerequisite for one of the libraries that will be installed for the Binary Toolkit.
Visit https://visualstudio.microsoft.com/visual-cpp-build-tools/ for the installer. 

### Install Toolkit Requirements
From the top-level Binary Toolkit source directory, execute the following commands:

```
pip install -r requirements.txt
pip install .
```

This will ensure that all required scripts are installed.

### Set Necessary Environment Variable
You will need to set the `CBC_AUTH_TOKEN` environment variable to the authentication
token you will be using to access the Carbon Black Cloud.  This is done with a command
such as:

```
set CBC_AUTH_TOKEN=Z123456789ABCDEFGHIJKLMN/ABCDEFGHIJ
```

It is a good idea to put this command in a batch file that you can use to set the
environment variable without haveing to type or copy it each time.

### Execute the Functional Tests
From the top-level Binary Toolkit source directory, execute the following command:

```
bin\func_tests.bat
```

The tests should return that they all completed successfully.

### Changing Python Versions
Using an Explorer window, visit the `AppData\Local\Programs\Python` subdirectory
under your user profile directory (usually `C:\Users\username`). Delete the existing
`CurrentVersion` link.

Then, using an _elevated_ command prompt,  go to the `AppData\Local\Programs\Python`
subdirectory under your user profile directory (usually `C:\Users\username`).
Then use the command:
      
```
mklink /D CurrentVersion (desired-subdirectory)
```
      
where _(desired-subdirectory)_ is the Python subdirectory you wish to use, either
`Python36`, `Python37`, or `Python38`.

After doing this, check to make sure the change is valid by opening a new command
prompt window and running the command `python --version`. It should show a Python
version number consistent with the link you made.

After doing this, you will have to perform the steps under "Install Toolkit Requirements"
(above) to properly prepare the required libraries and scripts in the new Python version.