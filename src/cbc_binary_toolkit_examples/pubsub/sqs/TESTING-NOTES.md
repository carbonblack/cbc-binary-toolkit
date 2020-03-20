# Notes on Testing

In order to run the unit tests for the builtin PubSub provider, you will need to have
[LocalStack](https://github.com/localstack/localstack) installed and running.

## Standard Install

The standard installation of LocalStack requires Docker.  On Mac and Linux systems, you can
install LocalStack this way, then start it normally with the `localstack start` command.
It will expose the various LocalStack services as ports on `localhost` where the test code
can find them.

## Windows VM Install

On Windows, Docker Desktop, when installed, changes the configuration of the system such that
existing virtualization services, such as VMware Workstation and VirtualBox, will no longer
function.  If this is not desired, an alternative mechanism can be used.

Set up a Linux VM which has a host-only network interface in addition to its standard NAT
interface.  Install LocalStack on this VM with all dependencies, to include `make` , `npm` ,
Java 8 JDK, and Maven, as given in the LocalStack documentation.

Note the IP address assigned to the host-only interface on this VM.  Start LocalStack running
on the VM with the command `HOSTNAME_EXTERNAL=$(address) localstack start --host` , where
`$(address)` is the IP address of the host-only interface.

Before running `pytest` on the Windows side, set the environment variable `SQS_TEST_SERVER_ADDR`
to be that same IP address.
