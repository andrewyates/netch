netch
======
netch is a utility for monitoring a system's internet connection status (not just whether or not it has an IP)

netch checks the internet connection by attempting to SSH to a known host and verifying that the
host key received matches a known-good value. It is best used on Debian-based systems in conjunction with scripts in if-down.d and if-up.d. In this scenario, the up and down scripts notify netch when the interface is up in order to minimize unnecessary checks. 

Configuration
=============
See config.sample for a full list of config options.

- check_when_online: whether or not to repeatedly checking the connection status when online
- online_hook: list of commands to run after coming online
- offline_hook: list of commands to run after going offline

Signals
=======
- SIGUSR1: signal interface down, causing netch to pause connection checks
- SIGUSR2: signal interface up, causing netch to reset the connection status and resume checks
- SIGHUP: reload the config file

License
=======
netch is available under the GNU General Public License v2, or (at your option) any later version.
