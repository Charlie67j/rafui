# RAFUI = Run After Fresh Ubuntu Install

Script to run on fresh Ubuntu installation to do the following:
1. Update the system with the latest patches
2. Install Open-SSH Server
3. Enable UFW and allow OpenSSH
4. Disable root login
5. Setup an SSH login message that shows current system status
6. Setup automatic security updates for unattended installation
7. Install and configure Fail2Ban (maxretry 4)
8. Install Speedtest CLI tool
9. Setup SFTP server that runs over SSH
10. Option to install Docker with Portainer
11. Option to install WireGuard VPN Server



If you created a non-root user as part of the setup, you can move on. If not, first create a non-rute user and add them to the sudo group like this. Be sure to replace "newusername" with the actual user name that you wish to create. 
1. From the root termianl issue the following command:  adduser newusername
2. Fill out the information, the password is the only important part. 
3. Next add the new user to the sudo group using this command:  usermod -aG sudo newusername
4. Now you can switch to the new user by issuing this command: su newusername
5. Finally, if you issue this command, you will go to your new home directory: cd ~/

To use this script, after installing a fresh Ubuntu Server, run this command as a non-root user:
wget https://raw.githubusercontent.com/Charlie67j/rafui/master/ubuntu_fresh_install.sh && chmod 755 ubuntu_fresh_install.sh && ./ubuntu_fresh_install.sh

