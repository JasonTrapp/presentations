#!/bin/bash
echo "$(date -Is) login user=${PAM_USER} rhost=${PAM_RHOST} service=${PAM_SERVICE}" >> /var/log/pam_marker.log
echo "demo marker showing pam_exec fired at $(date -Is)" > "/home/${PAM_USER}/DEMO_pam_exec.txt" 2>/dev/null

