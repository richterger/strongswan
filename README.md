#My patches for strongswan

Available branches:

##xauth_radius



    xauth-radius plugin. Supports xauth authentication via radius without using EAP.

    Also supports Challenge/Response Authentication, in case radius server
    answers with ACCESS_CHALLENGE.
    Usese the same configuration scheme as eap-radius, but does not support accounting


##id_user_fqdn

allows to specify an ID as @@<id> to force ID_USER_FQDN, instead of ID_FQDN

Example: leftid="@@my-id"                             


##LICENSE

All patches are published under the same license as strongswan itself (GPL V2 or later).
See LICENSE file for details.
