/*
 * pam_modules that resolves numeric rhost to name
 * 
 * Use case is when the application does not resolve hostnames themself
 * 
 * Only rudimentary error handling, missing debug and address family
 *
 * License: GPL 2+
 *
 */

#include <netdb.h>
#include <stddef.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#include <security/pam_modules.h>

int resolve_rhost(pam_handle_t *pamh, 	 
	int flags, 	 
	int argc, 	 
	const char **argv)
{
int retval;
const char *rhost = NULL;
struct addrinfo *res = NULL;
struct addrinfo hints = {
AI_NUMERICHOST,
AF_UNSPEC,
0,
0,
0, NULL, NULL, NULL
};
char host[NI_MAXHOST];

if ((retval = pam_get_item (pamh, PAM_RHOST, (const void **) &rhost)) != PAM_SUCCESS)
	return retval;

if (getaddrinfo(rhost, NULL, &hints, &res)) 
	return PAM_SUCCESS;

retval = getnameinfo(res->ai_addr, res->ai_addrlen, host, NI_MAXHOST, NULL, 0, NI_NAMEREQD);
freeaddrinfo(res);

if (retval)
	return PAM_SUCCESS;

return pam_set_item(pamh, PAM_RHOST, host);
}


PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, 	 
	int flags, 	 
	int argc, 	 
	const char **argv)
{
return resolve_rhost(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t	*pamh, 	 
	int flags, 	 
 	int argc, 	 
 	const char **argv)
{
return resolve_rhost(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, 	 
	int flags, 	 
 	int argc, 	 
 	const char **argv)
{
	return (PAM_SUCCESS);
}
