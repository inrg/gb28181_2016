#include "algorithm.h"

static void CvtHex(HASH Bin, HASHHEX Hex)
{
	unsigned short i;
	unsigned char j;
	for (i = 0; i < HASHLEN; i++)
	{
		j = (Bin[i] >> 4) & 0xf;
		if (j <= 9)
			Hex[i * 2] = (j + '0');
		else
			Hex[i * 2] = (j + 'a' - 10);
		j = Bin[i] & 0xf;
		if (j <= 9)
			Hex[i * 2 + 1] = (j + '0');
		else
			Hex[i * 2 + 1] = (j + 'a' - 10);
	};
	Hex[HASHHEXLEN] = '\0';
}
void DigestCalcHA1(const char *pszAlg, const char *pszUserName,
	const char *pszRealm, const char *pszPassword,
	const char *pszNonce, const char *pszCNonce,
	HASHHEX SessionKey)
{
	osip_MD5_CTX Md5Ctx;
	HASH HA1;
	osip_MD5Init(&Md5Ctx);
	osip_MD5Update(&Md5Ctx, (unsigned char *) pszUserName, strlen(pszUserName));
	osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	osip_MD5Update(&Md5Ctx, (unsigned char *) pszRealm, strlen(pszRealm));
	osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	osip_MD5Update(&Md5Ctx, (unsigned char *) pszPassword, strlen(pszPassword));
	osip_MD5Final((unsigned char *) HA1, &Md5Ctx);
	if ((pszAlg != NULL) && strcmp(pszAlg, "md5-sess") == 0)
	{
		osip_MD5Init(&Md5Ctx);
		osip_MD5Update(&Md5Ctx, (unsigned char *) HA1, HASHLEN);
		osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
		osip_MD5Update(&Md5Ctx, (unsigned char *) pszNonce, strlen(pszNonce));
		osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
		osip_MD5Update(&Md5Ctx, (unsigned char *) pszCNonce, strlen(pszCNonce));
		osip_MD5Final((unsigned char *) HA1, &Md5Ctx);
	}
	CvtHex(HA1, SessionKey);
}
void DigestCalcResponse(HASHHEX HA1, const char *pszNonce,
	const char *pszNonceCount, const char *pszCNonce,
	const char *pszQop, int Aka, const char *pszMethod,
	const char *pszDigestUri, HASHHEX HEntity, HASHHEX Response)
{
	osip_MD5_CTX Md5Ctx;
	HASH HA2;
	HASH RespHash;
	HASHHEX HA2Hex;
	/* calculate H(A2) */
	osip_MD5Init(&Md5Ctx);
	osip_MD5Update(&Md5Ctx, (unsigned char *) pszMethod, strlen(pszMethod));
	osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	osip_MD5Update(&Md5Ctx, (unsigned char *) pszDigestUri,
		strlen(pszDigestUri));
	if (pszQop == NULL)
	{
		goto auth_withoutqop;
	}
	else if (0 == strcmp(pszQop, "auth-int"))
	{
		goto auth_withauth_int;
	}
	else if (0 == strcmp(pszQop, "auth"))
	{
		goto auth_withauth;
	}
auth_withoutqop: osip_MD5Final((unsigned char *) HA2, &Md5Ctx);
	CvtHex(HA2, HA2Hex);
	/* calculate response */
	osip_MD5Init(&Md5Ctx);
	osip_MD5Update(&Md5Ctx, (unsigned char *) HA1, HASHHEXLEN);
	osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	osip_MD5Update(&Md5Ctx, (unsigned char *) pszNonce, strlen(pszNonce));
	osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	goto end;
auth_withauth_int:
	osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	osip_MD5Update(&Md5Ctx, (unsigned char *) HEntity, HASHHEXLEN);
auth_withauth: osip_MD5Final((unsigned char *) HA2, &Md5Ctx);
	CvtHex(HA2, HA2Hex);
	/* calculate response */
	osip_MD5Init(&Md5Ctx);
	osip_MD5Update(&Md5Ctx, (unsigned char *) HA1, HASHHEXLEN);
	osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	osip_MD5Update(&Md5Ctx, (unsigned char *) pszNonce, strlen(pszNonce));
	osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	if (Aka == 0)
	{
		osip_MD5Update(&Md5Ctx, (unsigned char *) pszNonceCount, strlen(
			pszNonceCount));
		osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
		osip_MD5Update(&Md5Ctx, (unsigned char *) pszCNonce, strlen(pszCNonce));
		osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
		osip_MD5Update(&Md5Ctx, (unsigned char *) pszQop, strlen(pszQop));
		osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	}
end: osip_MD5Update(&Md5Ctx, (unsigned char *) HA2Hex, HASHHEXLEN);
	osip_MD5Final((unsigned char *) RespHash, &Md5Ctx);
	CvtHex(RespHash, Response);
} 
