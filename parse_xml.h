/*
* Copyright (c) 2016, Spreadtrum Communications.
*
* The above copyright notice shall be
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef KEYMASTER_PARSE_XML_H_
#define KEYMASTER_PARSE_XML_H_

#pragma once

#define ATTEST_ECC_DATA_MASK 0x2000
#define ATTEST_RSA_DATA_MASK 0x3000
#define CERT_FILE_NAME  "TrustyCertChains.xml"
#define nullptr (void*)0

typedef enum xml_elems_{
	ELEMS_XML_VERSION=0,
	ELEMS_KEYBOXS_NUM,
	ELEMS_DEVICE_ID,

	ELEMS_ECC_KEY_ALGO,
	ELEMS_ECC_KEY_FORMAT,
	ELEMS_ECC_PRIV_KEY,
	ELEMS_ECC_CERT_NUM,
	ELEMS_ECC_CERT_FORMAT,
	ELEMS_ECC_ATTEST_CERT,
	ELEMS_ECC_ROOT_CERT,

	ELEMS_RSA_KEY_ALGO,
	ELEMS_RSA_KEY_FORMAT,
	ELEMS_RSA_PRIV_KEY,
	ELEMS_RSA_CERT_NUM,
	ELEMS_RSA_CERT_FORMAT,
	ELEMS_RSA_ATTEST_CERT,
	ELEMS_RSA_ROOT_CERT,
	ELEMS_MAX_ITERM,
}xml_elems_e;

typedef struct cert_elems_{
	xml_elems_e type;
	char tag_begin[32];
	char tag_end[32];
	void *data;
}cert_elems_t;

class ParseXml{
public:
	ParseXml();
	~ParseXml();
	char* GetRsaAttestKey(){
		return kRsaAttestKey;
	}
	size_t GetRsaAttestKeySize(){
		return kRsaAttestKeySize;
	}
	char* GetRsaAttestCert(){
		return kRsaAttestCert;
	}
	size_t GetRsaAttestCertSize(){
		return kRsaAttestCertSize;
	}
	char* GetRsaAttestRootCert(){
		return kRsaAttestRootCert;
	}
	size_t GetRsaAttestRootCertSize(){
		return kRsaAttestRootCertSize;
	}
	char* GetEcAttestKey(){
		return kEcAttestKey;
	}
	size_t GetEcAttestKeySize(){
		return kEcAttestKeySize;
	}
	char* GetEcAttestCert(){
		return kEcAttestCert;
	}
	size_t GetEcAttestCertSize(){
		return kEcAttestCertSize;
	}
	char* GetEcAttestRootCert(){
		return kEcAttestRootCert;
	}
	size_t GetEcAttestRootCertSize(){
		return kEcAttestRootCertSize;
	}

	char GetCertChainLength(){
		return key_num;
	}

private:
	bool read_xml_from_rpmb(void);
	void get_new_line(void);
	void get_elems_value(const char* begin,const char* end,char*value);
	void get_elems_value(const char* begin,const char* end,char* value,size_t *len);
	char *strXmlStart(char const *s1,char const *start,char const *end);
	char *strXmlEnd(char const *s1,char const *start,char const *end);
	bool get_cert_data(xml_elems_e type,const char* begin,const char* end);
	void parse_xml_elems(void);
	void switch_Attest_Context(void);
	char *xml_data;
	size_t xml_size;
	char *elem;
	char *elem_end;
	char version[4];
	char devID[64];
	char key_num;
	char ecc_name[8];
	char rsa_name[8];
	char ecc_key_f[8];
	char ecc_cert_f[8];
	char rsa_key_f[8];
	char rsa_cert_f[8];
	char ecc_cert_num;
	char rsa_cert_num;
	//unique_ptr<char>
	char* kRsaAttestKey;
	size_t kRsaAttestKeySize;
	char* kRsaAttestCert;
	size_t kRsaAttestCertSize;
	char* kRsaAttestRootCert;
	size_t kRsaAttestRootCertSize;
	char* kEcAttestKey;
	size_t kEcAttestKeySize;
	char* kEcAttestCert;
	size_t kEcAttestCertSize;
	char* kEcAttestRootCert;
	size_t kEcAttestRootCertSize;
	char kCertificateChainLength;
};

#endif //KEYMASTER_PARSE_XML_H_
