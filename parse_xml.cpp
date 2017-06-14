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
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dirent.h>
#include <fcntl.h>
#include <new>
#include <sys/stat.h>
#include <sys/types.h>

#include "parse_xml.h"

static cert_elems_t cert_elems[] = {
    {ELEMS_XML_VERSION, "xml version", "", nullptr},
    {ELEMS_KEYBOXS_NUM, "<NumberOfKeyboxes>", "</NumberOfKeyboxes>", nullptr},
    {ELEMS_DEVICE_ID, "Keybox DeviceID", "", nullptr},
    {ELEMS_ECC_KEY_ALGO, "Key algorithm", "", nullptr},
    {ELEMS_ECC_KEY_FORMAT, "PrivateKey format", "", nullptr},
    {ELEMS_ECC_PRIV_KEY, "BEGIN EC PRIVATE KEY", "END EC PRIVATE KEY", nullptr},
    {ELEMS_ECC_CERT_NUM, "<NumberOfCertificates>", "</NumberOfCertificates>",
     nullptr},
    {ELEMS_ECC_CERT_FORMAT, "Certificate format", "", nullptr},
    {ELEMS_ECC_ATTEST_CERT, "BEGIN CERTIFICATE", "END CERTIFICATE", nullptr},
    {ELEMS_ECC_ROOT_CERT, "BEGIN CERTIFICATE", "END CERTIFICATE", nullptr},

    {ELEMS_RSA_KEY_ALGO, "<Key algorithm", "", nullptr},
    {ELEMS_RSA_KEY_FORMAT, "PrivateKey format", "", nullptr},
    {ELEMS_RSA_PRIV_KEY, "BEGIN RSA PRIVATE KEY", "END RSA PRIVATE KEY",
     nullptr},
    {ELEMS_RSA_CERT_NUM, "<NumberOfCertificates>", "</NumberOfCertificates>",
     nullptr},
    {ELEMS_RSA_CERT_FORMAT, "Certificate", "", nullptr},
    {ELEMS_RSA_ATTEST_CERT, "BEGIN CERTIFICATE", "END CERTIFICATE", nullptr},
    {ELEMS_RSA_ROOT_CERT, "BEGIN CERTIFICATE", "END CERTIFICATE", nullptr},
    {ELEMS_MAX_ITERM, "Unknown", "", nullptr}};

ParseXml::ParseXml() : kRsaAttestKeySize(0) {
  kRsaAttestKey = (char *)malloc(1024);
  kRsaAttestKeySize = 0;
  kRsaAttestCert = (char *)malloc(1024);
  kRsaAttestCertSize = 0;
  kRsaAttestRootCert = (char *)malloc(1024);
  kRsaAttestRootCertSize = 0;
  kEcAttestKey = (char *)malloc(1024);
  kEcAttestKeySize = 0;
  kEcAttestCert = (char *)malloc(1024);
  kEcAttestCertSize = 0;
  kEcAttestRootCert = (char *)malloc(1024);
  kEcAttestRootCertSize = 0;

	memset(devID,0, sizeof(devID));
	memset(ecc_name,0, sizeof(ecc_name));
	memset(ecc_key_f,0, sizeof(ecc_key_f));
	memset(ecc_cert_f,0, sizeof(ecc_cert_f));
	memset(rsa_key_f,0, sizeof(rsa_key_f));
	memset(rsa_cert_f,0, sizeof(rsa_cert_f));

  read_xml_from_rpmb();
  parse_xml_elems();
	switch_Attest_Context();
}
ParseXml::~ParseXml() {
  free(xml_data);
  free(kRsaAttestKey);
  free(kRsaAttestCert);
  free(kRsaAttestRootCert);
  free(kEcAttestKey);
  free(kEcAttestCert);
  free(kEcAttestRootCert);
}

bool ParseXml::read_xml_from_rpmb(void) {

  int fd = open(CERT_FILE_NAME, 'r');
  xml_size = lseek(fd, 0, SEEK_END);
  xml_data = (char *)malloc(xml_size);
  lseek(fd, 0, SEEK_SET);
  read(fd, xml_data, xml_size);
  close(fd);
  elem_end = xml_data;
  elem = xml_data;
  return true;
}

void ParseXml::get_new_line(void) {
  elem = elem_end;
  while (*elem_end != '>')
    elem_end++;
  elem_end++;
}

char *ParseXml::strXmlStart(const char *s1, const char *start,
                            const char *end) {
  int l1, l2;

  l1 = strlen((const char *)s1);
  if (!l1)
    return (char *)start;
  l2 = end - start;
  while (l2 >= l1) {
    l2--;
    if (!memcmp(start, s1, l1)) {
      start += l1;
      return (char *)start;
    }
    start++;
  }
  start += l1 - 1;
  return NULL;
}

char *ParseXml::strXmlEnd(const char *s1, const char *start, const char *end) {
  int l1, l2;

  l1 = strlen((const char *)s1);
  if (!l1)
    return (char *)start;
  l2 = end - start;
  while (l2 >= l1) {
    l2--;
    if (!memcmp(start, s1, l1))
      return (char *)start;
    start++;
  }
  return NULL;
}
void dumpString(char *start, char *end) {
  printf("start=%p end=%p length = %d\n",start,end, end-start);
  while (start < end) {
    printf("%c", *start++);
  }
  printf("\n");
}
void ParseXml::parse_xml_elems(void) {
  char *start;
  char *end;
    char type = 0;

    for (type = 0; type < (char)ELEMS_MAX_ITERM; type++) {

      do {
        get_new_line();
        start = strXmlStart(cert_elems[type].tag_begin, elem, elem_end);
      } while (start == NULL);
      end = elem_end;
      if (strlen(cert_elems[type].tag_end) != 0) {
        do {
          get_new_line();
          end = strXmlEnd(cert_elems[type].tag_end, start, elem_end);
        } while (start == NULL);
      }
      get_cert_data((xml_elems_e)type, start, end);
    }
}
void ParseXml::get_elems_value(const char *begin, const char *end,
                               char *value) {
  while (begin < end) {
    if (*begin == '<' || *begin == '>' || *begin == '=' || *begin == '\"' ||
        *begin == '?'||((*begin&0x80) == 0x80)) {
      begin++;
      continue;
    }
    *value++ = *begin++;
  }
}

void ParseXml::get_elems_value(const char *begin, const char *end, char *value,
                               size_t *len) {
  int i = 0;
  while (begin < end) {
    if (*begin == '<' || *begin == '>' || *begin == '-' || *begin == '\"'||((*begin&0x80) == 0x80)) {
      begin++;
      continue;
    }
    *value++ = *begin++;
    i++;
  }
  *len = i;
}

bool ParseXml::get_cert_data(xml_elems_e type, const char *begin,
                             const char *end) {
  char num[2];
  switch (type) {
  case ELEMS_XML_VERSION:
    get_elems_value(begin, end, version);
    break;
  case ELEMS_DEVICE_ID:
    get_elems_value(begin, end, devID);
    break;
  case ELEMS_KEYBOXS_NUM:
    get_elems_value(begin, end, num);
    key_num = num[0] - '0';
    break;
  case ELEMS_ECC_KEY_ALGO:
    get_elems_value(begin, end, ecc_name);
    break;
  case ELEMS_ECC_KEY_FORMAT:
    get_elems_value(begin, end, ecc_key_f);
    break;
  case ELEMS_ECC_PRIV_KEY:
    get_elems_value(begin, end, kEcAttestKey, &kEcAttestKeySize);
    break;
  case ELEMS_ECC_CERT_NUM:
    get_elems_value(begin, end, num);
    ecc_cert_num = num[0] - '0';
    break;
  case ELEMS_ECC_CERT_FORMAT:
    get_elems_value(begin, end, rsa_key_f);
    break;
  case ELEMS_ECC_ATTEST_CERT:
    get_elems_value(begin, end, kEcAttestCert, &kEcAttestCertSize);
    break;
  case ELEMS_ECC_ROOT_CERT:
    get_elems_value(begin, end, kEcAttestRootCert, &kEcAttestRootCertSize);
    break;
  case ELEMS_RSA_KEY_ALGO:
    get_elems_value(begin, end, rsa_name);
    break;
  case ELEMS_RSA_KEY_FORMAT:
    get_elems_value(begin, end, rsa_key_f);
    break;
  case ELEMS_RSA_PRIV_KEY:
    get_elems_value(begin, end, kRsaAttestKey, &kRsaAttestKeySize);
    break;
  case ELEMS_RSA_CERT_NUM:
    get_elems_value(begin, end, num);
    rsa_cert_num = num[0] - '0';
    break;
  case ELEMS_RSA_CERT_FORMAT:
    get_elems_value(begin, end, rsa_cert_f);
    break;
  case ELEMS_RSA_ATTEST_CERT:
    get_elems_value(begin, end, kRsaAttestCert, &kRsaAttestCertSize);
    break;
  case ELEMS_RSA_ROOT_CERT:
    get_elems_value(begin, end, kRsaAttestRootCert, &kRsaAttestRootCertSize);
    break;
  default:
    break;
  }
  return true;
}
void ParseXml::switch_Attest_Context(void){
	if(!memcmp(ecc_name,"ecdsa",strlen(ecc_name))){
    printf("%s\n", ecc_name);
	}
}

int main() {
  ParseXml op;
   printf("%s\n", op.GetRsaAttestKey());
  return 0;
}
