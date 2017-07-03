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
    {ELEMS_XML_VERSION, "xmlversion","", nullptr},
    {ELEMS_KEYBOXS_NUM, "<NumberOfKeyboxes>","</NumberOfKeyboxes>", nullptr},
    {ELEMS_DEVICE_ID, "KeyboxDeviceID","", nullptr},
    {ELEMS_KEY_ALGO, "Keyalgorithm","</Key>", nullptr},
    {ELEMS_KEY_FORMAT, "PrivateKeyformat","</PrivateKey>", nullptr},
    {ELEMS_PRIV_KEY, "PRIVATEKEY","END", nullptr},
    {ELEMS_CERT_NUM, "<NumberOfCertificates>", "</NumberOfCertificates>",nullptr},
    {ELEMS_CERT_FORMAT, "<Certificate","</Certificate>", nullptr},
    {ELEMS_ATTEST_CERT, "BEGINCERTIFICATE","ENDCERTIFICATE", nullptr},
    {ELEMS_ROOT_CERT, "BEGINCERTIFICATE","ENDCERTIFICATE",nullptr},
    {ELEMS_MAX_ITERM, "Unknown","",nullptr}};

    ParseXml::ParseXml(){
    read_xml_from_rpmb();
}
ParseXml::~ParseXml() {
free(xml_data);
}

bool ParseXml::read_xml_from_rpmb(void) {
    char *buf;
    int fd = open(CERT_FILE_NAME, O_RDONLY);
    xml_size = lseek(fd, 0, SEEK_END);
    xml_data = (char *)malloc(xml_size);
    buf = (char *)malloc(xml_size);
    lseek(fd, 0, SEEK_SET);
    int rs=read(fd, buf, xml_size);
    if(rs < 0)return rs;
    close(fd);
    skip_sp(buf,xml_data);
    free(buf);
    key_elem=xml_data;
    elem=key_elem;
    elem_end=key_elem;
    return true;
}
bool ParseXml::write_data2file(const char* filename,const char* data) {
    char path[64] ={0};
    sprintf(path,"save/Attest.%s",filename);
    if(access("save",0) !=0){
        mkdir("save",0755);
    }
    FILE* fd = fopen(path,"w+");
    fseek(fd, 0, SEEK_SET);
    fwrite(data,strlen(data),sizeof(char),fd);
    fclose(fd);
    return true;
}

void ParseXml::skip_sp(char* in,char*out) {
    while (*in++){
        if(*in != 32&&*in != 10&&*in != 13)
           *out++=*in;
    }
}

void ParseXml::get_new_line() {
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
void dumpString(const char *start, const char *end) {
    printf("start=%p end=%p length = %ld\n",start,end, end-start);
    while (start < end) {
        printf("%c", *start++);
    }
    printf("\n");
}
void ParseXml::parse_xml_elems(char type) {
    const char *start=NULL;
    const char *end=NULL;
    elem=key_elem;
    elem_end=key_elem;
    do {
        get_new_line();
        if(elem_end >= xml_data+xml_size)break;
        start = strXmlStart(cert_elems[type].tag_begin, elem, elem_end);
    } while (start == NULL);
    end = elem_end;
    if (start!=NULL&&strlen(cert_elems[type].tag_end) != 0) {
        do {
            get_new_line();
            if(elem_end >= xml_data+xml_size)break;
            end = strXmlEnd(cert_elems[type].tag_end, start, elem_end);
        } while (end== NULL);
    }
    if(start!=NULL && end!=NULL)
        GetItemsValue((xml_elems_e)type, start, end);
}
void ParseXml::get_elems_value(const char *begin, const char *end,
                               char *value) {
  while (begin < end) {
    if (*begin == '<' || *begin == '=' || *begin == '\"' ||
        *begin == '?'||((*begin&0x80) == 0x80)) {
      begin++;
      continue;
    }
    if(*begin =='>')break;
    *value++ = *begin++;
  }
}

void ParseXml::get_elems_value(const char *begin, const char *end, char *value,
                               size_t *len) {
  int i = 0;
  while (begin < end) {
    if (*begin == '<' || *begin == '-' ||
          *begin == '\"'||((*begin&0x80) == 0x80)) {
      begin++;
      continue;
    }
    if(*begin =='>')break;
    *value++ = *begin++;
    i++;
  }
  *len = i;
}

bool ParseXml::GetItemsValue(xml_elems_e type, const char *begin,
                             const char *end) {
    memset(AttestBuf,0,sizeof(AttestBuf));
    AttestSize=0;
    switch (type) {
        case ELEMS_KEYBOXS_NUM:
        case ELEMS_CERT_NUM:
            get_elems_value(begin, end, AttestBuf);
            key_num =atoi(AttestBuf);
            break;
        case ELEMS_KEY_ALGO:
        case ELEMS_CERT_FORMAT:
        case ELEMS_KEY_FORMAT:
        case ELEMS_DEVICE_ID:
        case ELEMS_XML_VERSION:
            get_elems_value(begin, end, AttestBuf);
            break;
        case ELEMS_PRIV_KEY:
        case ELEMS_ATTEST_CERT:
        case ELEMS_ROOT_CERT:
            get_elems_value(begin, end, AttestBuf, &AttestSize);
            break;
       default:
           break;
    }
    return true;
}
void ParseXml::SaveXmlFiles(void){
    parse_xml_elems(ELEMS_XML_VERSION);
    printf("[ ELEMS_XML_VERSION ] %s\n",AttestBuf);
    parse_xml_elems(ELEMS_DEVICE_ID);
    printf("[ ELEMS_DEVICE_ID ] %s\n",AttestBuf);
    parse_xml_elems(ELEMS_KEYBOXS_NUM);
    printf("[ ELEMS_KEYBOXS_NUM ] %d\n",key_num);
    for(int i=0;i<key_num;i++){
        char algo[8]={0};
        char filename[32]={0};
        parse_xml_elems(ELEMS_KEY_ALGO);
        printf("[ ELEMS_KEY_ALGO ] %s\n",AttestBuf);
        memcpy(algo,AttestBuf,strlen(AttestBuf));
        parse_xml_elems(ELEMS_PRIV_KEY);
        printf("[ ELEMS_PRIV_KEY ] %s\n",AttestBuf);
        sprintf(filename,"%s.prikey",algo);
        write_data2file(filename,AttestBuf);
        parse_xml_elems(ELEMS_CERT_NUM);
        parse_xml_elems(ELEMS_KEYBOXS_NUM);
        if(AttestBuf != NULL){
            printf("[ ELEMS_CERT_NUM ] %d\n",key_num);
            sprintf(filename,"%s.Certnum",algo);
            write_data2file(filename,AttestBuf);
        }
        parse_xml_elems(ELEMS_ATTEST_CERT);
        printf("[ ELEMS_ATTEST_CERT ] %s\n",AttestBuf);
        sprintf(filename,"%s.attestcert",algo);
        write_data2file(filename,AttestBuf);
        parse_xml_elems(ELEMS_ROOT_CERT);
        printf("[ ELEMS_ROOT_CERT ] %s\n",AttestBuf);
        sprintf(filename,"%s.rootcert",algo);
        write_data2file(filename,AttestBuf);
        key_elem = strXmlStart(cert_elems[ELEMS_KEY_ALGO].tag_end,key_elem,xml_data+xml_size);
        //printf("[ ELEMS_KEY_ALGO ] %s\n", key_elem);
    }
}
int main() {
    ParseXml op;
    op.SaveXmlFiles();
    return 0;
}
