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

#define CERT_FILE_NAME  "data/TrustyCertChains.xml"
#define nullptr (void*)0

typedef enum xml_elems_{
    ELEMS_XML_VERSION=0,
    ELEMS_KEYBOXS_NUM,
    ELEMS_DEVICE_ID,
    ELEMS_KEY_ALGO,
    ELEMS_KEY_FORMAT,
    ELEMS_PRIV_KEY,
    ELEMS_CERT_NUM,
    ELEMS_CERT_FORMAT,
    ELEMS_ATTEST_CERT,
    ELEMS_ROOT_CERT,
    ELEMS_MAX_ITERM,
}xml_elems_e;

typedef struct cert_elems_{
    xml_elems_e type;
    const char tag_begin[32];
    const char tag_end[32];
    void *data;
}cert_elems_t;

class ParseXml{
public:
    ParseXml();
    ~ParseXml();
    void SaveXmlFiles(void);

private:
    bool read_xml_from_rpmb(void);
    void get_new_line(void);
    void get_elems_value(const char* begin,const char* end,char*value);
    void get_elems_value(const char* begin,const char* end,char* value,size_t *len);
    char *strXmlStart(char const *s1,char const *start,char const *end);
    char *strXmlEnd(char const *s1,char const *start,char const *end);
    bool GetItemsValue(xml_elems_e type,const char* begin,const char* end);
    void parse_xml_elems(char type);
    bool write_data2file( const char*, const char*);
    void skip_sp(char* in,char*out);
    char *xml_data;
    char *elem;
    char *key_elem;
    char *elem_end;
    size_t xml_size;
    char AttestBuf[2048]={0};
    size_t AttestSize=0;
    unsigned int key_num=0;
};

#endif //KEYMASTER_PARSE_XML_H_
