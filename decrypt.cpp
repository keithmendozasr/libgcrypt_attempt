#include <iostream>
#include <fstream>
#include <string>
#include <getopt.h>
#include <arpa/inet.h>
#include <cstdint>
#include <ctime>
#include <array>

#define GCRPYT_NO_DEPRECATED
#include <gcrypt.h>

using namespace std;

typedef struct _packet_info {
    bool format;
    uint8_t length_type;
    uint8_t tag;
} packet_info;

void usage()
{
    cerr<<"Usage: decrypt [-f filename|--file=filename] [-k|--key=privatekey]"<<endl;
}

inline static void printErrInfo(const string &msg, gcry_error_t err)
{
    cerr<<msg<<" Source: \""<<gcry_strsource(err)<<"\" Error: \""<<gcry_strerror(err)<<"\""<<endl;
}

bool initLibGcrypt()
{
    const char gcryptVersion[] = "1.6.2";
    if(!gcry_check_version(gcryptVersion))
    {
        cerr<<"Application expects libgcrypt v."<<gcryptVersion<<" or greater"<<endl;
        return false;
    }

    bool retVal = false;

    gcry_error_t err;
    if((err = gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN)))
        printErrInfo("Failed to suspend secmem warnings", err);
    else if((err = gcry_control(GCRYCTL_INIT_SECMEM, 1, 0)))
        printErrInfo("Failed to allocate secure memory", err);
    else if((err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0)))
        printErrInfo("Failed to flag initalization complete", err);
    else
        retVal = true;

    return retVal;
}

const packet_info getPacketTag(ifstream &inFile)
{
    uint8_t header;
    inFile>>header;

    packet_info retVal;
    retVal.format = (header & 64);
    if(retVal.format)
    {
        retVal.tag = (header & 63);
    }
    else
    {
        retVal.length_type = (header & 3);
        retVal.tag = (header &60) >> 2;
    }

    return move(retVal);
}

const unsigned int getBodyLength(ifstream &inFile, const packet_info &p)
{
    unsigned int retVal;

    switch(p.length_type)
    {
    case 3:
        throw string("Length is indeterminate type");
    case 0:
        cout<<"Length is 1 octet"<<endl;
        uint8_t oneOctet;
        inFile >> oneOctet;
        retVal = oneOctet;
        break;
    case 1:
        cout<<"Length is 2 octets"<<endl;
        uint16_t twoOctet;
        inFile.read(reinterpret_cast<char *>(&twoOctet), sizeof(twoOctet));
        retVal = ntohs(twoOctet);
        break;
    case 2:
        cout<<"Length is 4 octets"<<endl;
        uint32_t fourOctet;
        inFile >> fourOctet;
        retVal = ntohl(fourOctet);
        break;
    }

    return move(retVal);
}

gcry_mpi_t readMPI(const char* buf, const size_t &bufLen, size_t &nscanned)
{
    gcry_mpi_t retVal = gcry_mpi_snew(2048);
    gcry_error_t err = gcry_mpi_scan(&retVal, GCRYMPI_FMT_PGP, buf, bufLen, &nscanned);
    
    if(err)
    {
        throw string("Error encountered scanning mpi. Source: ") + string(gcry_strsource(err)) + string(" Cause: ") + string(gcry_strerror(err));
    }

    unsigned char *printBuf;
    size_t printBufSize;
    gcry_mpi_aprint(GCRYMPI_FMT_HEX, &printBuf, &printBufSize, retVal);
    printBuf[printBufSize-1] = '\0';
    cout<<"retVal: "<<printBuf<<endl
        <<"Value of nscanned: "<<nscanned<<endl;
    
    return retVal;
}

void getPublicKeyPacketInfo(weak_ptr<char> data, size_t dataSize)
{
    uint8_t ver;
    uint32_t createTime;
    uint8_t algorithm;

    if(auto ptr = data.lock())
    {
        const char * dataPtr = ptr.get();
        ver = dataPtr[0];
        memmove(&createTime, &(dataPtr[1]), sizeof(uint32_t));
        createTime = ntohl(createTime);
        algorithm = dataPtr[5];

        dataSize -= 7;
        size_t nextPos=6;

        cout<<"Version: "<<ver<<endl
            <<"Create time: ";
            {
                char *tmp = ctime(reinterpret_cast<const time_t *>(&createTime));
                if(tmp)
                    cout<<tmp;
                else
                {
                    int err = errno;
                    cout<<createTime<<" (Warning: Error converting time. Cause: "<<strerror(err)<<")";
                }
                cout<<endl;
            }
        cout<<"Algorithm: "<<(unsigned short)algorithm<<endl;

        //Get RSA modulus
        size_t nscanned;
        gcry_mpi_t modulus = readMPI(&dataPtr[nextPos], dataSize, nscanned);
        dataSize-= nscanned;
        nextPos += nscanned;

        gcry_mpi_t exponent = readMPI(&dataPtr[nextPos], dataSize, nscanned);
        gcry_mpi_release(modulus);
        gcry_mpi_release(exponent);
    }
    else
        throw string("Expired shared_ptr parameter provided");
}

void printPacketInfo(const packet_info &p)
{
    cout<<"Format: "<<(p.format ? "New" : "Old")<<endl;
    if(!p.format)
        cout<<"Length type: "<<(unsigned short)p.length_type<<endl;
    cout<<"Packet tag: "<<(unsigned short)p.tag<<endl;
}

void parsePrivateKey(const string &fileName)
{
    ifstream inFile;
    inFile.exceptions(ifstream::failbit | ifstream::badbit);
    inFile.open(fileName, ios::binary);

    const packet_info info = getPacketTag(inFile);
    printPacketInfo(info);
    if(info.tag != 5)
        throw move(string(fileName + " is not a private key file"));

    if(info.format)
        throw move(string("Unable to handle new format packet at this time"));
    cout<<"Parse out public key part"<<endl;
    const unsigned int keyDataLen = getBodyLength(inFile, info);
    cout<<"Key length: "<<keyDataLen<<endl;

    shared_ptr<char> body(reinterpret_cast<char *>(gcry_calloc_secure(keyDataLen, sizeof(char))), [](void *p){ gcry_free(p); } );
    inFile.read(body.get(), keyDataLen);
    getPublicKeyPacketInfo(body, keyDataLen);
}

int main(int argc, char **argv)
{
    static struct option opts [] = {
        { "file",   required_argument,  NULL,   'f' },
        { "key",    required_argument,  NULL,   'k' },
        { NULL,     0,                  NULL,   0 }
    };

    string fileName;
    string keyFile;
    int ch;
    while((ch = getopt_long(argc, argv, "f:k:", opts, NULL)) != -1)
    {
        switch(ch)
        {
        case 'f':
            fileName = string(optarg);
            break;
        case 'k':
            keyFile = string(optarg);
            break;
        default:
            usage();
            return EXIT_FAILURE;
        }
    };

    if(!fileName.length() || !keyFile.length())
    {
        usage();
        return EXIT_FAILURE;
    }

    if(!initLibGcrypt())
        return EXIT_FAILURE;

    int retVal = EXIT_FAILURE;

    try
    {
        parsePrivateKey(keyFile);
    }
    catch(const string &e)
    {
        cerr<<"Error \""<<e<<"\" Terminating program"<<endl;
    }
    /*catch(const ios::failure &e)
    {
        cerr<<"Error encountered reading file. Cause: "<<e.what()<<endl;
    }*/
    
    /*
    if(fileName.length())
    {
        cout<<"Opening file"<<fileName<<endl;
        ifstream inFile;
        inFile.exceptions(ifstream::failbit | ifstream::badbit);
        try
        {
            inFile.open(fileName, ifstream::binary);
            packet_info p = getPacketTag(inFile);

            int length = getBodyLength(p, inFile);
            cout<<"Body length: "<<length<<endl;

            getPublicKeyPacketInfo(inFile);
            readMPI(inFile);
            retVal = EXIT_SUCCESS;
        }
        catch(ifstream::failure e)
        {
            cerr<<"Error encounted processing. Cause: "<<e.what()<<endl;
        }
    }
    else
        usage();
    */

    return retVal;
}
